#!/usr/bin/env python3
import subprocess
import time
import requests
import re
import os
from datetime import datetime
import pexpect
import shutil
import sys
import zipfile
import shlex

DEBUG = False  # Enable debug output

# Print debug messages if DEBUG is True
def debug_log(msg):
    if DEBUG:
        print(f"DEBUG: {msg}")

# URL for retrieving the current server IP
SWAMP_URL = "https://swamp.sv/"

# Configuration constants
CHECK_DURATION = 5               # Duration for traffic capture (seconds)
MAX_RETRIES = 3                  # Maximum retry attempts for capturing UDP traffic
CHECK_INTERVAL = 5               # Time interval between checks (seconds)
FAILED_ATTEMPTS_THRESHOLD = 3    # Number of failed launch attempts before validation
MIN_PACKET_THRESHOLD = 5         # Minimum packets to consider traffic active

# OS-specific settings for Steam URIs, process names, and required commands
if os.name == 'nt':
    GMOD_STEAM_URI = "steam://connect/{server_ip}:27015"
    GMOD_VALIDATE_URI = "steam://validate/4000"
    PROCESS_NAMES = ["gmod.exe"]
    REQUIRED_CMDS = ["dumpcap"]
else:
    GMOD_STEAM_URI = "steam://connect/{server_ip}:27015"
    GMOD_VALIDATE_URI = "steam://validate/4000"
    PROCESS_NAMES = ["gmod", "hl2_linux", "hl2.sh", "garrysmod"]
    REQUIRED_CMDS = ["tcpdump", "pgrep", "xdg-open"]

# Global variable to store the full path to the CEF patch executable
GMOD_CEF_FIX_PATH = None

# Extract the patch from a zip file and set GMOD_CEF_FIX_PATH
def extract_gmod_cef_fix(zip_path, extract_to):
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(extract_to)
    except Exception as e:
        log_message(f"⚠️ [ERROR] Failed to extract zip file: {e}")
        return None
    gmod_cef_exe = None
    gmod_cef_folder = None
    # Recursively search for the executable inside the extracted files
    for root, dirs, files in os.walk(extract_to):
        for file in files:
            if file.lower().endswith(".exe") and "gmodcefcodecfix" in file.lower():
                gmod_cef_exe = os.path.join(root, file)
                gmod_cef_folder = root
                break
        if gmod_cef_exe:
            break
    if gmod_cef_exe and gmod_cef_folder:
        dest_folder = os.path.join(os.path.dirname(zip_path), "GModCEFCodecFix")
        if os.path.exists(dest_folder):
            shutil.rmtree(dest_folder)
        try:
            shutil.copytree(gmod_cef_folder, dest_folder)
        except Exception as e:
            log_message(f"⚠️ [ERROR] Failed to copy extracted folder: {e}")
            return None
        exe_name = os.path.basename(gmod_cef_exe)
        global GMOD_CEF_FIX_PATH
        GMOD_CEF_FIX_PATH = os.path.join(dest_folder, exe_name)
        try:
            os.chmod(GMOD_CEF_FIX_PATH, 0o755)  # Ensure the file is executable
        except Exception as e:
            log_message(f"⚠️ [ERROR] Failed to set executable permission: {e}")
        log_message(f"✅ [INFO] Extracted GModCEFCodecFix to: {dest_folder}")
        return dest_folder
    else:
        log_message("⚠️ [ERROR] No executable found in the extracted zip.")
        return None

# State tracking variables
last_gmod_state = None
last_connection_state = None
failed_attempts = 0
crash_attempts = 0
server_ip = None

# Simple logging function with a timestamp
def log_message(message):
    print(f"{time.strftime('%Y-%m-%d %I:%M:%S %p')} {message}")

# Verify that required system commands are available
def check_dependencies():
    missing = []
    for cmd in REQUIRED_CMDS:
        if shutil.which(cmd) is None:
            missing.append(cmd)
            debug_log(f"Command not found: {cmd}")
    if missing:
        log_message("⚠️ [WARNING] The following required commands are missing: " + ", ".join(missing))
    else:
        log_message("✅ [INFO] All required system commands are available.")

# Retrieve the current server IP from the SWAMP_URL
def fetch_server_ip():
    global server_ip
    try:
        response = requests.get(SWAMP_URL, timeout=5)
    except Exception as e:
        log_message(f"⚠️ [ERROR] Failed to fetch server IP: {e}")
        return
    debug_log(f"Fetched server IP page, status code: {response.status_code}")
    match = re.search(r"steam://connect/(\d+\.\d+\.\d+\.\d+):(\d+)", response.text)
    if match:
        new_ip = match.group(1)
        if new_ip != server_ip:
            log_message(f"🌍 [INFO] Updated server IP: {new_ip}")
            server_ip = new_ip
        else:
            debug_log("Server IP unchanged.")
    else:
        log_message("⚠️ [WARNING] Could not parse server IP from response.")

# Check if GMod is running using tasklist (Windows) or pgrep (Linux)
def is_gmod_running():
    if os.name == 'nt':
        try:
            output = subprocess.check_output(["tasklist"], text=True)
            debug_log(f"tasklist output: {output[:200]}...")
            for proc in PROCESS_NAMES:
                if proc.lower() in output.lower():
                    debug_log(f"Found process {proc} in tasklist.")
                    return True
            return False
        except Exception as e:
            log_message(f"⚠️ [ERROR] Exception in is_gmod_running: {e}")
            return False
    else:
        try:
            for process in PROCESS_NAMES:
                result = subprocess.run(["pgrep", "-a", process],
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL,
                                        text=True)
                debug_log(f"pgrep output for {process}: {result.stdout.strip()}")
                if result.stdout.strip():
                    return True
            return False
        except Exception as e:
            log_message(f"⚠️ [ERROR] Exception in is_gmod_running: {e}")
            return False

# List network interfaces using dumpcap on Windows
def get_windows_capture_interfaces():
    dumpcap_path = shutil.which("dumpcap")
    if not dumpcap_path:
        log_message("⚠️ [ERROR] dumpcap not found.")
        return []
    try:
        result = subprocess.run([dumpcap_path, "-D"],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                text=True,
                                timeout=10)
        lines = result.stdout.splitlines()
        debug_log(f"dumpcap -D output: {lines}")
        return lines
    except Exception as e:
        log_message(f"⚠️ [WARNING] Exception in get_windows_capture_interfaces: {e}")
        return []

# Determine an active network interface by testing each candidate with dumpcap
def find_active_interface(ip):
    dumpcap_path = shutil.which("dumpcap")
    if not dumpcap_path:
        log_message("⚠️ [ERROR] dumpcap not found.")
        return "1"
    interfaces = get_windows_capture_interfaces()
    candidate_ifaces = []
    for line in interfaces:
        match_iface = re.match(r"(\d+)\.", line)
        if match_iface:
            candidate_ifaces.append(match_iface.group(1))
    debug_log(f"Candidate interfaces: {candidate_ifaces}")
    filter_str = f"host {ip}"
    for iface in candidate_ifaces:
        temp_file = "temp_test.pcap"
        cmd = [
            dumpcap_path,
            "-i", iface,
            "-a", "duration:2",
            "-f", filter_str,
            "-w", temp_file
        ]
        debug_log(f"Testing interface {iface} with filter: {filter_str}")
        try:
            subprocess.run(cmd,
                           stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE,
                           timeout=3)
            if os.path.exists(temp_file):
                size = os.path.getsize(temp_file)
                debug_log(f"Interface {iface} produced file size: {size}")
                os.remove(temp_file)
                if size > 0:
                    return iface
        except subprocess.TimeoutExpired:
            debug_log(f"Interface {iface} timed out during test capture.")
            if os.path.exists(temp_file):
                os.remove(temp_file)
            continue
    log_message("⚠️ [WARNING] No active interface detected; defaulting to interface 1.")
    return "1"

# Check for UDP traffic from a given IP using dumpcap (Windows) or tcpdump (Linux)
def check_udp_traffic(ip, retries=MAX_RETRIES):
    if not ip:
        return False
    if os.name == 'nt':
        dumpcap_path = shutil.which("dumpcap")
        if not dumpcap_path:
            return False
        interface = find_active_interface(ip)
        debug_log(f"Using interface {interface} for capture.")
        filter_str = f"host {ip}"
        for attempt in range(retries):
            temp_file = "temp_capture.pcap"
            cmd = [
                dumpcap_path,
                "-i", interface,
                "-a", f"duration:{CHECK_DURATION}",
                "-f", filter_str,
                "-w", temp_file
            ]
            debug_log(f"Attempt {attempt+1}: Running command: {cmd}")
            try:
                subprocess.run(cmd,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE,
                               timeout=CHECK_DURATION+2)
                if os.path.exists(temp_file):
                    size = os.path.getsize(temp_file)
                    debug_log(f"Capture file size: {size}")
                    os.remove(temp_file)
                    if size > 0:
                        return True
            except subprocess.TimeoutExpired:
                debug_log("Dumpcap timed out on this attempt.")
                if os.path.exists(temp_file):
                    os.remove(temp_file)
            time.sleep(2)
        return False
    else:
        for attempt in range(retries):
            cmd = [
                "timeout", str(CHECK_DURATION),
                "tcpdump", "-nn", "-q", "-c", str(MIN_PACKET_THRESHOLD),
                "host", ip
            ]
            debug_log(f"Attempt {attempt+1}: Running command: {cmd}")
            try:
                result = subprocess.run(cmd,
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL,
                                        text=True)
                debug_log(f"tcpdump result: {result.stdout.strip()}")
                if result.returncode == 0 and ip in result.stdout:
                    return True
            except Exception as e:
                debug_log(f"Error running tcpdump: {e}")
            time.sleep(2)
        return False

# Update state variables and log changes when the state differs
def log_state_change(state_variable, new_state, message):
    global last_gmod_state, last_connection_state
    if state_variable == "gmod":
        if new_state != last_gmod_state:
            log_message(message)
            last_gmod_state = new_state
    elif state_variable == "connection":
        if new_state != last_connection_state:
            log_message(message)
            last_connection_state = new_state

# Launch GMod using the appropriate Steam URI
def launch_gmod():
    global failed_attempts, crash_attempts, server_ip
    if server_ip:
        log_message(f"🚀 [INFO] Launching GMod & connecting to {server_ip}:27015...")
        if os.name == 'nt':
            steam_uri = GMOD_STEAM_URI.format(server_ip=server_ip)
            subprocess.run(["cmd", "/c", "start", steam_uri],
                           stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
        else:
            steam_uri = GMOD_STEAM_URI.format(server_ip=server_ip)
            subprocess.run(["xdg-open", steam_uri],
                           stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
        time.sleep(30)
        failed_attempts = 0
    else:
        log_message("⚠️ [ERROR] No valid server IP. Cannot launch GMod.")

# Restart GMod and trigger file validation, then wait for full validation before patching
def validate_and_restart_gmod():
    global failed_attempts, crash_attempts
    log_message("🔄 [INFO] Restarting GMod & verifying game files...")
    if os.name == 'nt':
        try:
            subprocess.run(["taskkill", "/F", "/IM", "gmod.exe"],
                           stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
        except Exception as e:
            debug_log(f"Error during taskkill: {e}")
        subprocess.run(["cmd", "/c", "start", GMOD_VALIDATE_URI],
                       stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)
    else:
        subprocess.run(["pkill", "-9", "gmod"],
                       stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)
        subprocess.run(["steam", GMOD_VALIDATE_URI],
                       stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)
    failed_attempts = 0
    crash_attempts = 0
    time.sleep(45)  # Wait to ensure Steam has fully validated files
    if not run_gmod_cef_fix():
        log_message("⚠️ [ERROR] GModCEFCodecFix did not apply successfully after validation.")

# Check GitHub for a newer version of the patch and update if needed
def check_for_new_cef_fix():
    global GMOD_CEF_FIX_PATH
    try:
        response = requests.get("https://api.github.com/repos/solsticegamestudios/GModCEFCodecFix/releases/latest", timeout=10)
    except Exception as e:
        log_message(f"⚠️ [ERROR] Exception while fetching remote release info: {e}")
        return
    debug_log(f"GitHub release status: {response.status_code}")
    if response.status_code != 200:
        log_message("⚠️ [ERROR] Failed to fetch release info from GitHub.")
        return
    try:
        data = response.json()
    except Exception as e:
        log_message(f"⚠️ [ERROR] Failed to parse JSON from GitHub response: {e}")
        return
    remote_created_at_str = data.get("created_at", None)
    if not remote_created_at_str:
        log_message("⚠️ [ERROR] Remote release info did not contain a creation date.")
        return
    try:
        remote_date = datetime.strptime(remote_created_at_str, "%Y-%m-%dT%H:%M:%SZ")
    except Exception as e:
        log_message(f"⚠️ [ERROR] Failed to parse remote date: {e}")
        return
    debug_log(f"Remote patch creation date: {remote_date}")
    if not GMOD_CEF_FIX_PATH or not os.path.exists(GMOD_CEF_FIX_PATH):
        log_message(f"⚠️ [WARNING] Local patch file not found at {GMOD_CEF_FIX_PATH}.")
        return
    try:
        local_timestamp = os.path.getmtime(GMOD_CEF_FIX_PATH)
        local_date = datetime.fromtimestamp(local_timestamp)
    except Exception as e:
        log_message(f"⚠️ [ERROR] Could not get modification time for local patch: {e}")
        return
    debug_log(f"Local patch file modification date: {local_date}")
    if remote_date > local_date:
        log_message(f"🌍 [INFO] New patch available (remote: {remote_date}, local: {local_date}). Updating...")
        if os.name == 'nt':
            asset_url = None
            try:
                response = requests.get("https://api.github.com/repos/solsticegamestudios/GModCEFCodecFix/releases/latest", timeout=10)
                data = response.json()
                assets = data.get("assets", [])
                for asset in assets:
                    name = asset.get("name", "")
                    if name.lower().endswith(".exe") and "gmodcefcodecfix" in name.lower():
                        asset_url = asset.get("browser_download_url")
                        break
                if asset_url is None:
                    for asset in assets:
                        name = asset.get("name", "")
                        if name.lower().endswith(".zip") and "gmodcefcodecfix" in name.lower():
                            asset_url = asset.get("browser_download_url")
                            break
            except Exception as e:
                log_message(f"⚠️ [ERROR] Exception while fetching asset info: {e}")
                return
            if asset_url:
                try:
                    r = requests.get(asset_url, timeout=10)
                    if r.status_code == 200:
                        exe_path = os.path.join(os.path.dirname(GMOD_CEF_FIX_PATH), os.path.basename(asset_url))
                        with open(exe_path, "wb") as f:
                            f.write(r.content)
                        os.chmod(exe_path, 0o755)
                        GMOD_CEF_FIX_PATH = exe_path
                        log_message("✅ [INFO] Updated GModCEFCodecFix to the latest patch.")
                    else:
                        log_message("⚠️ [ERROR] Failed to download the patch from GitHub.")
                except Exception as e:
                    log_message(f"⚠️ [ERROR] Exception while downloading new patch: {e}")
            else:
                log_message("⚠️ [ERROR] No suitable Windows patch found in the latest release.")
        else:
            asset_url = None
            try:
                response = requests.get("https://api.github.com/repos/solsticegamestudios/GModCEFCodecFix/releases/latest", timeout=10)
                data = response.json()
                assets = data.get("assets", [])
                for asset in assets:
                    name = asset.get("name", "")
                    if "linux" in name.lower() and "gmodcefcodecfix" in name.lower():
                        asset_url = asset.get("browser_download_url")
                        break
            except Exception as e:
                log_message(f"⚠️ [ERROR] Exception while fetching asset info: {e}")
                return
            if asset_url:
                try:
                    r = requests.get(asset_url, timeout=10)
                    if r.status_code == 200:
                        linux_path = os.path.join(os.path.dirname(GMOD_CEF_FIX_PATH), os.path.basename(asset_url))
                        with open(linux_path, "wb") as f:
                            f.write(r.content)
                        os.chmod(linux_path, 0o755)
                        GMOD_CEF_FIX_PATH = linux_path
                        log_message("✅ [INFO] Updated GModCEFCodecFix for Linux to the latest patch.")
                        return
                    else:
                        log_message("⚠️ [ERROR] Failed to download the Linux patch from GitHub.")
                except Exception as e:
                    log_message(f"⚠️ [ERROR] Exception while downloading new patch: {e}")
            else:
                log_message("⚠️ [ERROR] No suitable Linux patch found in the latest release.")
    else:
        log_message(f"✅ [INFO] Local patch is up-to-date (remote: {remote_date}, local: {local_date}).")

# Run the CEF patch using pexpect inside a bash shell to capture output and send responses automatically.
def run_gmod_cef_fix():
    log_message("🛠 [INFO] Running GModCEFCodecFix with pexpect...")
    check_for_new_cef_fix()
    if not GMOD_CEF_FIX_PATH or not os.path.exists(GMOD_CEF_FIX_PATH):
        log_message(f"⚠️ [ERROR] GModCEFCodecFix not found at {GMOD_CEF_FIX_PATH}")
        return False
    if not os.access(GMOD_CEF_FIX_PATH, os.X_OK):
        log_message(f"⚠️ [ERROR] GModCEFCodecFix is not executable. Attempting to set executable permission.")
        try:
            os.chmod(GMOD_CEF_FIX_PATH, 0o755)
        except Exception as e:
            log_message(f"⚠️ [ERROR] Failed to set executable permission: {e}")
            return False
    try:
        # Use bash to run the patcher, quoting the full absolute path to handle spaces
        cmd = shlex.quote(GMOD_CEF_FIX_PATH)
        child = pexpect.spawn("/bin/bash", ["-c", cmd], timeout=180)
        child.logfile = sys.stdout.buffer
        # Wait for the success message from the patcher
        child.expect("CEFCodecFix applied successfully!", timeout=180)
        # If the patcher then prompts for launching GMod, send "n"
        try:
            child.expect("Do you want to Launch Garry's Mod now\\?", timeout=30)
            child.sendline("n")
        except pexpect.TIMEOUT:
            debug_log("No launch prompt received; continuing without sending input.")
        output = child.before.decode() if hasattr(child.before, "decode") else child.before
        ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
        cleaned_output = ansi_escape.sub('', output)
        log_message("✅ [INFO] GModCEFCodecFix applied successfully (pexpect).")
        log_message(f"Output: {cleaned_output}")
        return True
    except pexpect.TIMEOUT:
        log_message("⚠️ [ERROR] GModCEFCodecFix timed out in pexpect mode.")
        return False
    except Exception as e:
        log_message(f"⚠️ [ERROR] Exception in pexpect patch run: {e}")
        return False

# Search common directories for the patch; download it if not found
def auto_configure_gmod_cef_path():
    global GMOD_CEF_FIX_PATH
    search_dirs = []
    home = os.path.expanduser("~")
    for folder in ["Documents", "Desktop", "Downloads"]:
        dir_path = os.path.join(home, folder)
        if os.path.isdir(dir_path):
            search_dirs.append(dir_path)
    if os.name == 'nt':
        patterns = [("GModCEFCodecFix", ".exe"), ("GModCEFCodecFix", ".zip")]
    else:
        patterns = [("GModCEFCodecFix-Linux", "")]
    for d in search_dirs:
        for root, _, files in os.walk(d):
            for file in files:
                for prefix, ext in patterns:
                    if file.startswith(prefix) and file.endswith(ext):
                        candidate = os.path.join(root, file)
                        if os.name == 'nt' and ext == ".zip":
                            extract_dir = os.path.join(root, "GModCEFCodecFix_extracted")
                            os.makedirs(extract_dir, exist_ok=True)
                            try:
                                extract_gmod_cef_fix(candidate, extract_dir)
                                return GMOD_CEF_FIX_PATH
                            except Exception as e:
                                log_message(f"⚠️ [ERROR] Failed to extract zip: {e}")
                        else:
                            GMOD_CEF_FIX_PATH = candidate
                            log_message(f"Found GModCEFCodecFix at: {GMOD_CEF_FIX_PATH}")
                            return GMOD_CEF_FIX_PATH
    log_message("GModCEFCodecFix not found in common directories. Downloading latest patch...")
    download_latest_gmod_cef_fix()
    return GMOD_CEF_FIX_PATH

# Download the latest patch from GitHub if not available locally
def download_latest_gmod_cef_fix():
    global GMOD_CEF_FIX_PATH
    download_dir = os.path.dirname(os.path.realpath(__file__))
    try:
        response = requests.get("https://api.github.com/repos/solsticegamestudios/GModCEFCodecFix/releases/latest", timeout=10)
    except Exception as e:
        log_message(f"⚠️ [ERROR] Exception while fetching release info from GitHub: {e}")
        return
    if response.status_code != 200:
        log_message("⚠️ [ERROR] Failed to fetch release info from GitHub.")
        return
    try:
        data = response.json()
    except Exception as e:
        log_message(f"⚠️ [ERROR] Failed to parse GitHub JSON response: {e}")
        return
    assets = data.get("assets", [])
    if os.name == 'nt':
        exe_asset = None
        zip_asset = None
        for asset in assets:
            name = asset.get("name", "")
            if name.lower().endswith(".exe") and "gmodcefcodecfix" in name.lower():
                exe_asset = asset
                break
            elif name.lower().endswith(".zip") and "gmodcefcodecfix" in name.lower():
                zip_asset = asset
        if exe_asset:
            url = exe_asset.get("browser_download_url")
            exe_path = os.path.join(download_dir, exe_asset.get("name"))
            log_message(f"Downloading latest patch (Windows) from: {url}")
            try:
                r = requests.get(url, timeout=10)
            except Exception as e:
                log_message(f"⚠️ [ERROR] Exception while downloading executable: {e}")
                return
            if r.status_code == 200:
                with open(exe_path, "wb") as f:
                    f.write(r.content)
                try:
                    os.chmod(exe_path, 0o755)
                except Exception as e:
                    log_message(f"⚠️ [ERROR] Failed to set executable permission: {e}")
                GMOD_CEF_FIX_PATH = exe_path
                log_message("✅ [INFO] Downloaded latest patch (Windows).")
                return
            else:
                log_message("⚠️ [ERROR] Failed to download the executable patch.")
        elif zip_asset:
            url = zip_asset.get("browser_download_url")
            zip_path = os.path.join(download_dir, zip_asset.get("name"))
            log_message(f"Downloading latest patch (Windows) from: {url}")
            try:
                r = requests.get(url, timeout=10)
            except Exception as e:
                log_message(f"⚠️ [ERROR] Exception while downloading zip asset: {e}")
                return
            if r.status_code == 200:
                with open(zip_path, "wb") as f:
                    f.write(r.content)
                extract_dir = os.path.join(download_dir, "GModCEFCodecFix_extracted")
                os.makedirs(extract_dir, exist_ok=True)
                extract_gmod_cef_fix(zip_path, extract_dir)
                return
            else:
                log_message("⚠️ [ERROR] Failed to download the zip patch.")
        else:
            log_message("⚠️ [ERROR] No suitable Windows patch found in the latest release.")
    else:
        linux_asset = None
        for asset in assets:
            name = asset.get("name", "")
            if "linux" in name.lower() and "gmodcefcodecfix" in name.lower():
                linux_asset = asset
                break
        if linux_asset:
            url = linux_asset.get("browser_download_url")
            linux_path = os.path.join(download_dir, linux_asset.get("name"))
            log_message(f"Downloading latest patch (Linux) from: {url}")
            try:
                r = requests.get(url, timeout=10)
            except Exception as e:
                log_message(f"⚠️ [ERROR] Exception while downloading Linux asset: {e}")
                return
            if r.status_code == 200:
                with open(linux_path, "wb") as f:
                    f.write(r.content)
                try:
                    os.chmod(linux_path, 0o755)
                except Exception as e:
                    log_message(f"⚠️ [ERROR] Failed to set executable permission: {e}")
                GMOD_CEF_FIX_PATH = linux_path
                log_message("✅ [INFO] Downloaded latest patch (Linux).")
                return
            else:
                log_message("⚠️ [ERROR] Failed to download the Linux patch.")
        else:
            log_message("⚠️ [ERROR] No suitable Linux patch found in the latest release.")

# Main loop: continuously check server status and apply patch as needed.
# This loop will never exit unless the user manually terminates the script.
def main():
    global server_ip, failed_attempts, crash_attempts
    auto_configure_gmod_cef_path()
    check_dependencies()
    while True:
        try:
            fetch_server_ip()
            gmod_running = is_gmod_running()
            udp_active = check_udp_traffic(server_ip) if server_ip else False
            debug_log(f"Server IP: {server_ip}, GMod running: {gmod_running}, Traffic detected: {udp_active}")
            if gmod_running and udp_active:
                log_state_change("gmod", True, "🟢 [INFO] GMod is running & connected to the server.")
                failed_attempts = 0
                crash_attempts = 0
            elif not gmod_running:
                log_state_change("gmod", False, "❌ [INFO] GMod is NOT running. Attempting to launch...")
                crash_attempts += 1
                launch_gmod()
                if crash_attempts >= 3:
                    log_message("⚠️ [INFO] 3 consecutive failed launches detected. Validating and reapplying patch...")
                    validate_and_restart_gmod()
                    crash_attempts = 0
            else:
                log_state_change("connection", False, "🔴 [INFO] GMod is running but NOT connected.")
                failed_attempts += 1
                if failed_attempts >= FAILED_ATTEMPTS_THRESHOLD:
                    validate_and_restart_gmod()
            time.sleep(CHECK_INTERVAL)
        except Exception as e:
            log_message(f"⚠️ [ERROR] Uncaught exception in main loop: {e}")
            time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    main()

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

DEBUG = False  # Set to True for verbose debugging

def debug_log(msg):
    if DEBUG:
        print(f"DEBUG: {msg}")

SWAMP_URL = "https://swamp.sv/"  # Site to get current server IP
CHECK_DURATION = 5               # Seconds to monitor traffic (time-based capture)
MAX_RETRIES = 3                  # Max retries for detection
CHECK_INTERVAL = 5               # Time between each connection check (in seconds)
FAILED_ATTEMPTS_THRESHOLD = 3    # Connection failures before validation
MIN_PACKET_THRESHOLD = 5         # Minimum packets to consider traffic active

# OS-specific settings
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

# Global variable for the GModCEFCodecFix executable path.
GMOD_CEF_FIX_PATH = ""

# This function extracts the zip and recursively searches for the executable
def extract_gmod_cef_fix(zip_path, extract_to):
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(extract_to)
    gmod_cef_exe = None
    gmod_cef_folder = None
    for root, dirs, files in os.walk(extract_to):
        for file in files:
            if file.lower().endswith(".exe") and "gmodcefcodecfix" in file.lower():
                gmod_cef_exe = os.path.join(root, file)
                gmod_cef_folder = root
                break
        if gmod_cef_exe:
            break
    if gmod_cef_exe and gmod_cef_folder:
        # Copy the entire folder (with the exe and dependencies) to a new destination
        dest_folder = os.path.join(os.path.dirname(zip_path), "GModCEFCodecFix")
        if os.path.exists(dest_folder):
            shutil.rmtree(dest_folder)
        shutil.copytree(gmod_cef_folder, dest_folder)
        # Update executable path to point inside the new folder
        exe_name = os.path.basename(gmod_cef_exe)
        global GMOD_CEF_FIX_PATH
        GMOD_CEF_FIX_PATH = os.path.join(dest_folder, exe_name)
        os.chmod(GMOD_CEF_FIX_PATH, 0o755)
        log_message(f"✅ [INFO] Extracted GModCEFCodecFix to: {dest_folder}")
        return dest_folder
    else:
        log_message("⚠️ [ERROR] No executable found in the extracted zip.")
        return None

# STATE TRACKING
last_gmod_state = None
last_connection_state = None
failed_attempts = 0   # For connection failures (GMod running but not connected)
crash_attempts = 0    # For launch failures (GMod not running, assumed crash)
server_ip = None

def log_message(message):
    print(f"{time.strftime('%Y-%m-%d %I:%M:%S %p')} {message}")

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

def fetch_server_ip():
    global server_ip
    try:
        response = requests.get(SWAMP_URL, timeout=5)
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
    except Exception as e:
        log_message(f"⚠️ [ERROR] Failed to fetch server IP: {e}")

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
            result = subprocess.run(cmd,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL,
                                    text=True)
            debug_log(f"tcpdump result: {result.stdout.strip()}")
            if result.returncode == 0 and ip in result.stdout:
                return True
            time.sleep(2)
        return False

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
    time.sleep(15)
    if not run_gmod_cef_fix():
        log_message("⚠️ [ERROR] GModCEFCodecFix did not apply successfully after validation.")

def check_for_new_cef_fix():
    try:
        response = requests.get("https://api.github.com/repos/solsticegamestudios/GModCEFCodecFix/releases/latest", timeout=10)
        debug_log(f"GitHub release status: {response.status_code}")
        if response.status_code != 200:
            log_message("⚠️ [ERROR] Failed to fetch release info from GitHub.")
            return
        data = response.json()
        remote_created_at_str = data.get("created_at", None)
        if not remote_created_at_str:
            log_message("⚠️ [ERROR] Remote release info did not contain a creation date.")
            return
        remote_date = datetime.strptime(remote_created_at_str, "%Y-%m-%dT%H:%M:%SZ")
        debug_log(f"Remote patch creation date: {remote_date}")
    except Exception as e:
        log_message(f"⚠️ [ERROR] Exception while fetching remote release info: {e}")
        return

    if not os.path.exists(GMOD_CEF_FIX_PATH):
        log_message(f"⚠️ [WARNING] Local patch file not found at {GMOD_CEF_FIX_PATH}.")
        return

    local_timestamp = os.path.getmtime(GMOD_CEF_FIX_PATH)
    local_date = datetime.fromtimestamp(local_timestamp)
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
                        log_message("✅ [INFO] Updated GModCEFCodecFix to the latest version.")
                    else:
                        log_message("⚠️ [ERROR] Failed to download the asset from GitHub.")
                except Exception as e:
                    log_message(f"⚠️ [ERROR] Exception while downloading new patch: {e}")
            else:
                log_message("⚠️ [ERROR] No suitable Windows asset found in the latest release.")
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
                        log_message("✅ [INFO] Updated GModCEFCodecFix for Linux.")
                        return
                    else:
                        log_message("⚠️ [ERROR] Failed to download the Linux asset.")
                except Exception as e:
                    log_message(f"⚠️ [ERROR] Exception while downloading new patch: {e}")
            else:
                log_message("⚠️ [ERROR] No suitable Linux asset found in the latest release.")
    else:
        log_message(f"✅ [INFO] Local patch is up-to-date (remote: {remote_date}, local: {local_date}).")

def run_gmod_cef_fix():
    log_message("🛠 [INFO] Running GModCEFCodecFix with pexpect...")
    check_for_new_cef_fix()

    if not os.path.exists(GMOD_CEF_FIX_PATH):
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
        if os.name == 'nt':
            child = pexpect.popen_spawn.PopenSpawn(GMOD_CEF_FIX_PATH, timeout=120)
        else:
            child = pexpect.spawn(GMOD_CEF_FIX_PATH, timeout=120)
        child.sendline("n")
        child.sendline("")
        child.expect("CEFCodecFix applied successfully!", timeout=120)
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

def auto_configure_gmod_cef_path():
    """
    Searches the user's Documents, Desktop, and Downloads folders for the GModCEFCodecFix file.
    If not found, downloads the latest release.
    """
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
    log_message("GModCEFCodecFix not found in common directories. Downloading latest release...")
    download_latest_gmod_cef_fix()
    return GMOD_CEF_FIX_PATH

def download_latest_gmod_cef_fix():
    """
    Downloads the latest GModCEFCodecFix release from GitHub dynamically.
    For Windows, it tries to find an .exe asset first; if not, falls back to a .zip asset.
    For Linux, it downloads the asset with 'linux' in its name.
    The file is saved in the same directory as the script.
    """
    global GMOD_CEF_FIX_PATH
    download_dir = os.path.dirname(os.path.realpath(__file__))
    try:
        response = requests.get("https://api.github.com/repos/solsticegamestudios/GModCEFCodecFix/releases/latest", timeout=10)
        if response.status_code != 200:
            log_message("⚠️ [ERROR] Failed to fetch release info from GitHub.")
            return
        data = response.json()
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
                log_message(f"Downloading Windows executable from: {url}")
                r = requests.get(url, timeout=10)
                if r.status_code == 200:
                    with open(exe_path, "wb") as f:
                        f.write(r.content)
                    os.chmod(exe_path, 0o755)
                    GMOD_CEF_FIX_PATH = exe_path
                    log_message("✅ [INFO] Downloaded GModCEFCodecFix Windows exe.")
                    return
                else:
                    log_message("⚠️ [ERROR] Failed to download the exe asset.")
            elif zip_asset:
                url = zip_asset.get("browser_download_url")
                zip_path = os.path.join(download_dir, zip_asset.get("name"))
                log_message(f"Downloading Windows zip from: {url}")
                r = requests.get(url, timeout=10)
                if r.status_code == 200:
                    with open(zip_path, "wb") as f:
                        f.write(r.content)
                    extract_dir = os.path.join(download_dir, "GModCEFCodecFix_extracted")
                    os.makedirs(extract_dir, exist_ok=True)
                    # CHANGED: Use the new extraction function instead of manual extraction.
                    extract_gmod_cef_fix(zip_path, extract_dir)
                    return
                else:
                    log_message("⚠️ [ERROR] Failed to download the zip asset.")
            else:
                log_message("⚠️ [ERROR] No suitable Windows asset found in the latest release.")
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
                log_message(f"Downloading Linux asset from: {url}")
                r = requests.get(url, timeout=10)
                if r.status_code == 200:
                    with open(linux_path, "wb") as f:
                        f.write(r.content)
                    os.chmod(linux_path, 0o755)
                    GMOD_CEF_FIX_PATH = linux_path
                    log_message("✅ [INFO] Downloaded GModCEFCodecFix for Linux.")
                    return
                else:
                    log_message("⚠️ [ERROR] Failed to download the Linux asset.")
            else:
                log_message("⚠️ [ERROR] No suitable Linux asset found in the latest release.")
    except Exception as e:
        log_message(f"⚠️ [ERROR] Exception while downloading latest patch: {e}")

def main():
    global server_ip, failed_attempts, crash_attempts
    auto_configure_gmod_cef_path()
    check_dependencies()
    
    while True:
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
                log_message("⚠️ [INFO] 3 consecutive failed launches detected. Validating and reapplying CEF patch...")
                validate_and_restart_gmod()
                crash_attempts = 0
        else:
            log_state_change("connection", False, "🔴 [INFO] GMod is running but NOT connected.")
            failed_attempts += 1
            if failed_attempts >= FAILED_ATTEMPTS_THRESHOLD:
                validate_and_restart_gmod()

        time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    main()

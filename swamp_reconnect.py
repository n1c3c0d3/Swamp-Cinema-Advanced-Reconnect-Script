#!/usr/bin/env python3
import subprocess
import time
import requests
import re
import os
from datetime import datetime
import shutil
import sys
import zipfile
import shlex

try:
    import pexpect  # type: ignore
except ImportError:  # pragma: no cover - optional dependency on Windows
    pexpect = None

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
CHECK_INTERVAL = 10              # Time interval between main loop checks (seconds)
FAILED_ATTEMPTS_THRESHOLD = 3    # Number of failed launch attempts before validation
MIN_PACKET_THRESHOLD = 5         # Minimum packets to consider traffic active

# Caching for server IP fetch
FETCH_INTERVAL_SECONDS = 60      # Only fetch IP at most once per 60 seconds
last_fetch_time = 0              # Timestamp of the last fetch

# Maintain a session with standard browser headers to avoid bot detection
SESSION = requests.Session()
SESSION.headers.update({
    'User-Agent': (
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
        'AppleWebKit/537.36 (KHTML, like Gecko) '
        'Chrome/115.0.0.0 Safari/537.36'
    ),
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9',
    'Connection': 'keep-alive',
})

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

# Global variable to store the full path to the patch tool executable
GMOD_PATCH_TOOL_PATH = None
PATCH_TOOL_REPO = "solsticegamestudios/GModPatchTool"

# Regular expression used to strip ANSI colour codes from subprocess output
ANSI_ESCAPE_RE = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
PATCH_SUCCESS_MESSAGE = "Patch applied successfully"


def _clean_patch_output(raw_output):
    """Return subprocess text output with ANSI colour codes removed."""
    if raw_output is None:
        return ""
    if not isinstance(raw_output, str):
        try:
            raw_output = raw_output.decode()
        except Exception:
            raw_output = str(raw_output)
    return ANSI_ESCAPE_RE.sub('', raw_output)


# Extract the patch from a zip file and set GMOD_PATCH_TOOL_PATH
def extract_gmod_patch_tool(zip_path, extract_to):
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(extract_to)
    except Exception as e:
        log_message(f"⚠️ [ERROR] Failed to extract zip file: {e}")
        return None
    gmod_patch_tool_exe = None
    gmod_patch_tool_folder = None
    # Recursively search for the executable inside the extracted files
    for root, dirs, files in os.walk(extract_to):
        for file in files:
            lower_name = file.lower()
            if "gmodpatchtool" not in lower_name:
                continue
            if lower_name.endswith(".exe") or lower_name.endswith(".bin") or \
                    lower_name.endswith(".x86_64") or '.' not in file:
                gmod_patch_tool_exe = os.path.join(root, file)
                gmod_patch_tool_folder = root
                break
        if gmod_patch_tool_exe:
            break
    if gmod_patch_tool_exe and gmod_patch_tool_folder:
        dest_folder = os.path.join(os.path.dirname(zip_path), "gmodpatchtool")
        if os.path.exists(dest_folder):
            shutil.rmtree(dest_folder)
        try:
            shutil.copytree(gmod_patch_tool_folder, dest_folder)
        except Exception as e:
            log_message(f"⚠️ [ERROR] Failed to copy extracted folder: {e}")
            return None
        exe_name = os.path.basename(gmod_patch_tool_exe)
        global GMOD_PATCH_TOOL_PATH
        GMOD_PATCH_TOOL_PATH = os.path.join(dest_folder, exe_name)
        try:
            os.chmod(GMOD_PATCH_TOOL_PATH, 0o755)  # Ensure the file is executable
        except Exception as e:
            log_message(f"⚠️ [ERROR] Failed to set executable permission: {e}")
        log_message(f"✅ [INFO] Extracted gmodpatchtool to: {dest_folder}")
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
def fetch_server_ip(force=False):
    global server_ip, last_fetch_time
    current_time = time.time()
    if not force and current_time - last_fetch_time < FETCH_INTERVAL_SECONDS:
        debug_log("Skipping server IP fetch; interval not reached.")
        return
    last_fetch_time = current_time

    try:
        response = SESSION.get(SWAMP_URL, timeout=5, headers={'Referer': SWAMP_URL})
        response.raise_for_status()
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
def validate_and_restart_gmod(apply_patch=False):
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
        subprocess.run(["xdg-open", GMOD_VALIDATE_URI],
                       stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)
    failed_attempts = 0
    crash_attempts = 0
    time.sleep(45)  # Wait to ensure Steam has fully validated files
    if apply_patch:
        if not run_gmod_patch_tool():
            log_message("⚠️ [ERROR] gmodpatchtool did not apply successfully after validation.")

# Check GitHub for a newer version of the patch and update if needed
def check_for_new_patch_tool():
    global GMOD_PATCH_TOOL_PATH
    try:
        response = requests.get(f"https://api.github.com/repos/{PATCH_TOOL_REPO}/releases/latest", timeout=10)
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
    if not GMOD_PATCH_TOOL_PATH or not os.path.exists(GMOD_PATCH_TOOL_PATH):
        log_message(f"⚠️ [WARNING] Local patch file not found at {GMOD_PATCH_TOOL_PATH}.")
        return
    try:
        local_timestamp = os.path.getmtime(GMOD_PATCH_TOOL_PATH)
        local_date = datetime.fromtimestamp(local_timestamp)
    except Exception as e:
        log_message(f"⚠️ [ERROR] Could not get modification time for local patch: {e}")
        return
    debug_log(f"Local patch file modification date: {local_date}")
    assets = data.get("assets", [])
    if remote_date > local_date:
        log_message(f"🌍 [INFO] New patch available from {PATCH_TOOL_REPO} (remote: {remote_date}, local: {local_date}). Updating...")
        if os.name == 'nt':
            asset_url = None
            for asset in assets:
                name = asset.get("name", "")
                lower_name = name.lower()
                if lower_name.endswith(".exe") and "gmodpatchtool" in lower_name:
                    asset_url = asset.get("browser_download_url")
                    break
            if asset_url is None:
                for asset in assets:
                    name = asset.get("name", "")
                    lower_name = name.lower()
                    if lower_name.endswith(".zip") and "gmodpatchtool" in lower_name:
                        asset_url = asset.get("browser_download_url")
                        break
            if asset_url:
                try:
                    r = requests.get(asset_url, timeout=10)
                    if r.status_code == 200:
                        exe_path = os.path.join(os.path.dirname(GMOD_PATCH_TOOL_PATH), os.path.basename(asset_url))
                        with open(exe_path, "wb") as f:
                            f.write(r.content)
                        os.chmod(exe_path, 0o755)
                        GMOD_PATCH_TOOL_PATH = exe_path
                        log_message("✅ [INFO] Updated gmodpatchtool to the latest patch.")
                    else:
                        log_message("⚠️ [ERROR] Failed to download the patch from GitHub.")
                except Exception as e:
                    log_message(f"⚠️ [ERROR] Exception while downloading new patch: {e}")
            else:
                log_message("⚠️ [ERROR] No suitable Windows patch found in the latest release.")
        else:
            asset_url = None
            for asset in assets:
                name = asset.get("name", "")
                lower_name = name.lower()
                if "linux" in lower_name and "gmodpatchtool" in lower_name:
                    asset_url = asset.get("browser_download_url")
                    break
            if asset_url is None:
                for asset in assets:
                    name = asset.get("name", "")
                    lower_name = name.lower()
                    if lower_name.endswith(".zip") and "gmodpatchtool" in lower_name:
                        asset_url = asset.get("browser_download_url")
                        break
            if asset_url:
                try:
                    r = requests.get(asset_url, timeout=10)
                    if r.status_code == 200:
                        linux_path = os.path.join(os.path.dirname(GMOD_PATCH_TOOL_PATH), os.path.basename(asset_url))
                        with open(linux_path, "wb") as f:
                            f.write(r.content)
                        os.chmod(linux_path, 0o755)
                        GMOD_PATCH_TOOL_PATH = linux_path
                        log_message("✅ [INFO] Updated gmodpatchtool for Linux to the latest patch.")
                        return
                    else:
                        log_message("⚠️ [ERROR] Failed to download the Linux patch from GitHub.")
                except Exception as e:
                    log_message(f"⚠️ [ERROR] Exception while downloading new patch: {e}")
            else:
                log_message("⚠️ [ERROR] No suitable Linux patch found in the latest release.")
    else:
        log_message(f"✅ [INFO] Local patch is up-to-date (remote: {remote_date}, local: {local_date}).")

def _run_patch_tool_windows():
    try:
        process = subprocess.Popen(
            [GMOD_PATCH_TOOL_PATH],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
    except Exception as e:
        log_message(f"⚠️ [ERROR] Failed to launch gmodpatchtool: {e}")
        return False

    try:
        # Send "n" pre-emptively in case the patcher asks to relaunch GMod.
        stdout, _ = process.communicate(input="n\n", timeout=180)
    except subprocess.TimeoutExpired:
        process.kill()
        log_message("⚠️ [ERROR] gmodpatchtool timed out on Windows.")
        return False

    cleaned_output = _clean_patch_output(stdout)
    if PATCH_SUCCESS_MESSAGE.lower() in cleaned_output.lower():
        log_message("✅ [INFO] gmodpatchtool applied successfully (Windows).")
        log_message(f"Output: {cleaned_output}")
        return True

    log_message("⚠️ [ERROR] gmodpatchtool did not report a successful patch on Windows.")
    log_message(f"Output: {cleaned_output}")
    return False


def _run_patch_tool_posix():
    if pexpect is None:
        log_message("⚠️ [ERROR] pexpect is not installed; cannot run gmodpatchtool interactively on this platform.")
        return False

    try:
        cmd = shlex.quote(GMOD_PATCH_TOOL_PATH)
        child = pexpect.spawn("/bin/bash", ["-c", cmd], timeout=180)
        child.logfile = sys.stdout.buffer
        child.expect(PATCH_SUCCESS_MESSAGE, timeout=180)
        try:
            child.expect("Do you want to Launch Garry's Mod now\\?", timeout=30)
            child.sendline("n")
        except pexpect.TIMEOUT:
            debug_log("No launch prompt received; continuing without sending input.")
        output = _clean_patch_output(child.before)
        log_message("✅ [INFO] gmodpatchtool applied successfully (pexpect).")
        log_message(f"Output: {output}")
        return True
    except pexpect.TIMEOUT:
        log_message("⚠️ [ERROR] gmodpatchtool timed out in pexpect mode.")
        return False
    except Exception as e:
        log_message(f"⚠️ [ERROR] Exception in pexpect patch run: {e}")
        return False


# Run the patch tool using a platform-appropriate strategy.
def run_gmod_patch_tool():
    log_message("🛠 [INFO] Running gmodpatchtool...")
    check_for_new_patch_tool()
    if not GMOD_PATCH_TOOL_PATH or not os.path.exists(GMOD_PATCH_TOOL_PATH):
        log_message(f"⚠️ [ERROR] gmodpatchtool not found at {GMOD_PATCH_TOOL_PATH}")
        return False
    if not os.access(GMOD_PATCH_TOOL_PATH, os.X_OK):
        log_message("⚠️ [ERROR] gmodpatchtool is not executable. Attempting to set executable permission.")
        try:
            os.chmod(GMOD_PATCH_TOOL_PATH, 0o755)
        except Exception as e:
            log_message(f"⚠️ [ERROR] Failed to set executable permission: {e}")
            return False

    if os.name == 'nt':
        return _run_patch_tool_windows()
    return _run_patch_tool_posix()

# Search common directories for the patch; download it if not found
def auto_configure_gmod_patch_tool_path():
    global GMOD_PATCH_TOOL_PATH
    search_dirs = []
    home = os.path.expanduser("~")
    for folder in ["Documents", "Desktop", "Downloads"]:
        dir_path = os.path.join(home, folder)
        if os.path.isdir(dir_path):
            search_dirs.append(dir_path)
    if os.name == 'nt':
        patterns = [
            ("GModPatchTool", ".exe"),
            ("GModPatchTool", ".zip"),
            ("gmodpatchtool", ".exe"),
            ("gmodpatchtool", ".zip"),
        ]
    else:
        patterns = [
            ("GModPatchTool-Linux", ""),
            ("gmodpatchtool", ""),
            ("gmodpatchtool", ".zip"),
            ("GModPatchTool", ".zip"),
        ]
    for d in search_dirs:
        for root, _, files in os.walk(d):
            for file in files:
                for prefix, ext in patterns:
                    if file.startswith(prefix) and file.endswith(ext):
                        candidate = os.path.join(root, file)
                        if ext == ".zip":
                            extract_dir = os.path.join(root, "gmodpatchtool_extracted")
                            os.makedirs(extract_dir, exist_ok=True)
                            try:
                                extract_gmod_patch_tool(candidate, extract_dir)
                                return GMOD_PATCH_TOOL_PATH
                            except Exception as e:
                                log_message(f"⚠️ [ERROR] Failed to extract zip: {e}")
                        else:
                            GMOD_PATCH_TOOL_PATH = candidate
                            log_message(f"Found gmodpatchtool at: {GMOD_PATCH_TOOL_PATH}")
                            return GMOD_PATCH_TOOL_PATH
    log_message("gmodpatchtool not found in common directories. Downloading latest patch...")
    download_latest_gmod_patch_tool()
    return GMOD_PATCH_TOOL_PATH

# Download the latest patch from GitHub if not available locally
def download_latest_gmod_patch_tool():
    global GMOD_PATCH_TOOL_PATH
    download_dir = os.path.dirname(os.path.realpath(__file__))
    try:
        response = requests.get(f"https://api.github.com/repos/{PATCH_TOOL_REPO}/releases/latest", timeout=10)
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
            if name.lower().endswith(".exe") and "gmodpatchtool" in name.lower():
                exe_asset = asset
                break
            elif name.lower().endswith(".zip") and "gmodpatchtool" in name.lower():
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
                GMOD_PATCH_TOOL_PATH = exe_path
                log_message("✅ [INFO] Downloaded latest gmodpatchtool (Windows).")
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
                extract_dir = os.path.join(download_dir, "gmodpatchtool_extracted")
                os.makedirs(extract_dir, exist_ok=True)
                extract_gmod_patch_tool(zip_path, extract_dir)
                return
            else:
                log_message("⚠️ [ERROR] Failed to download the zip patch.")
        else:
            log_message("⚠️ [ERROR] No suitable Windows patch found in the latest release.")
    else:
        linux_asset = None
        linux_zip_asset = None
        for asset in assets:
            name = asset.get("name", "")
            lower_name = name.lower()
            if "linux" in lower_name and "gmodpatchtool" in lower_name:
                linux_asset = asset
                break
            if lower_name.endswith(".zip") and "gmodpatchtool" in lower_name:
                linux_zip_asset = asset
        target_asset = linux_asset or linux_zip_asset
        if target_asset:
            url = target_asset.get("browser_download_url")
            target_path = os.path.join(download_dir, target_asset.get("name"))
            log_message(f"Downloading latest patch (Linux) from: {url}")
            try:
                r = requests.get(url, timeout=10)
            except Exception as e:
                log_message(f"⚠️ [ERROR] Exception while downloading Linux asset: {e}")
                return
            if r.status_code == 200:
                with open(target_path, "wb") as f:
                    f.write(r.content)
                if target_path.lower().endswith(".zip"):
                    extract_dir = os.path.join(download_dir, "gmodpatchtool_extracted")
                    os.makedirs(extract_dir, exist_ok=True)
                    extract_gmod_patch_tool(target_path, extract_dir)
                    return
                try:
                    os.chmod(target_path, 0o755)
                except Exception as e:
                    log_message(f"⚠️ [ERROR] Failed to set executable permission: {e}")
                GMOD_PATCH_TOOL_PATH = target_path
                log_message("✅ [INFO] Downloaded latest gmodpatchtool (Linux).")
                return
            else:
                log_message("⚠️ [ERROR] Failed to download the Linux patch.")
        else:
            log_message("⚠️ [ERROR] No suitable Linux patch found in the latest release.")

# Main loop: continuously check server status and apply patch as needed.
# This loop only re-fetches the server IP after repeated connection failures.
def main():
    global server_ip, failed_attempts, crash_attempts
    auto_configure_gmod_patch_tool_path()
    check_dependencies()
    while True:
        try:
            gmod_running = is_gmod_running()

            # Ensure we have a server IP before checking for UDP traffic
            if server_ip is None:
                fetch_server_ip()

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
                    log_message("⚠️ [INFO] 3 consecutive failed launches detected. Validating game files and applying gmodpatchtool before retrying...")
                    validate_and_restart_gmod(apply_patch=True)
                    crash_attempts = 0
            else:
                log_state_change("connection", False, "🔴 [INFO] GMod is running but NOT connected.")
                failed_attempts += 1
                if failed_attempts >= FAILED_ATTEMPTS_THRESHOLD:
                    fetch_server_ip(force=True)
                    log_message("⚠️ [INFO] Connection retries exceeded. Validating game files and applying gmodpatchtool...")
                    validate_and_restart_gmod(apply_patch=True)
                    failed_attempts = 0

            time.sleep(CHECK_INTERVAL)
        except Exception as e:
            log_message(f"⚠️ [ERROR] Uncaught exception in main loop: {e}")
            time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    main()

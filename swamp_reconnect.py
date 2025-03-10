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

def debug_log(msg):
    if DEBUG:
        print(f"DEBUG: {msg}")

# ------------------------------
# CONFIGURATION (Platform-Specific)
# ------------------------------
SWAMP_URL = "https://swamp.sv/"  # Site to get current server IP
CHECK_DURATION = 5               # Seconds to monitor traffic (time-based capture)
MAX_RETRIES = 3                  # Max retries for detection
CHECK_INTERVAL = 5               # Time between each connection check (in seconds)
FAILED_ATTEMPTS_THRESHOLD = 3    # Connection failures before validation

if os.name == 'nt':
    # Windows settings
    GMOD_LAUNCH_CMD = "start steam://connect/{server_ip}:27015"
    # Default placeholder for Windows
    GMOD_CEF_FIX_PATH = r"C:\Path\To\GModCEFCodecFix-Windows.exe"
    PROCESS_NAMES = ["gmod.exe"]
    REQUIRED_CMDS = ["dumpcap"]
else:
    # Linux settings
    GMOD_LAUNCH_CMD = "xdg-open 'steam://connect/{server_ip}:27015'"
    # Default placeholder for Linux
    GMOD_CEF_FIX_PATH = "/Path/To/GModCEFCodecFix-Linux"
    PROCESS_NAMES = ["gmod", "hl2_linux", "hl2.sh", "garrysmod"]
    REQUIRED_CMDS = ["tcpdump", "pgrep", "xdg-open"]

# ------------------------------
# STATE TRACKING
# ------------------------------
last_gmod_state = None
last_connection_state = None
failed_attempts = 0   # For connection failures (GMod running but not connected)
crash_attempts = 0    # For launch failures (GMod not running, assumed crash)
server_ip = None

# ------------------------------
# HELPER FUNCTIONS
# ------------------------------
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
            output = subprocess.check_output("tasklist", shell=True, text=True)
            debug_log(f"tasklist output: {output[:100]}...")
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
        result = subprocess.run("dumpcap -D", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)
        lines = result.stdout.splitlines()
        debug_log(f"dumpcap -D output: {lines}")
        return lines
    except Exception as e:
        log_message(f"⚠️ [WARNING] Exception in get_windows_capture_interfaces: {e}")
        return []

def find_active_interface(ip):
    """
    Iterates over available interfaces using dumpcap -D and tests each with the BPF filter "host {ip}".
    Uses a duration-based capture of 2 seconds for testing.
    Returns the first interface index that produces a capture file with data, or defaults to "1".
    """
    dumpcap_path = shutil.which("dumpcap")
    if not dumpcap_path:
        log_message("⚠️ [ERROR] dumpcap not found.")
        return "1"
    interfaces = get_windows_capture_interfaces()
    candidate_ifaces = []
    for line in interfaces:
        match = re.match(r"(\d+)\.", line)
        if match:
            candidate_ifaces.append(match.group(1))
    debug_log(f"Candidate interfaces: {candidate_ifaces}")
    
    filter_str = f"host {ip}"
    for iface in candidate_ifaces:
        temp_file = "temp_test.pcap"
        cmd = f'"{dumpcap_path}" -i {iface} -a duration:2 -f "{filter_str}" -w {temp_file}'
        debug_log(f"Testing interface {iface} with filter: {filter_str}")
        try:
            subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3)
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
    """
    Checks if any packets from the server IP are captured.
    On Windows, uses dumpcap with a selected interface and the BPF filter "host {ip}" with a time-based capture.
    On Linux, uses tcpdump with the same filter.
    """
    if os.name == 'nt':
        dumpcap_path = shutil.which("dumpcap")
        if not dumpcap_path:
            return False
        interface = find_active_interface(ip)
        debug_log(f"Using interface {interface} for capture.")
        filter_str = f"host {ip}"
        for attempt in range(retries):
            temp_file = "temp_capture.pcap"
            cmd = f'"{dumpcap_path}" -i {interface} -a duration:{CHECK_DURATION} -f "{filter_str}" -w {temp_file}'
            debug_log(f"Attempt {attempt+1}: Running command: {cmd}")
            try:
                subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=CHECK_DURATION+2)
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
            filter_str = f"host {ip}"
            cmd = f"timeout {CHECK_DURATION} tcpdump -nn -q -c {MIN_PACKET_THRESHOLD} '{filter_str}'"
            debug_log(f"Attempt {attempt+1}: Running command: {cmd}")
            result = subprocess.run(cmd, shell=True,
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
    global failed_attempts, crash_attempts
    if server_ip:
        log_message(f"🚀 [INFO] Launching GMod & connecting to {server_ip}:27015...")
        subprocess.run(GMOD_LAUNCH_CMD.format(server_ip=server_ip), shell=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(30)
        failed_attempts = 0
    else:
        log_message("⚠️ [ERROR] No valid server IP. Cannot launch GMod.")

def validate_and_restart_gmod():
    global failed_attempts, crash_attempts
    log_message("🔄 [INFO] Restarting GMod & verifying game files...")
    if os.name == 'nt':
        try:
            subprocess.run("taskkill /F /IM gmod.exe", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            debug_log(f"Error during taskkill: {e}")
        subprocess.run("start steam://validate/4000", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        subprocess.run("pkill -9 gmod", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run("steam steam://validate/4000", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
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
            new_url = "https://raw.githubusercontent.com/solsticegamestudios/GModCEFCodecFix/main/GModCEFCodecFix-Windows.exe"
        else:
            new_url = "https://raw.githubusercontent.com/solsticegamestudios/GModCEFCodecFix/main/GModCEFCodecFix-Linux"
        try:
            r = requests.get(new_url, timeout=10)
            if r.status_code == 200:
                with open(GMOD_CEF_FIX_PATH, "wb") as f:
                    f.write(r.content)
                os.chmod(GMOD_CEF_FIX_PATH, 0o755)
                log_message("✅ [INFO] Updated GModCEFCodecFix to the latest version.")
            else:
                log_message("⚠️ [ERROR] Failed to download the latest patch from GitHub.")
        except Exception as e:
            log_message(f"⚠️ [ERROR] Exception while downloading new patch: {e}")
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

def update_gmod_cef_path_in_source(new_path):
    """
    Updates the GMOD_CEF_FIX_PATH value in the source file permanently.
    Reads the current source file, replaces the line that defines GMOD_CEF_FIX_PATH,
    and writes the updated file back.
    """
    file_path = os.path.realpath(__file__)
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        with open(file_path, "w", encoding="utf-8") as f:
            for line in lines:
                if line.strip().startswith("GMOD_CEF_FIX_PATH ="):
                    f.write(f'GMOD_CEF_FIX_PATH = r"{new_path}"  # Updated by configuration prompt\n')
                else:
                    f.write(line)
        log_message("✅ [INFO] GMOD_CEF_FIX_PATH updated in source file.")
    except Exception as e:
        log_message(f"⚠️ [ERROR] Failed to update GMOD_CEF_FIX_PATH in source file: {e}")

def prompt_for_gmod_cef_path():
    """
    Prompts the user to enter the GMOD CEF path if the current path is still the default.
    Checks if the entered path is valid (exists and is a file). Updates the global variable
    and the source file accordingly.
    """
    global GMOD_CEF_FIX_PATH
    if os.name == 'nt':
        default_path = r"C:\Path\To\GModCEFCodecFix-Windows.exe"
    else:
        default_path = "/Path/To/GModCEFCodecFix-Linux"
    while GMOD_CEF_FIX_PATH == default_path or GMOD_CEF_FIX_PATH.strip() == "":
        new_path = input("Enter the full path to the GModCEFCodecFix executable: ").strip()
        if new_path:
            if os.path.isfile(new_path):
                GMOD_CEF_FIX_PATH = new_path
                update_gmod_cef_path_in_source(new_path)
                break
            else:
                log_message("⚠️ [WARNING] The path entered does not exist or is not a file. Please try again.")
        else:
            log_message("⚠️ [WARNING] No path entered; using default placeholder.")
            break

# ------------------------------
# MAIN LOOP
# ------------------------------
if __name__ == "__main__":
    prompt_for_gmod_cef_path()  # Prompt the user if the path is not set properly.
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

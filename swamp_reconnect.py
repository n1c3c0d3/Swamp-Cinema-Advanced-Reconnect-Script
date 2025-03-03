#!/usr/bin/env python3
import subprocess
import time
import requests
import json
import re
import os
from datetime import datetime
import pexpect

# ✅ CONFIGURATION
SWAMP_URL = "https://swamp.sv/"  # Site to get current server IP
CHECK_DURATION = 5               # Time in seconds to monitor UDP packets
MIN_PACKET_THRESHOLD = 5         # Minimum UDP packets required
MAX_RETRIES = 3                  # Max retries for UDP detection
CHECK_INTERVAL = 5               # Reduced time between each connection check (from 10 to 5 seconds)
FAILED_ATTEMPTS_THRESHOLD = 3    # Attempts for connection failures before validation
GMOD_LAUNCH_CMD = "xdg-open 'steam://connect/{server_ip}:27015'"  # Command to launch GMod
GMOD_CEF_FIX_PATH = "/home/nicegame/Documents/GModCEFCodecFix-Linux"  # Path to CEF Fix patch executable

# ✅ STATE TRACKING
last_gmod_state = None
last_connection_state = None
failed_attempts = 0       # For connection failures (GMod running but not connected)
crash_attempts = 0        # For launch failures (GMod not running, assumed crash)
server_ip = None

def log_message(message):
    """Prints a message prefixed with a timestamp in 12-hour format with AM/PM."""
    print(f"{time.strftime('%Y-%m-%d %I:%M:%S %p')} {message}")

def fetch_server_ip():
    """Scrapes swamp.sv for the latest server IP."""
    global server_ip
    try:
        response = requests.get(SWAMP_URL, timeout=5)
        match = re.search(r"steam://connect/(\d+\.\d+\.\d+\.\d+):(\d+)", response.text)
        if match:
            new_ip = match.group(1)
            if new_ip != server_ip:
                log_message(f"🌍 [INFO] Updated server IP: {new_ip}")
                server_ip = new_ip
    except Exception as e:
        log_message(f"⚠️ [ERROR] Failed to fetch server IP: {e}")

def is_gmod_running():
    """Checks if GMod process is running."""
    process_names = ["gmod", "hl2_linux", "hl2.sh", "garrysmod"]
    try:
        for process in process_names:
            result = subprocess.run(["pgrep", "-a", process],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL,
                                    text=True)
            if result.stdout.strip():
                return True  # ✅ GMod is running
        return False  # ❌ GMod is not running
    except Exception:
        return False

def check_udp_traffic(ip, retries=MAX_RETRIES):
    """Checks if UDP packets are actively being exchanged with the server."""
    for attempt in range(retries):
        debug_command = f"timeout {CHECK_DURATION} tcpdump -nn -q -c {MIN_PACKET_THRESHOLD} 'udp and host {ip}'"
        result = subprocess.run(debug_command, shell=True,
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL,
                                  text=True)
        if result.returncode == 0 and "UDP" in result.stdout:
            return True  # ✅ Active UDP packets detected
        elif result.returncode == 124:
            pass  # Timeout expired without enough packets
        time.sleep(2)  # 🔄 Delay before retry
    return False  # ❌ No active UDP exchange detected

def log_state_change(state_variable, new_state, message):
    """Prints message only when state changes."""
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
    """Launches GMod using Steam's connect URL."""
    global failed_attempts, crash_attempts
    if server_ip:
        log_message(f"🚀 [INFO] Launching GMod & connecting to {server_ip}:27015...")
        subprocess.run(GMOD_LAUNCH_CMD.format(server_ip=server_ip), shell=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(30)  # Reduced delay from 60 to 30 seconds
        failed_attempts = 0
    else:
        log_message("⚠️ [ERROR] No valid server IP. Cannot launch GMod.")

def validate_and_restart_gmod():
    """Validates & updates GMod if it fails too many times, then runs the CEF patch."""
    global failed_attempts, crash_attempts
    log_message("🔄 [INFO] Restarting GMod & verifying game files...")
    subprocess.run("pkill -9 gmod", shell=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run("steam steam://validate/4000", shell=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    failed_attempts = 0
    crash_attempts = 0  # Reset crash counter after validation
    time.sleep(15)  # Reduced delay from 30 to 15 seconds
    if not run_gmod_cef_fix():
        log_message("⚠️ [ERROR] GModCEFCodecFix did not apply successfully after validation.")

def check_for_new_cef_fix():
    """
    Checks GitHub for the latest release of GModCEFCodecFix.
    Compares the remote release's creation date to the local file's modification time.
    If the remote date is newer, downloads and updates the patch.
    """
    try:
        response = requests.get("https://api.github.com/repos/solsticegamestudios/GModCEFCodecFix/releases/latest", timeout=10)
        if response.status_code != 200:
            log_message("⚠️ [ERROR] Failed to fetch release info from GitHub.")
            return
        data = response.json()
        remote_created_at_str = data.get("created_at", None)
        if not remote_created_at_str:
            log_message("⚠️ [ERROR] Remote release info did not contain a creation date.")
            return
        remote_date = datetime.strptime(remote_created_at_str, "%Y-%m-%dT%H:%M:%SZ")
    except Exception as e:
        log_message(f"⚠️ [ERROR] Exception while fetching remote release info: {e}")
        return

    if not os.path.exists(GMOD_CEF_FIX_PATH):
        log_message(f"⚠️ [WARNING] Local patch file not found at {GMOD_CEF_FIX_PATH}.")
        return

    local_timestamp = os.path.getmtime(GMOD_CEF_FIX_PATH)
    local_date = datetime.fromtimestamp(local_timestamp)

    if remote_date > local_date:
        log_message(f"🌍 [INFO] New patch available (remote: {remote_date}, local: {local_date}). Updating...")
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
    """
    Runs GModCEFCodecFix to patch game files automatically using pexpect in a pseudo-terminal.
    Sends "n" to answer the yes/no prompt and an extra newline for the "press enter" prompt.
    Waits for the success indicator "CEFCodecFix applied successfully!".
    Returns True if the patch appears successful, False otherwise.
    """
    log_message("🛠 [INFO] Running GModCEFCodecFix with pexpect...")

    # Check for a new patch and update if needed.
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

if __name__ == "__main__":
    while True:
        fetch_server_ip()
        gmod_running = is_gmod_running()
        udp_active = check_udp_traffic(server_ip) if server_ip else False

        if gmod_running and udp_active:
            log_state_change("gmod", True, "🟢 [INFO] GMod is running & connected to the server.")
            failed_attempts = 0
            crash_attempts = 0  # Reset crash counter on success
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

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Swamp Reconnect Script

A fault-tolerant auto-reconnect manager for Garry’s Mod clients on the
Swamp Cinema server. The script continuously evaluates the client’s
connection state and applies staged recovery actions when problems are
detected.

High-level design:
------------------
• Healthy state:
  GMod is running AND UDP traffic is observed with the active Swamp IP.

• Failure detection:
  Consecutive failed connectivity checks increment `failure_ticks`
  (server must be online for failures to count).

• Recovery pipeline:
    1. Soft recovery:
       - Run GModPatchTool after repeated failures.
       - Relaunch GMod and attempt to reconnect.
    2. Hard recovery:
       - If post-patch failures persist, trigger Steam file validation
         and re-apply the patch (at most once per failure window).
    3. Final escalation:
       - If even validation fails to stabilize the connection,
         the script continues relaunch attempts but does not spam
         validation loops.
       - If failures keep accumulating, enter “catastrophic” mode:
         pause all remediation for 1 hour, then retry.

• Patch management:
  - Automatically discover or download GModPatchTool.
  - Select correct platform asset.
  - Auto-update to the latest release.
  - Clean up stale pid-locks or zombie patcher processes.

• Server monitoring:
  - UDP packet sniffing (tcpdump/dumpcap).
  - A2S_INFO pings when no packets are observed.
  - Live server IP scraping from swamp.sv.

Behavior summary:
-----------------
- When the Swamp server is OFFLINE/unreachable:
  * No failures are counted and no patches/validations are triggered.

- When GMod is NOT running while the server is online:
  * The script launches GMod and allows a grace window.
  * If GMod starts and then closes before ever reaching a healthy
    connection, that counts as a failure tick.
  * If GMod never appears to start within the grace window, that also
    counts as a failure tick.

- When GMod IS running but has no UDP traffic while the server is online:
  * Each such check after the grace window counts as a failure tick.

- Validation is **not** retried endlessly:
  * After a validate+patch cycle, the script will not revalidate again
    until a healthy connection has been achieved at least once.

- Catastrophic mode:
  * If the failure count explodes (e.g. VAC/Steam outage or deep
    systemic problem), the script enters a 1-hour backoff period with
    no patch/validate/relaunch.
  * After that hour, it resets the recovery window and retries the
    normal pipeline.
"""

__version__ = "DEV"

import os
import sys
import re
import time
import shutil
import subprocess
import zipfile
import tarfile
import tempfile
from datetime import datetime
import socket  # for A2S_INFO server-online checks

import requests
import pexpect
import signal  # For sending SIGTERM/SIGKILL to stale GModPatchTool processes

# Optional debug logger (controlled by DEBUG flag)
# 0=off, 1=basic, 2=detailed, 3=verbose   (verbose is not implemented until unknown exceptions arise, only meant for meticulous diagnostics)
DEBUG_LEVEL = 0

def debug(level: int, msg: str) -> None:
    if DEBUG_LEVEL >= level:
        print(f"[DEBUG-{level}] {msg}")

# Backwards-compatible single-level debug logger.
# Existing calls in the script use debug_log(msg); these are treated as level 1 debug messages under the new system.
def debug_log(msg: str) -> None:
    debug(1, msg)

# Where we scrape the live server IP from:
SWAMP_URL = "https://swamp.sv/"

# Networking/monitoring knobs
CHECK_DURATION = 3            # seconds to listen for network packets each check
MAX_RETRIES = 2               # how many quick attempts for packet checks (per phase)
CHECK_INTERVAL = 10           # main loop sleep between checks (seconds)
PATCH_FAILURE_THRESHOLD = 3   # after this many failure ticks, run patch (no validation)
POST_PATCH_VALIDATION_THRESHOLD = 2  # after patching, this many more fails => validate + patch
MIN_PACKET_THRESHOLD = 5      # tcpdump -c <count>; how many packets qualify a "connected" state

# Grace period after launching GMod before we treat failures as real
LAUNCH_GRACE_SECONDS = 45

# Catastrophic backoff configuration
MAX_FAILURES_PER_WINDOW = 10          # hard cap on failures before we consider it catastrophic
CATASTROPHIC_BACKOFF_SECONDS = 3600   # 1 hour cooldown before retrying full recovery pipeline

# Cache server IP fetches to avoid hammering the site
FETCH_INTERVAL_SECONDS = 60
last_fetch_time = 0

# Shared HTTP session with sensible headers (helps avoid being blocked)
SESSION = requests.Session()
SESSION.headers.update({
    'User-Agent': (
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 '
        '(KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36'
    ),
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9',
    'Connection': 'keep-alive',
})

# OS-specific settings for Steam URIs, process names, and required commands
if os.name == 'nt':
    GMOD_STEAM_URI = "steam://connect/{server_ip}:27015"  # Steam connect URI
    GMOD_VALIDATE_URI = "steam://validate/4000"           # Steam validate URI
    PROCESS_NAMES = ["gmod.exe"]                          # Processes indicating GMod is running
    REQUIRED_CMDS = ["dumpcap"]                           # Capture tool on Windows (Wireshark family)
else:
    GMOD_STEAM_URI = "steam://connect/{server_ip}:27015"
    GMOD_VALIDATE_URI = "steam://validate/4000"
    PROCESS_NAMES = ["gmod", "hl2_linux", "hl2.sh", "garrysmod"]  # Common Linux GMod processes
    REQUIRED_CMDS = ["tcpdump", "pgrep", "xdg-open", "timeout"]   # Capture, process grep, open URIs, timeout

# Path to the patcher executable (set dynamically)
GMOD_PATCH_TOOL_PATH: str | None = None
# Base directory (used when saving patcher downloads)
SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))

# State trackers for logging & policy decisions
last_gmod_state: bool | None = None         # Last known "GMod running" state
last_connection_state: bool | None = None   # Last known network connectivity state

failure_ticks = 0  # Consecutive failures while server is online (only when GMod is running / launching)
server_ip: str | None = None  # Current Swamp server IP scraped from SWAMP_URL

patch_triggered_after_failures = False        # True once patch has been run for this failure window
post_patch_failure_attempts = 0               # Failures after patch before validation escalation
patch_required_before_launch = False          # Flag that a patch is required before next launch
validated_and_patched_recently = False        # True after a validate+patch cycle started
had_success_since_validate = False            # Tracks a successful connection post-validate

loop_count = 0            # Simple loop counter for diagnostics
last_launch_time = None   # Timestamp of last GMod launch (for grace period)

# Per-launch flags:
gmod_seen_since_launch = False      # True if we've seen GMod running since last launch
healthy_since_launch = False        # True if we've seen a healthy connection since last launch

# Catastrophic mode state:
catastrophic_mode = False           # True when we've given up for an hour
catastrophic_since = None           # Timestamp when catastrophic mode was entered


def log_message(message: str) -> None:
    # Standard timestamped log output
    print(f"{time.strftime('%Y-%m-%d %I:%M:%S %p')} {message}")


def log_state_change(state_variable: str, new_state: bool, message: str) -> None:
    # Emit state transitions once instead of logging the same message every loop
    global last_gmod_state, last_connection_state
    if state_variable == "gmod":
        if new_state != last_gmod_state:
            log_message(message)
            last_gmod_state = new_state
    elif state_variable == "connection":
        if new_state != last_connection_state:
            log_message(message)
            last_connection_state = new_state


def is_archive(path: str) -> bool:
    # Identify common archive formats used for GModPatchTool distribution
    lower = path.lower()
    return lower.endswith((".zip", ".tar", ".tar.gz", ".tgz"))


def find_executable_in_dir(dir_path: str) -> str | None:
    # Locate a GModPatchTool executable under dir_path, respecting platform expectations
    for root, dirs, files in os.walk(dir_path):
        for file in files:
            name = file.lower()
            if (
                "gmodpatchtool" in name
                and not name.endswith((".zip", ".tar", ".tar.gz", ".tgz", ".pid"))
            ):
                candidate = os.path.join(root, file)
                if os.name == 'nt':
                    if not name.endswith(".exe"):
                        continue
                else:
                    try:
                        os.chmod(candidate, 0o755)
                    except Exception:
                        pass
                    if not os.access(candidate, os.X_OK):
                        continue
                return candidate
    return None


def check_dependencies() -> None:
    # Check for external tools used for monitoring and launching; log if any are missing
    missing = []
    for cmd in REQUIRED_CMDS:
        if shutil.which(cmd) is None:
            missing.append(cmd)
            debug_log(f"Command not found: {cmd}")
    if missing:
        log_message("⚠️ [WARNING] Missing helper commands: " + ", ".join(missing))
    else:
        log_message("✅ [INFO] All required system commands are available.")


def fetch_server_ip(force: bool = False) -> None:
    # Scrape the Swamp website for the current server IP, with simple caching
    global server_ip, last_fetch_time
    current_time = time.time()
    if not force and current_time - last_fetch_time < FETCH_INTERVAL_SECONDS:
        return
    last_fetch_time = current_time

    try:
        response = SESSION.get(SWAMP_URL, timeout=5, headers={'Referer': SWAMP_URL})
        response.raise_for_status()
    except Exception as e:
        log_message(f"⚠️ [ERROR] Failed to fetch server IP: {e}")
        return

    match = re.search(r"steam://connect/(\d+\.\d+\.\d+\.\d+):(\d+)", response.text)
    if match:
        new_ip = match.group(1)
        if new_ip != server_ip:
            log_message(f"🌍 [INFO] Updated server IP: {new_ip}")
            server_ip = new_ip
    else:
        log_message("⚠️ [WARNING] Could not parse server IP from response.")


def is_gmod_running() -> bool:
    # Determine whether GMod is currently running on this machine
    if os.name == 'nt':
        try:
            output = subprocess.check_output(["tasklist"], text=True)
            for proc in PROCESS_NAMES:
                if proc.lower() in output.lower():
                    return True
            return False
        except Exception as e:
            log_message(f"⚠️ [ERROR] Exception in is_gmod_running: {e}")
            return False
    else:
        try:
            for process in PROCESS_NAMES:
                result = subprocess.run(
                    ["pgrep", "-a", process],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True,
                )
                if result.stdout.strip():
                    return True
            return False
        except Exception as e:
            log_message(f"⚠️ [ERROR] Exception in is_gmod_running: {e}")
            return False


def get_windows_capture_interfaces() -> list[str]:
    # Return the raw dumpcap interface listing on Windows
    dumpcap_path = shutil.which("dumpcap")
    if not dumpcap_path:
        log_message("⚠️ [ERROR] dumpcap not found.")
        return []
    try:
        result = subprocess.run(
            [dumpcap_path, "-D"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
        )
        return result.stdout.splitlines()
    except Exception as e:
        log_message(f"⚠️ [WARNING] Exception in get_windows_capture_interfaces: {e}")
        return []


def find_active_interface(ip: str) -> str:
    # Heuristic to pick a dumpcap interface that sees traffic to the target IP
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
    filter_str = f"host {ip}"
    for iface in candidate_ifaces:
        temp_file = "temp_test.pcap"
        cmd = [
            dumpcap_path,
            "-i", iface,
            "-a", "duration:2",
            "-f", filter_str,
            "-w", temp_file,
        ]
        try:
            subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=3,
            )
            if os.path.exists(temp_file):
                size = os.path.getsize(temp_file)
                os.remove(temp_file)
                if size > 0:
                    return iface
        except subprocess.TimeoutExpired:
            if os.path.exists(temp_file):
                os.remove(temp_file)
            continue
    log_message("⚠️ [WARNING] No active interface detected; defaulting to interface 1.")
    return "1"


def check_udp_traffic(ip: str, retries: int = MAX_RETRIES) -> bool:
    # Check whether we observe UDP traffic to/from the Swamp server IP
    if not ip:
        return False
    if os.name == 'nt':
        dumpcap_path = shutil.which("dumpcap")
        if not dumpcap_path:
            return False
        interface = find_active_interface(ip)
        filter_str = f"host {ip}"
        for _ in range(retries):
            temp_file = "temp_capture.pcap"
            cmd = [
                dumpcap_path,
                "-i", interface,
                "-a", f"duration:{CHECK_DURATION}",
                "-f", filter_str,
                "-w", temp_file,
            ]
            try:
                subprocess.run(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=CHECK_DURATION + 2,
                )
                if os.path.exists(temp_file):
                    size = os.path.getsize(temp_file)
                    os.remove(temp_file)
                    if size > 0:
                        return True
            except subprocess.TimeoutExpired:
                if os.path.exists(temp_file):
                    os.remove(temp_file)
            time.sleep(2)
        return False
    else:
        for _ in range(retries):
            cmd = [
                "timeout", str(CHECK_DURATION),
                "tcpdump", "-nn", "-q", "-c", str(MIN_PACKET_THRESHOLD),
                "host", ip,
            ]
            try:
                result = subprocess.run(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True,
                )
                if result.returncode == 0 and ip in result.stdout:
                    return True
            except Exception as e:
                debug_log(f"Error running tcpdump: {e}")
            time.sleep(2)
        return False


def is_server_online(ip: str, port: int = 27015, timeout: float = 2.0) -> bool:
    # Probe the Source server with an A2S_INFO request to see if it is responding
    if not ip:
        return False

    try:
        packet = b"\xFF\xFF\xFF\xFFTSource Engine Query\x00"
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(packet, (ip, port))
            data, _ = sock.recvfrom(4096)
            if data:
                debug_log(f"Server online check: received {len(data)} bytes from {ip}:{port}")
                return True
            debug_log(f"Server online check: empty response from {ip}:{port}")
            return False
        finally:
            sock.close()
    except Exception as e:
        debug_log(f"Error checking server online status for {ip}:{port}: {e}")
        return False


def extract_gmod_patch_tool(zip_path: str) -> str | None:
    # Normalize a downloaded archive into a clean GModPatchTool/ folder
    global GMOD_PATCH_TOOL_PATH
    try:
        with tempfile.TemporaryDirectory(prefix="gmodpatchtool_") as tmpdir:
            if zip_path.lower().endswith(".zip"):
                with zipfile.ZipFile(zip_path, 'r') as zf:
                    zf.extractall(tmpdir)
            else:
                with tarfile.open(zip_path, 'r:*') as tf:
                    tf.extractall(tmpdir)

            exe = find_executable_in_dir(tmpdir)
            if exe:
                dest_folder = os.path.join(os.path.dirname(zip_path), "GModPatchTool")
                if os.path.exists(dest_folder):
                    shutil.rmtree(dest_folder)
                shutil.copytree(os.path.dirname(exe), dest_folder)

                GMOD_PATCH_TOOL_PATH = os.path.join(dest_folder, os.path.basename(exe))
                try:
                    os.chmod(GMOD_PATCH_TOOL_PATH, 0o755)
                except Exception as e:
                    log_message(f"⚠️ [ERROR] Failed to set executable permission: {e}")
                log_message(f"✅ [INFO] Extracted GModPatchTool to: {dest_folder}")
                return dest_folder
            else:
                log_message("⚠️ [ERROR] No executable found in the extracted archive.")
                return None
    except Exception as e:
        log_message(f"⚠️ [ERROR] Failed to extract archive: {e}")
        return None


def _select_platform_asset(assets: list[dict]) -> dict | None:
    # Choose an appropriate GModPatchTool release asset for the current platform
    if not assets:
        return None

    for a in assets:
        name = a.get("name", "").lower()
        is_linux = "linux" in name
        is_windows = ("windows" in name) or name.endswith(".exe")
        if os.name == 'nt' and is_windows:
            return a
        if os.name != 'nt' and is_linux:
            return a

    for a in assets:
        name = a.get("name", "").lower()
        if "gmodpatchtool" in name and name.endswith((".zip", ".tar.gz", ".tgz")):
            if os.name == 'nt' and "linux" in name:
                continue
            if os.name != 'nt' and ("windows" in name or name.endswith(".exe")):
                continue
            return a

    for a in assets:
        name = a.get("name", "").lower()
        if "gmodpatchtool" in name:
            return a

    return None


def auto_configure_gmod_patch_tool_path() -> str | None:
    # Try to locate an existing GModPatchTool installation or archive, otherwise download it
    global GMOD_PATCH_TOOL_PATH
    if GMOD_PATCH_TOOL_PATH and os.path.exists(GMOD_PATCH_TOOL_PATH) and os.access(GMOD_PATCH_TOOL_PATH, os.X_OK):
        return GMOD_PATCH_TOOL_PATH

    search_dirs = [SCRIPT_DIR]
    home = os.path.expanduser("~")
    for folder in ["Documents", "Desktop", "Downloads"]:
        dir_path = os.path.join(home, folder)
        if os.path.isdir(dir_path) and dir_path not in search_dirs:
            search_dirs.append(dir_path)

    for d in search_dirs:
        canonical = os.path.join(d, "GModPatchTool")
        if os.path.isdir(canonical):
            exe = find_executable_in_dir(canonical)
            if exe:
                GMOD_PATCH_TOOL_PATH = exe
                log_message(f"Found GModPatchTool at: {GMOD_PATCH_TOOL_PATH}")
                return GMOD_PATCH_TOOL_PATH

    for d in search_dirs:
        for root, _, files in os.walk(d):
            for file in files:
                path = os.path.join(root, file)
                lname = file.lower()
                if "gmodpatchtool" not in lname:
                    continue
                if is_archive(path):
                    if extract_gmod_patch_tool(path):
                        return GMOD_PATCH_TOOL_PATH
                else:
                    if os.name == 'nt' and not lname.endswith(".exe"):
                        continue
                    try:
                        os.chmod(path, 0o755)
                    except Exception:
                        pass
                    if os.access(path, os.X_OK):
                        dest_folder = os.path.join(os.path.dirname(path), "GModPatchTool")
                        if os.path.exists(dest_folder):
                            shutil.rmtree(dest_folder)
                        os.makedirs(dest_folder, exist_ok=True)
                        dest = os.path.join(dest_folder, os.path.basename(path))
                        try:
                            shutil.copy2(path, dest)
                            os.chmod(dest, 0o755)
                        except Exception:
                            dest = path
                        GMOD_PATCH_TOOL_PATH = dest
                        log_message(f"Found GModPatchTool at: {GMOD_PATCH_TOOL_PATH}")
                        return GMOD_PATCH_TOOL_PATH

    log_message("GModPatchTool not found in common directories. Downloading latest patch...")
    download_latest_gmod_patch_tool()
    return GMOD_PATCH_TOOL_PATH


def ensure_gmod_patch_tool_ready() -> bool:
    # Ensure GMOD_PATCH_TOOL_PATH is set to an executable on disk
    if GMOD_PATCH_TOOL_PATH and os.path.exists(GMOD_PATCH_TOOL_PATH):
        return True
    auto_configure_gmod_patch_tool_path()
    if GMOD_PATCH_TOOL_PATH and os.path.exists(GMOD_PATCH_TOOL_PATH):
        return True
    log_message("⚠️ [ERROR] Unable to locate GModPatchTool. Download may have failed.")
    return False


def download_latest_gmod_patch_tool() -> None:
    # Download the latest GModPatchTool release asset for this platform and normalize it
    global GMOD_PATCH_TOOL_PATH
    download_dir = os.path.dirname(os.path.realpath(__file__))
    try:
        response = requests.get(
            "https://api.github.com/repos/solsticegamestudios/GModPatchTool/releases/latest",
            timeout=10,
        )
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

    asset = _select_platform_asset(data.get("assets", []))
    if not asset:
        log_message("⚠️ [ERROR] No suitable patch found in the latest release.")
        return

    url = asset.get("browser_download_url")
    name = asset.get("name", "gmodpatchtool")
    if not url:
        log_message("⚠️ [ERROR] Asset download URL missing.")
        return

    out_path = os.path.join(download_dir, name)
    log_message(f"Downloading latest patch from: {url}")
    try:
        r = requests.get(url, timeout=20)
    except Exception as e:
        log_message(f"⚠️ [ERROR] Exception while downloading patch: {e}")
        return

    if r.status_code == 200:
        with open(out_path, "wb") as f:
            f.write(r.content)

        if is_archive(out_path):
            extract_gmod_patch_tool(out_path)
        else:
            try:
                os.chmod(out_path, 0o755)
            except Exception:
                pass
            dest_folder = os.path.join(download_dir, "GModPatchTool")
            if os.path.exists(dest_folder):
                shutil.rmtree(dest_folder)
            os.makedirs(dest_folder, exist_ok=True)
            dest = os.path.join(dest_folder, os.path.basename(out_path))
            try:
                shutil.copy2(out_path, dest)
                os.chmod(dest, 0o755)
            except Exception:
                dest = out_path
            GMOD_PATCH_TOOL_PATH = dest

        log_message(f"✅ [INFO] Downloaded latest patch asset for this platform: {name}")
    else:
        log_message("⚠️ [ERROR] Failed to download the patch.")


def check_for_new_patch_tool() -> None:
    # Compare local GModPatchTool timestamp with the latest GitHub release and update if needed
    global GMOD_PATCH_TOOL_PATH
    try:
        response = requests.get(
            "https://api.github.com/repos/solsticegamestudios/GModPatchTool/releases/latest",
            timeout=10,
        )
    except Exception as e:
        log_message(f"⚠️ [ERROR] Exception while fetching remote release info: {e}")
        return
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

    if not GMOD_PATCH_TOOL_PATH or not os.path.exists(GMOD_PATCH_TOOL_PATH):
        log_message("⚠️ [WARNING] Local patch file not found for update check.")
        return

    try:
        local_timestamp = os.path.getmtime(GMOD_PATCH_TOOL_PATH)
        local_date = datetime.fromtimestamp(local_timestamp)
    except Exception as e:
        log_message(f"⚠️ [ERROR] Could not get modification time for local patch: {e}")
        return

    if remote_date > local_date:
        log_message(f"🌍 [INFO] New patch available (remote: {remote_date}, local: {local_date}). Updating...")
        asset = _select_platform_asset(data.get("assets", []))
        if not asset:
            log_message("⚠️ [ERROR] No suitable patch asset found in the latest release.")
            return

        asset_url = asset.get("browser_download_url")
        out_name = asset.get("name", "gmodpatchtool")
        if not asset_url:
            log_message("⚠️ [ERROR] Asset download URL missing.")
            return

        try:
            r = requests.get(asset_url, timeout=15)
            if r.status_code == 200:
                out_path = os.path.join(os.path.dirname(GMOD_PATCH_TOOL_PATH) or SCRIPT_DIR, out_name)
                with open(out_path, "wb") as f:
                    f.write(r.content)

                if is_archive(out_path):
                    extract_gmod_patch_tool(out_path)
                else:
                    try:
                        os.chmod(out_path, 0o755)
                    except Exception:
                        pass
                    GMOD_PATCH_TOOL_PATH = out_path

                log_message(f"✅ [INFO] Updated GModPatchTool to the latest platform asset: {out_name}")
            else:
                log_message("⚠️ [ERROR] Failed to download the patch from GitHub.")
        except Exception as e:
            log_message(f"⚠️ [ERROR] Exception while downloading new patch: {e}")
    else:
        log_message(f"✅ [INFO] Local patch is up-to-date (remote: {remote_date}, local: {local_date}).")


def _pid_alive(pid: int) -> bool:
    # Return True if a process with the given PID appears to exist
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except OSError:
        return True


def _try_kill_pid(pid: int, desc: str = "GModPatchTool") -> bool:
    # Try to terminate a conflicting GModPatchTool process (SIGTERM then SIGKILL/Windows-safe)
    try:
        os.kill(pid, signal.SIGTERM)
    except Exception:
        pass
    for _ in range(10):
        if not _pid_alive(pid):
            return True
        time.sleep(0.2)

    if os.name != 'nt':
        try:
            os.kill(pid, signal.SIGKILL)
        except Exception:
            pass
        for _ in range(10):
            if not _pid_alive(pid):
                return True
            time.sleep(0.2)

    return not _pid_alive(pid)


def _preclear_stale_instance(tool_path: str) -> None:
    # Remove stale pid files and stop any leftover patcher processes before running a new one
    if not tool_path:
        return
    tool_dir = os.path.dirname(tool_path) or "."
    for name in ("gmodpatchtool.pid", "GModPatchTool.pid"):
        pid_path = os.path.join(tool_dir, name)
        if os.path.isfile(pid_path):
            try:
                with open(pid_path, "r", encoding="utf-8") as f:
                    txt = f.read().strip()
                nums = re.findall(r"\d+", txt)
                pid = int(nums[0]) if nums else None
            except Exception:
                pid = None

            if pid:
                if _pid_alive(pid):
                    log_message(f"🔒 [INFO] Another GModPatchTool instance appears active (pid {pid}); attempting to stop it...")
                    if _try_kill_pid(pid):
                        log_message("✅ [INFO] Stale GModPatchTool instance stopped.")
                    else:
                        log_message("⚠️ [WARNING] Could not stop existing GModPatchTool cleanly.")
                else:
                    log_message("🧹 [INFO] Removing stale GModPatchTool pid file.")
            try:
                os.remove(pid_path)
            except Exception:
                pass


def run_gmod_patch_tool() -> bool:
    # Execute GModPatchTool and interpret its output according to our policy
    if not ensure_gmod_patch_tool_ready():
        return False

    log_message("🛠 [INFO] Running GModPatchTool...")
    check_for_new_patch_tool()

    if not GMOD_PATCH_TOOL_PATH or not os.path.exists(GMOD_PATCH_TOOL_PATH):
        log_message("⚠️ [ERROR] GModPatchTool not found on disk after update check.")
        return False
    if not os.access(GMOD_PATCH_TOOL_PATH, os.X_OK) and os.name != 'nt':
        log_message("⚠️ [ERROR] GModPatchTool is not executable. Attempting to set executable permission.")
        try:
            os.chmod(GMOD_PATCH_TOOL_PATH, 0o755)
        except Exception as e:
            log_message(f"⚠️ [ERROR] Failed to set executable permission: {e}")
            return False

    _preclear_stale_instance(GMOD_PATCH_TOOL_PATH)

    def _run_windows(allow_retry_on_already_running: bool) -> bool:
        # Windows: run via subprocess, stream output, and parse for success/locked-instance
        spawn_cmd = GMOD_PATCH_TOOL_PATH
        try:
            proc = subprocess.Popen(
                [spawn_cmd],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
        except Exception as e:
            log_message(f"⚠️ [ERROR] Failed to spawn GModPatchTool on Windows: {e}")
            return False

        output = ""
        start_time = time.time()

        while True:
            if proc.stdout is None:
                break

            line = proc.stdout.readline()
            if not line:
                # If process ended, break; else just loop until timeout
                if proc.poll() is not None:
                    break
            else:
                # Echo GModPatchTool’s output into this console
                print(line, end="")
                output += line

                # Respond to prompts if present
                if "Launch Garry's Mod" in line:
                    try:
                        proc.stdin.write("n\n")
                        proc.stdin.flush()
                    except Exception:
                        pass
                if "Press Enter to exit" in line:
                    try:
                        proc.stdin.write("\n")
                        proc.stdin.flush()
                    except Exception:
                        pass

            # Enforce a hard timeout
            if time.time() - start_time > 300:
                log_message("⚠️ [ERROR] GModPatchTool timed out in subprocess mode (Windows).")
                try:
                    proc.kill()
                except Exception:
                    pass
                break

        try:
            proc.wait(timeout=5)
        except Exception:
            pass

        # Look for "already running" message
        already_match = re.search(
            r"Another instance of GModPatchTool is already running \((\d+)\)\.",
            output,
        )
        success_match = re.search(
            r"GModPatchTool applied successfully!|Patch applied successfully",
            output,
        )

        if already_match:
            pid_text = already_match.group(1)
            try:
                stale_pid = int(pid_text)
            except Exception:
                stale_pid = None

            if stale_pid:
                if _try_kill_pid(stale_pid):
                    log_message(f"✅ [INFO] Cleared running GModPatchTool instance (pid {stale_pid}).")
                else:
                    log_message(f"⚠️ [WARNING] Could not stop running instance (pid {stale_pid}).")

            if allow_retry_on_already_running:
                log_message("🔁 [INFO] Retrying GModPatchTool after clearing running instance...")
                return _run_windows(False)
            else:
                return False

        if success_match:
            log_message("✅ [INFO] GModPatchTool applied successfully (subprocess, Windows).")
            return True

        log_message("⚠️ [INFO] Patch tool exited without success on Windows; will follow policy thresholds.")
        return False

    def _run_posix(allow_retry_on_already_running: bool) -> bool:
        # POSIX: original pexpect-based runner
        spawn_cmd = GMOD_PATCH_TOOL_PATH
        spawn_args: list[str] = []

        debug_log(
            f"Spawning GModPatchTool: cmd={spawn_cmd}, args={spawn_args}, "
            f"allow_retry={allow_retry_on_already_running}"
        )
        try:
            child = pexpect.spawn(spawn_cmd, spawn_args, timeout=300)
        except Exception as e:
            log_message(f"⚠️ [ERROR] Failed to spawn GModPatchTool: {e}")
            return False

        # Mirror child output into this console
        child.logfile = sys.stdout.buffer

        already_running_pat = r"Another instance of GModPatchTool is already running \((\d+)\)\."
        success_pats = [r"GModPatchTool applied successfully!", r"Patch applied successfully"]

        try:
            idx = child.expect(
                [already_running_pat] + success_pats + [r"Press Enter to exit\.\.\."],
                timeout=300,
            )

            if idx == 0:
                pid_text = child.match.group(1)
                if isinstance(pid_text, bytes):
                    pid_text = pid_text.decode(errors="ignore")
                try:
                    stale_pid = int(pid_text)
                except Exception:
                    stale_pid = None

                try:
                    child.sendline("")
                except Exception:
                    pass
                try:
                    child.close(force=True)
                except Exception:
                    pass

                if stale_pid:
                    if _try_kill_pid(stale_pid):
                        log_message(f"✅ [INFO] Cleared running GModPatchTool instance (pid {stale_pid}).")
                    else:
                        log_message(f"⚠️ [WARNING] Could not stop running instance (pid {stale_pid}).")

                if allow_retry_on_already_running:
                    log_message("🔁 [INFO] Retrying GModPatchTool after clearing running instance...")
                    return _run_posix(False)
                else:
                    return False

            elif idx in (1, 2):
                try:
                    child.sendline("")
                except Exception:
                    pass

                try:
                    child.expect([r"Launch Garry's Mod", pexpect.EOF, pexpect.TIMEOUT], timeout=5)
                    if child.after not in (pexpect.EOF, pexpect.TIMEOUT):
                        try:
                            child.sendline("n")
                        except Exception:
                            pass
                except Exception:
                    pass

                try:
                    child.close(force=True)
                except Exception:
                    pass
                log_message("✅ [INFO] GModPatchTool applied successfully (pexpect).")
                return True

            else:
                try:
                    child.sendline("")
                except Exception:
                    pass
                try:
                    child.close(force=True)
                except Exception:
                    pass
                log_message("⚠️ [INFO] Patch tool exited without success; will follow policy thresholds.")
                return False

        except pexpect.TIMEOUT:
            log_message("⚠️ [ERROR] GModPatchTool timed out in pexpect mode.")
            try:
                child.close(force=True)
            except Exception:
                pass
            return False

        except pexpect.EOF:
            try:
                child.close(force=True)
            except Exception:
                pass
            log_message("⚠️ [ERROR] Unexpected EOF before success pattern.")
            return False

        except Exception as e:
            try:
                child.close(force=True)
            except Exception:
                pass
            log_message(f"⚠️ [ERROR] Exception in pexpect patch run: {e}")
            return False

    if os.name == 'nt':
        return _run_windows(True)
    else:
        return _run_posix(True)


def enter_catastrophic_mode(reason: str) -> None:
    """
    Enter catastrophic backoff mode:
    - Stop all patch/validate/relaunch activity.
    - Wait for CATASTROPHIC_BACKOFF_SECONDS before resuming normal behavior.
    """
    global catastrophic_mode, catastrophic_since
    global failure_ticks, patch_triggered_after_failures, post_patch_failure_attempts
    global validated_and_patched_recently, had_success_since_validate

    if catastrophic_mode:
        return

    catastrophic_mode = True    # we intentionally DO NOT clear patch_required_before_launch here
    catastrophic_since = time.time()

    log_message(f"❌ [INFO] {reason}")
    log_message(
        f"⏱️ [INFO] Entering catastrophic backoff mode for "
        f"{CATASTROPHIC_BACKOFF_SECONDS // 60} minutes. "
        "Automatic patch/validate/relaunch will pause until the backoff window ends."
    )


def record_failure(reason: str, server_online: bool) -> None:
    """
    Handle a single connection failure tick while the server is online.

    This increments failure_ticks, logs the reason, and applies the same
    patch/validate escalation policy used across the script.

    IMPORTANT:
    - Validation is only triggered once per failure window after patching.
    - No infinite validate-and-retry loops.
    - If failures explode, enter catastrophic backoff mode and pause
      remediation for an hour.
    """
    global failure_ticks, patch_triggered_after_failures, post_patch_failure_attempts
    global validated_and_patched_recently, had_success_since_validate
    global catastrophic_mode

    if catastrophic_mode:
        log_message("⚠️ [INFO] In catastrophic backoff mode; ignoring additional failures for now.")
        return

    failure_ticks += 1
    log_message(
        f"⚠️ [INFO] {reason} (failure #{failure_ticks} while server is online)."
    )

    # If we've reached the catastrophic cap, stop here and enter backoff mode.
    if failure_ticks >= MAX_FAILURES_PER_WINDOW:
        enter_catastrophic_mode(
            "Maximum failures reached in this recovery window without a stable connection."
        )
        return

    if failure_ticks == 1:
        log_message(
            "⚠️ [INFO] First failed connection-related check while server is online. "
            "Will keep monitoring before taking action."
        )
    elif failure_ticks == PATCH_FAILURE_THRESHOLD:
        log_message(
            f"⚠️ [INFO] Failure count has reached {PATCH_FAILURE_THRESHOLD}. "
            "Triggering patch and considering a relaunch if needed."
        )
    elif failure_ticks % PATCH_FAILURE_THRESHOLD == 0:
        log_message(
            f"⚠️ [INFO] Ongoing issues: {failure_ticks} failed checks in a row while server is online."
        )

    # After a patch has already been applied
    if patch_triggered_after_failures:
        post_patch_failure_attempts += 1
        log_message(
            f"⚠️ [INFO] Still failing after patch; post-patch failure count: "
            f"{post_patch_failure_attempts}."
        )

        # Only trigger validation if we haven't already validated in this window
        if (not validated_and_patched_recently
                and post_patch_failure_attempts >= POST_PATCH_VALIDATION_THRESHOLD):
            log_message(
                "⚠️ [INFO] Post-patch failures exceeded threshold; performing validate+patch cycle."
            )
            validate_and_restart_gmod()
            # After validation we consider this a new window: reset counters.
            failure_ticks = 0
            post_patch_failure_attempts = 0
    else:
        # First-time patch escalation for this failure window
        if failure_ticks >= PATCH_FAILURE_THRESHOLD:
            if run_gmod_patch_tool():
                patch_triggered_after_failures = True
                post_patch_failure_attempts = 0
                log_message(
                    "✅ [INFO] Patch applied after repeated failures; "
                    "watching for a successful reconnect."
                )
            else:
                log_message(
                    "⚠️ [ERROR] Patch tool failed after repeated failures; "
                    "will continue monitoring and may escalate to validation."
                )

    # If we've hit the failure threshold with server online, relaunch
    if server_online and failure_ticks >= PATCH_FAILURE_THRESHOLD:
        if patch_triggered_after_failures:
            log_message(
                "🚀 [INFO] Repeated failures while the server was online; "
                "relaunching GMod after applying patch..."
            )
        else:
            log_message(
                "🚀 [INFO] Repeated failures while the server is online; "
                "relaunching GMod..."
            )
        launch_gmod()


def launch_gmod() -> None:
    # Launch GMod via Steam and connect to the current server IP, replacing any existing instance
    global patch_required_before_launch, last_launch_time
    global gmod_seen_since_launch, healthy_since_launch

    if not server_ip:
        log_message("⚠️ [ERROR] No valid server IP. Cannot launch GMod.")
        return

    if is_gmod_running():
        log_message("🧹 [INFO] Existing GMod instance detected; attempting to close it before relaunch.")
        if os.name == 'nt':
            try:
                subprocess.run(
                    ["taskkill", "/F", "/IM", "gmod.exe"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            except Exception as e:
                debug_log(f"Error during taskkill in launch_gmod: {e}")
        else:
            try:
                subprocess.run(
                    ["pkill", "-9", "gmod"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            except Exception as e:
                debug_log(f"Error during pkill in launch_gmod: {e}")
        time.sleep(2)

    if patch_required_before_launch:
        log_message("🛠 [INFO] Applying required patch before launching GMod...")
        if not run_gmod_patch_tool():
            log_message("⚠️ [ERROR] Patch tool failed to run before reconnect attempt. Aborting launch.")
            return
        patch_required_before_launch = False

    log_message(f"🚀 [INFO] Launching GMod & connecting to {server_ip}:27015...")
    steam_uri = GMOD_STEAM_URI.format(server_ip=server_ip)
    if os.name == 'nt':
        subprocess.run(
            ["cmd", "/c", "start", "", steam_uri],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    else:
        subprocess.run(
            ["xdg-open", steam_uri],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    last_launch_time = time.time()
    gmod_seen_since_launch = False
    healthy_since_launch = False
    time.sleep(30)


def validate_and_restart_gmod() -> None:
    # Full remediation: kill GMod, trigger Steam validation, then re-run GModPatchTool
    global patch_required_before_launch, validated_and_patched_recently, had_success_since_validate

    log_message("🔄 [INFO] Restarting GMod & verifying game files...")
    patch_required_before_launch = True

    if os.name == 'nt':
        try:
            subprocess.run(
                ["taskkill", "/F", "/IM", "gmod.exe"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception as e:
            debug_log(f"Error during taskkill: {e}")
        subprocess.run(
            ["cmd", "/c", "start", "", GMOD_VALIDATE_URI],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    else:
        subprocess.run(
            ["pkill", "-9", "gmod"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            ["xdg-open", GMOD_VALIDATE_URI],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    time.sleep(45)

    if not run_gmod_patch_tool():
        log_message("⚠️ [ERROR] GModPatchTool did not apply successfully after validation.")
    else:
        patch_required_before_launch = False
        validated_and_patched_recently = True
        had_success_since_validate = False


def main() -> None:
    # Main control loop for Swamp reconnect behavior and escalation policy
    global server_ip, failure_ticks, patch_triggered_after_failures, post_patch_failure_attempts
    global validated_and_patched_recently, had_success_since_validate, loop_count, last_launch_time
    global gmod_seen_since_launch, healthy_since_launch, catastrophic_mode, catastrophic_since

    auto_configure_gmod_patch_tool_path()
    check_dependencies()

    log_message("==============================================")
    log_message(f"🚀 [INFO] Swamp reconnect script started (version {__version__}).")
    log_message(
        f"📋 [INFO] Policy: patch after {PATCH_FAILURE_THRESHOLD} failures, "
        f"validate+patch after {POST_PATCH_VALIDATION_THRESHOLD} post-patch failures, "
        f"catastrophic backoff after {MAX_FAILURES_PER_WINDOW} total failures."
    )
    log_message("📡 [INFO] Waiting for Swamp server IP and monitoring GMod status.")
    log_message("👉 [INFO] Press Ctrl+C at any time to stop the script.")
    log_message("==============================================")

    while True:
        try:
            loop_count += 1

            # If we're in catastrophic backoff, enforce the cooldown first
            if catastrophic_mode:
                now = time.time()
                elapsed = now - catastrophic_since if catastrophic_since else 0
                if elapsed < CATASTROPHIC_BACKOFF_SECONDS:
                    # Still cooling down; do nothing except sleep.
                    time.sleep(CHECK_INTERVAL)
                    continue
                else:
                    # Backoff window elapsed; reset state and resume normal behavior.
                    catastrophic_mode = False
                    catastrophic_since = None
                    failure_ticks = 0
                    patch_triggered_after_failures = False
                    post_patch_failure_attempts = 0
                    validated_and_patched_recently = False
                    had_success_since_validate = False
                    last_launch_time = None
                    gmod_seen_since_launch = False
                    healthy_since_launch = False
                    log_message(
                        "⏱️ [INFO] Catastrophic backoff window elapsed; "
                        "resuming normal recovery behavior."
                    )

            gmod_running = is_gmod_running()

            if server_ip is None:
                fetch_server_ip()

            if server_ip is None:
                log_message("⚠️ [WARNING] No server IP detected yet; will retry shortly...")
                time.sleep(CHECK_INTERVAL)
                continue

            # Only sniff UDP when GMod is actually running
            if gmod_running:
                connected = check_udp_traffic(server_ip)
            else:
                connected = False

            if connected:
                server_online = True
            else:
                server_online = is_server_online(server_ip)

            healthy = gmod_running and connected

            # Track per-launch state:
            if gmod_running:
                gmod_seen_since_launch = True

            if healthy:
                healthy_since_launch = True

            debug_log(
                f"Loop={loop_count}, gmod_running={gmod_running}, server_ip={server_ip}, "
                f"server_online={server_online}, connected={connected}, "
                f"failure_ticks={failure_ticks}, "
                f"patch_triggered_after_failures={patch_triggered_after_failures}, "
                f"post_patch_failure_attempts={post_patch_failure_attempts}, "
                f"validated_and_patched_recently={validated_and_patched_recently}, "
                f"had_success_since_validate={had_success_since_validate}, "
                f"last_launch_time={last_launch_time}, "
                f"gmod_seen_since_launch={gmod_seen_since_launch}, "
                f"healthy_since_launch={healthy_since_launch}, "
                f"catastrophic_mode={catastrophic_mode}"
            )

            if healthy:
                # GMod running AND we see UDP packets to the server
                log_state_change("gmod", True, "🟢 [INFO] GMod is running.")
                log_state_change(
                    "connection",
                    True,
                    "🟢 [INFO] UDP traffic to Swamp server detected. Connection looks healthy."
                )
                failure_ticks = 0
                patch_triggered_after_failures = False
                post_patch_failure_attempts = 0

                if validated_and_patched_recently:
                    if not had_success_since_validate:
                        had_success_since_validate = True
                        log_message("✅ [INFO] Successful connection after validation+patch.")
                    # Close this validation window so future issues can validate again.
                    validated_and_patched_recently = False
                    post_patch_failure_attempts = 0

            else:
                # Not healthy: either server offline, or client down, or running-but-disconnected
                if not server_online:
                    # Server appears offline; don't burn failure ticks or patch
                    if gmod_running:
                        log_message(
                            "🌐 [INFO] Swamp server appears OFFLINE or unreachable. "
                            "Not patching or validating while server is down."
                        )
                    else:
                        log_message(
                            "🌐 [INFO] Swamp server appears OFFLINE or unreachable. "
                            "Not launching GMod yet; waiting for server to return."
                        )
                    log_state_change(
                        "connection",
                        False,
                        "🔴 [INFO] No UDP traffic and server appears offline."
                    )
                    failure_ticks = 0
                    patch_triggered_after_failures = False
                    post_patch_failure_attempts = 0
                    time.sleep(CHECK_INTERVAL)
                    continue

                # Server is online from here down
                if not gmod_running:
                    # GMod is not running while server is online.
                    log_state_change(
                        "gmod",
                        False,
                        "🟡 [INFO] GMod is not running while the Swamp server is online."
                    )
                    log_state_change(
                        "connection",
                        False,
                        "🔴 [INFO] No UDP traffic to Swamp server while it is online."
                    )

                    now = time.time()

                    # Case 1: We've never launched GMod from this script yet
                    if last_launch_time is None:
                        log_message(
                            "🚀 [INFO] Swamp server is online but GMod is not running; launching GMod..."
                        )
                        launch_gmod()
                        time.sleep(CHECK_INTERVAL)
                        continue

                    since_launch = now - last_launch_time

                    # Case 2: We launched recently and are still within the grace window
                    if since_launch < LAUNCH_GRACE_SECONDS:
                        remaining = max(0, int(LAUNCH_GRACE_SECONDS - since_launch))
                        log_message(
                            f"⏳ [INFO] GMod was launched recently; giving it more time to start before "
                            f"treating this as a failure (~{remaining}s grace left)."
                        )
                        time.sleep(CHECK_INTERVAL)
                        continue

                    # Case 3: Grace window expired and GMod is still not running.
                    # Now decide if this counts as a failure tick.

                    if healthy_since_launch:
                        # GMod connected successfully at least once after the last launch,
                        # so this looks like a normal shutdown / user close.
                        # Relaunch without treating it as a connection failure.
                        log_message(
                            "🔁 [INFO] GMod previously reached a healthy connection this launch; "
                            "treating shutdown as a normal close and relaunching."
                        )
                        launch_gmod()
                        time.sleep(CHECK_INTERVAL)
                        continue

                    if gmod_seen_since_launch:
                        # GMod actually started but never connected and then died → failure tick.
                        record_failure(
                            "GMod started but closed before establishing a healthy connection",
                            server_online=True,
                        )
                    else:
                        # We never even saw the process; treat this as a failure too,
                        # since Steam/launching appears broken.
                        record_failure(
                            "GMod failed to start within the grace window after launch",
                            server_online=True,
                        )

                    time.sleep(CHECK_INTERVAL)
                    continue

                # From here on: gmod_running == True, server_online == True, but no UDP = connection problem
                log_state_change(
                    "gmod",
                    True,
                    "🟡 [INFO] GMod is running but appears disconnected from the server."
                )
                log_state_change(
                    "connection",
                    False,
                    "🔴 [INFO] No UDP traffic to Swamp server while it is online."
                )

                # If we just launched GMod from this script, allow a grace period before counting failures
                if last_launch_time is not None and (time.time() - last_launch_time) < LAUNCH_GRACE_SECONDS:
                    remaining = max(0, int(LAUNCH_GRACE_SECONDS - (time.time() - last_launch_time)))
                    log_message(
                        f"⏳ [INFO] Recently relaunched GMod; allowing time for the client to start and connect "
                        f"(~{remaining}s grace left)..."
                    )
                    time.sleep(CHECK_INTERVAL)
                    continue

                # Now we treat this as a *real* failure tick (GMod running but disconnected)
                record_failure(
                    "GMod is running but cannot establish/maintain UDP traffic to the Swamp server",
                    server_online=True,
                )

                time.sleep(CHECK_INTERVAL)
                continue

            time.sleep(CHECK_INTERVAL)

        except KeyboardInterrupt:
            log_message("👋 [INFO] Swamp reconnect script stopped by user (Ctrl+C).")
            break
        except Exception as e:
            log_message(f"⚠️ [ERROR] Unexpected exception in main loop: {e}")
            time.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    main()

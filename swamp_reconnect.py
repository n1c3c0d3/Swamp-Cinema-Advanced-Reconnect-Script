#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Swamp Reconnect Script — fully commented (Version 4.1)

What this script does (high level):
- Keeps trying to get you connected to the Swamp Cinema server.
- "Healthy" means:
    - Garry's Mod (GMod) is running, AND
    - We see UDP traffic between your PC and the Swamp server IP.
- If GMod is not healthy, we treat that as a "failure tick".

Escalation policy:
- After PATCH_FAILURE_THRESHOLD failure ticks (default: 3):
    - Run GModPatchTool (NO validation yet).
    - Optionally relaunch GMod and reconnect to the server.
- After patching, if we still see POST_PATCH_VALIDATION_THRESHOLD failures (default: 2):
    - Validate game files via Steam and re-apply the patch.
- If after a successful post-validation connection you later fail again:
    - Immediately escalate to validate + patch again.

Patch-tool behavior:
- Runs GModPatchTool *in the same console* via pexpect, so you see all its output.
- Handles "Another instance of GModPatchTool is already running (PID)" by:
    - Killing that PID cleanly, then retrying once.
- When needed, downloads the correct patch tool (Linux vs Windows) based on platform tags in release filenames.
- Extracts archives into a temporary directory and installs into a clean `GModPatchTool/` folder — no leftovers.
- Politely answers "no" if GModPatchTool offers to launch GMod itself, so this script stays in control.

Version 4 additions:
- Uses an A2S_INFO UDP query as a *fallback* to tell if the Swamp server is online
  when we don’t see any UDP traffic from tcpdump/dumpcap.
- Auto-relaunches GMod when:
    - The server is online, AND
    - We’ve had at least PATCH_FAILURE_THRESHOLD failed checks in a row,
  regardless of whether GMod is already running (we now kill any old instance first).

Version 4.1 quality-of-life improvements:
- Cleaner, clearer log messages for the user (less noisy, but more meaningful).
- Safer relaunch behavior: if GMod is already running, we terminate it before launching again.
- Small optimization: we only sniff UDP traffic when GMod is actually running.
- Extra comments explaining the purpose of the internal state variables.
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
import shlex
import signal  # For sending SIGTERM/SIGKILL to stale GModPatchTool processes

# Toggle to True if you want to see extra internal debugging prints
DEBUG = False


def debug_log(msg: str) -> None:
    """Optional debug logger (controlled by DEBUG flag)."""
    if DEBUG:
        print(f"DEBUG: {msg}")


# Where we scrape the live server IP from:
SWAMP_URL = "https://swamp.sv/"

# Networking/monitoring knobs
CHECK_DURATION = 5            # seconds to listen for network packets each check
MAX_RETRIES = 3               # how many quick attempts for packet checks (per phase)
CHECK_INTERVAL = 10           # main loop sleep between checks (seconds)
PATCH_FAILURE_THRESHOLD = 3   # after this many failure ticks, run patch (no validation)
POST_PATCH_VALIDATION_THRESHOLD = 2  # after patching, this many more fails => validate + patch
MIN_PACKET_THRESHOLD = 5      # tcpdump -c <count>; how many packets qualify a "connected" state

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

# Platform-specific bits:
if os.name == 'nt':
    # Steam URIs for Windows
    GMOD_STEAM_URI = "steam://connect/{server_ip}:27015"
    GMOD_VALIDATE_URI = "steam://validate/4000"
    PROCESS_NAMES = ["gmod.exe"]  # processes that indicate GMod is running
    REQUIRED_CMDS = ["dumpcap"]   # capture tool on Windows (Wireshark family)
else:
    # Steam URIs for Linux
    GMOD_STEAM_URI = "steam://connect/{server_ip}:27015"
    GMOD_VALIDATE_URI = "steam://validate/4000"
    PROCESS_NAMES = ["gmod", "hl2_linux", "hl2.sh", "garrysmod"]  # common names on Linux
    REQUIRED_CMDS = ["tcpdump", "pgrep", "xdg-open"]  # capture, process grep, open URIs

# Path to the patcher executable (set dynamically)
GMOD_PATCH_TOOL_PATH: str | None = None
# Base directory (used when saving patcher downloads)
SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))

# ----------------------------------------------------------------------
# State trackers for logging & policy decisions
# ----------------------------------------------------------------------
# last_gmod_state / last_connection_state:
#   - Track the LAST known boolean state so we only log changes once.
last_gmod_state: bool | None = None
last_connection_state: bool | None = None

# failure_ticks:
#   - The main "our side is broken" counter.
#   - Incremented when the server is online but we are not "healthy".
failure_ticks = 0

# server_ip:
#   - The current Swamp server IP scraped from SWAMP_URL.
server_ip: str | None = None

# patch_triggered_after_failures:
#   - True once we've already run GModPatchTool after hitting the failure threshold.
patch_triggered_after_failures = False

# post_patch_failure_attempts:
#   - How many times we've still been unhealthy AFTER a patch.
#   - When this hits POST_PATCH_VALIDATION_THRESHOLD -> validate+patch escalation.
post_patch_failure_attempts = 0

# patch_required_before_launch:
#   - Used when we want to enforce "validate+patch before launching GMod".
patch_required_before_launch = False

# validated_and_patched_recently:
#   - True after a validate+patch cycle.
# had_success_since_validate:
#   - Tracks whether we have seen a healthy connection after that validate+patch.
validated_and_patched_recently = False
had_success_since_validate = False

# Simple loop counter for optional diagnostics / future use
loop_count = 0


# ---------------- Logging helpers ----------------
def log_message(message: str) -> None:
    """Print a timestamped log line."""
    print(f"{time.strftime('%Y-%m-%d %I:%M:%S %p')} {message}")


def log_state_change(state_variable: str, new_state: bool, message: str) -> None:
    """
    Only log when a state actually changes (reduces noisy repeats).
    state_variable: "gmod" | "connection"
    """
    global last_gmod_state, last_connection_state
    if state_variable == "gmod":
        if new_state != last_gmod_state:
            log_message(message)
            last_gmod_state = new_state
    elif state_variable == "connection":
        if new_state != last_connection_state:
            log_message(message)
            last_connection_state = new_state


# ---------------- Misc helpers ----------------
def is_archive(path: str) -> bool:
    """True if `path` looks like an archive (zip/tar)."""
    lower = path.lower()
    return lower.endswith((".zip", ".tar", ".tar.gz", ".tgz"))


def find_executable_in_dir(dir_path: str) -> str | None:
    """
    Search a directory tree for a plausible GModPatchTool executable.
    Skips archives and pid files. Ensures executable bit on Linux.
    """
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
                    # Ensure executable on Linux
                    try:
                        os.chmod(candidate, 0o755)
                    except Exception:
                        pass
                    if not os.access(candidate, os.X_OK):
                        continue
                return candidate
    return None


def check_dependencies() -> None:
    """
    Verify presence of required system commands.
    We don't fail hard here; we warn to keep script flexible.
    """
    missing = []
    for cmd in REQUIRED_CMDS:
        if shutil.which(cmd) is None:
            missing.append(cmd)
            debug_log(f"Command not found: {cmd}")
    if missing:
        log_message("⚠️ [WARNING] The following required commands are missing: " + ", ".join(missing))
    else:
        log_message("✅ [INFO] All required system commands are available.")


def fetch_server_ip(force: bool = False) -> None:
    """
    Scrape the Swamp website for the current server IP.
    Cached for FETCH_INTERVAL_SECONDS; pass force=True to bypass cache.
    """
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
    """Best-effort check if GMod is running (Windows: tasklist; Linux: pgrep)."""
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
                result = subprocess.run(["pgrep", "-a", process],
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL,
                                        text=True)
                if result.stdout.strip():
                    return True
            return False
        except Exception as e:
            log_message(f"⚠️ [ERROR] Exception in is_gmod_running: {e}")
            return False


# ---------- Windows capture helpers (dumpcap) ----------
def get_windows_capture_interfaces() -> list[str]:
    """List dumpcap interfaces (Windows)."""
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
        return result.stdout.splitlines()
    except Exception as e:
        log_message(f"⚠️ [WARNING] Exception in get_windows_capture_interfaces: {e}")
        return []


def find_active_interface(ip: str) -> str:
    """
    Heuristic: try each interface briefly; pick the one that captures any packets
    to/from the target IP. Default to "1" if unsure.
    """
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
            "-w", temp_file
        ]
        try:
            subprocess.run(cmd,
                           stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE,
                           timeout=3)
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


# ---------- Connection check ----------
def check_udp_traffic(ip: str, retries: int = MAX_RETRIES) -> bool:
    """
    Decide "connected" by observing packets to/from the server IP.
    - Windows: dumpcap writes a file briefly; size > 0 counts as success
    - Linux: tcpdump with a minimal packet count; if we hit count and IP appears, success
    """
    if not ip:
        return False
    if os.name == 'nt':
        dumpcap_path = shutil.which("dumpcap")
        if not dumpcap_path:
            return False
        interface = find_active_interface(ip)
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
            try:
                subprocess.run(cmd,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE,
                               timeout=CHECK_DURATION + 2)
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
        for attempt in range(retries):
            cmd = [
                "timeout", str(CHECK_DURATION),
                "tcpdump", "-nn", "-q", "-c", str(MIN_PACKET_THRESHOLD),
                "host", ip
            ]
            try:
                result = subprocess.run(cmd,
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL,
                                        text=True)
                # If tcpdump exits 0 and prints lines including the IP, we count that as traffic
                if result.returncode == 0 and ip in result.stdout:
                    return True
            except Exception as e:
                debug_log(f"Error running tcpdump: {e}")
            time.sleep(2)
        return False


def is_server_online(ip: str, port: int = 27015, timeout: float = 2.0) -> bool:
    """
    Check if the Source engine server is reachable using an A2S_INFO query.

    This does NOT guarantee we're joined, but if we see any UDP response to the
    standard A2S_INFO packet, we treat the server as "online".
    """
    if not ip:
        return False

    try:
        # Classic A2S_INFO request: 0xFFFFFFFF + "TSource Engine Query\0"
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


# ---------------- GModPatchTool handling ----------------
def extract_gmod_patch_tool(zip_path: str, extract_to: str) -> str | None:
    """
    Extract an archive (zip/tar*) to a temp dir, find the patcher executable,
    and install the contents into a clean `GModPatchTool/` folder next to the archive.
    """
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
                # Clean rebuild target folder to avoid stale junk
                dest_folder = os.path.join(os.path.dirname(zip_path), "GModPatchTool")
                if os.path.exists(dest_folder):
                    shutil.rmtree(dest_folder)
                shutil.copytree(os.path.dirname(exe), dest_folder)

                GMOD_PATCH_TOOL_PATH = os.path.join(dest_folder, os.path.basename(exe))
                # Make executable on Linux
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
    """
    Choose the best release asset based on platform tags in the filename:
    - Linux: look for 'linux' in the name
    - Windows: look for 'windows' or .exe in the name
    If not found, fallback to generic archives but avoid obvious mismatches.
    """
    if not assets:
        return None

    # First pass: exact platform tags
    for a in assets:
        name = a.get("name", "").lower()
        is_linux = "linux" in name
        is_windows = ("windows" in name) or name.endswith(".exe")
        if os.name == 'nt' and is_windows:
            return a
        if os.name != 'nt' and is_linux:
            return a

    # Second pass: generic archives that still look OK
    for a in assets:
        name = a.get("name", "").lower()
        if "gmodpatchtool" in name and name.endswith((".zip", ".tar.gz", ".tgz")):
            if os.name == 'nt' and "linux" in name:
                continue
            if os.name != 'nt' and ("windows" in name or name.endswith(".exe")):
                continue
            return a

    # Third pass: last resort — any gmodpatchtool asset
    for a in assets:
        name = a.get("name", "").lower()
        if "gmodpatchtool" in name:
            return a

    return None


def auto_configure_gmod_patch_tool_path() -> str | None:
    """
    Try to locate an already-downloaded/installed patcher:
    - Prefer ~/Documents/…/GModPatchTool or script folder
    - If we see an archive, extract/normalize it into GModPatchTool/
    - If nothing is found, trigger a fresh download
    """
    global GMOD_PATCH_TOOL_PATH
    if GMOD_PATCH_TOOL_PATH and os.path.exists(GMOD_PATCH_TOOL_PATH) and os.access(GMOD_PATCH_TOOL_PATH, os.X_OK):
        return GMOD_PATCH_TOOL_PATH

    search_dirs = [SCRIPT_DIR]
    home = os.path.expanduser("~")
    for folder in ["Documents", "Desktop", "Downloads"]:
        dir_path = os.path.join(home, folder)
        if os.path.isdir(dir_path) and dir_path not in search_dirs:
            search_dirs.append(dir_path)

    # Preferred: a clean, ready folder
    for d in search_dirs:
        canonical = os.path.join(d, "GModPatchTool")
        if os.path.isdir(canonical):
            exe = find_executable_in_dir(canonical)
            if exe:
                GMOD_PATCH_TOOL_PATH = exe
                log_message(f"Found GModPatchTool at: {GMOD_PATCH_TOOL_PATH}")
                return GMOD_PATCH_TOOL_PATH

    # Otherwise: scan for archives or loose binaries and normalize them
    for d in search_dirs:
        for root, _, files in os.walk(d):
            for file in files:
                path = os.path.join(root, file)
                lname = file.lower()
                if "gmodpatchtool" not in lname:
                    continue
                if is_archive(path):
                    if extract_gmod_patch_tool(path, extract_to=os.path.dirname(path)):
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
                            dest = path  # fallback if copy fails
                        GMOD_PATCH_TOOL_PATH = dest
                        log_message(f"Found GModPatchTool at: {GMOD_PATCH_TOOL_PATH}")
                        return GMOD_PATCH_TOOL_PATH

    # Nothing found — download latest
    log_message("GModPatchTool not found in common directories. Downloading latest patch...")
    download_latest_gmod_patch_tool()
    return GMOD_PATCH_TOOL_PATH


def ensure_gmod_patch_tool_ready() -> bool:
    """Ensure we have a patcher path on disk; try auto-configure if missing."""
    if GMOD_PATCH_TOOL_PATH and os.path.exists(GMOD_PATCH_TOOL_PATH):
        return True
    auto_configure_gmod_patch_tool_path()
    if GMOD_PATCH_TOOL_PATH and os.path.exists(GMOD_PATCH_TOOL_PATH):
        return True
    log_message("⚠️ [ERROR] Unable to locate GModPatchTool. Download may have failed.")
    return False


def download_latest_gmod_patch_tool() -> None:
    """
    Hit GitHub releases for GModPatchTool and fetch the correct platform asset.
    Normalize any archive into a clean `GModPatchTool/` folder and set the path.
    """
    global GMOD_PATCH_TOOL_PATH
    download_dir = os.path.dirname(os.path.realpath(__file__))
    try:
        response = requests.get("https://api.github.com/repos/solsticegamestudios/GModPatchTool/releases/latest", timeout=10)
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
            # Extract to temp and install into GModPatchTool/
            extract_gmod_patch_tool(out_path, extract_to=os.path.dirname(out_path))
        else:
            # Single binary: normalize into GModPatchTool/
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
    """
    Compare remote release date to local patch mtime.
    If remote is newer, download the correct platform asset and install it.
    """
    global GMOD_PATCH_TOOL_PATH
    try:
        response = requests.get("https://api.github.com/repos/solsticegamestudios/GModPatchTool/releases/latest", timeout=10)
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
                    extract_gmod_patch_tool(out_path, extract_to=os.path.dirname(out_path))
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


# -------- Stale-instance handling for GModPatchTool (pid/lock) --------
def _pid_alive(pid: int) -> bool:
    """True if a process with PID exists (kill(0) trick)."""
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except OSError:
        # Permission denied still means it exists
        return True


def _try_kill_pid(pid: int, desc: str = "GModPatchTool") -> bool:
    """
    Try to stop a conflicting patcher instance:
    - First SIGTERM with a short wait
    - Then SIGKILL with another short wait
    """
    try:
        os.kill(pid, signal.SIGTERM)
    except Exception:
        pass
    for _ in range(10):
        if not _pid_alive(pid):
            return True
        time.sleep(0.2)

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
    """
    Before running the patcher, clean up any stale pid file and
    try to stop a still-running previous instance if detected.
    """
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
    """
    Run the patcher in the *same console* using pexpect.
    - Checks for an update first (platform aware).
    - Clears stale instance/lock.
    - Watches output for:
        - "Another instance ... running (PID)" -> kill PID and retry once.
        - Success lines -> auto-press Enter, then accept EOF/TIMEOUT as normal completion.
        - If we see "Press Enter to exit..." before success, we press Enter and treat as failure.
    Returns True on success, False otherwise.
    """
    if not ensure_gmod_patch_tool_ready():
        return False

    log_message("🛠 [INFO] Running GModPatchTool with pexpect...")
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

    # Clear pid/lock before spawning
    _preclear_stale_instance(GMOD_PATCH_TOOL_PATH)

    def _spawn_and_watch(allow_retry_on_already_running: bool) -> bool:
        """Internal child runner with one allowed retry for 'already running'."""
        if os.name == 'nt':
            # On Windows, spawn the .exe directly
            spawn_cmd = GMOD_PATCH_TOOL_PATH
            spawn_args: list[str] = []
        else:
            # On Linux, stay close to terminal behavior via /bin/bash -c
            cmd = shlex.quote(GMOD_PATCH_TOOL_PATH)
            spawn_cmd = "/bin/bash"
            spawn_args = ["-c", cmd]

        debug_log(
            f"Spawning GModPatchTool: cmd={spawn_cmd}, args={spawn_args}, "
            f"allow_retry={allow_retry_on_already_running}"
        )
        try:
            child = pexpect.spawn(spawn_cmd, spawn_args, timeout=300)
        except Exception as e:
            log_message(f"⚠️ [ERROR] Failed to spawn GModPatchTool: {e}")
            return False

        # Stream full patch output straight to this console (your existing behavior)
        child.logfile = sys.stdout.buffer

        # Patterns to detect
        already_running_pat = r"Another instance of GModPatchTool is already running \((\d+)\)\."
        success_pats = [r"GModPatchTool applied successfully!", r"Patch applied successfully"]

        try:
            # Watch for: already-running, success lines, or "Press Enter to exit..." (before success)
            idx = child.expect(
                [already_running_pat] + success_pats + [r"Press Enter to exit\.\.\."],
                timeout=300,
            )

            if idx == 0:
                # "Another instance is already running (PID)" — kill and retry once
                pid_text = child.match.group(1)
                if isinstance(pid_text, bytes):
                    pid_text = pid_text.decode(errors="ignore")
                try:
                    stale_pid = int(pid_text)
                except Exception:
                    stale_pid = None

                # Close this run
                try:
                    child.sendline("")  # press Enter to exit
                except Exception:
                    pass
                try:
                    child.close(force=True)
                except Exception:
                    pass

                # Attempt to stop the other instance
                if stale_pid:
                    if _try_kill_pid(stale_pid):
                        log_message(f"✅ [INFO] Cleared running GModPatchTool instance (pid {stale_pid}).")
                    else:
                        log_message(f"⚠️ [WARNING] Could not stop running instance (pid {stale_pid}).")

                if allow_retry_on_already_running:
                    log_message("🔁 [INFO] Retrying GModPatchTool after clearing running instance...")
                    return _spawn_and_watch(False)
                else:
                    return False

            elif idx in (1, 2):
                # We matched a success line
                try:
                    child.sendline("")  # press Enter if prompted to exit
                except Exception:
                    pass

                # Some versions then prompt "Launch Garry's Mod?" — decline politely
                try:
                    child.expect([r"Launch Garry's Mod", pexpect.EOF, pexpect.TIMEOUT], timeout=5)
                    if child.after not in (pexpect.EOF, pexpect.TIMEOUT):
                        try:
                            child.sendline("n")
                        except Exception:
                            pass
                except Exception:
                    pass

                # Clean close; treat EOF/TIMEOUT as okay now
                try:
                    child.close(force=True)
                except Exception:
                    pass
                log_message("✅ [INFO] GModPatchTool applied successfully (pexpect).")
                return True

            else:
                # We saw "Press Enter to exit..." WITHOUT success first. Treat as failed attempt.
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
            # No decisive output in time; treat as failure
            log_message("⚠️ [ERROR] GModPatchTool timed out in pexpect mode.")
            try:
                child.close(force=True)
            except Exception:
                pass
            return False

        except pexpect.EOF:
            # EOF before success — treat as failure (success branch already accepts EOF after success)
            try:
                child.close(force=True)
            except Exception:
                pass
            log_message("⚠️ [ERROR] Unexpected EOF before success pattern.")
            return False

        except Exception as e:
            # Any other exception
            try:
                child.close(force=True)
            except Exception:
                pass
            log_message(f"⚠️ [ERROR] Exception in pexpect patch run: {e}")
            return False

    # Allow exactly one retry on the "already running" condition
    return _spawn_and_watch(True)


# ---------------- Game launch/validation ----------------
def launch_gmod() -> None:
    """
    Launch GMod and connect to the current server IP via Steam URI.

    Safety improvements:
    - If GMod is already running, we try to terminate it first to avoid "double instances".
    - If a validate+patch was requested before launch (policy), run the patch first.
    """
    global patch_required_before_launch

    if not server_ip:
        log_message("⚠️ [ERROR] No valid server IP. Cannot launch GMod.")
        return

    # Safety: ensure there is not a stale GMod instance before launching again.
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
            ["cmd", "/c", "start", steam_uri],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    else:
        subprocess.run(
            ["xdg-open", steam_uri],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    # Give Steam/GMod time to come up a bit
    time.sleep(30)


def validate_and_restart_gmod() -> None:
    """
    Full remediation:
    - Kill GMod (if running)
    - Trigger Steam validation for app 4000
    - Run GModPatchTool
    """
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
            ["cmd", "/c", "start", GMOD_VALIDATE_URI],
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

    # Give validation some head start time (Steam continues in background)
    time.sleep(45)

    # Apply patch after validation
    if not run_gmod_patch_tool():
        log_message("⚠️ [ERROR] GModPatchTool did not apply successfully after validation.")
    else:
        patch_required_before_launch = False
        validated_and_patched_recently = True
        had_success_since_validate = False


# ---------------- Main control loop (Version 4.1 policy) ----------------
def main() -> None:
    """
    Drive the policy:

    - Healthy state:
        * GMod is running, AND
        * UDP traffic to server IP is observed.

    - Failure state:
        * Server appears online, but we are not healthy.

    Behavior summary:
    - Track "failure ticks" when we're unhealthy while the server is online.
    - After PATCH_FAILURE_THRESHOLD failures:
        * Apply GModPatchTool.
        * Attempt to relaunch GMod and reconnect.
    - After a patch, if we still fail POST_PATCH_VALIDATION_THRESHOLD times:
        * Validate game files + re-apply patch.
    - After validate+patch, if we NEVER see a success before failing again:
        * Immediately escalate to validate+patch next time.
    """
    global server_ip, failure_ticks, patch_triggered_after_failures, post_patch_failure_attempts
    global validated_and_patched_recently, had_success_since_validate, loop_count

    auto_configure_gmod_patch_tool_path()
    check_dependencies()

    log_message("==============================================")
    log_message(f"🚀 [INFO] Swamp reconnect script started (version {__version__}).")
    log_message(
        f"📋 [INFO] Policy: patch after {PATCH_FAILURE_THRESHOLD} failures, "
        f"validate+patch after {POST_PATCH_VALIDATION_THRESHOLD} post-patch failures."
    )
    log_message("📡 [INFO] Waiting for Swamp server IP and monitoring GMod status.")
    log_message("👉 [INFO] Press Ctrl+C at any time to stop the script.")
    log_message("==============================================")

    while True:
        try:
            loop_count += 1
            gmod_running = is_gmod_running()

            if server_ip is None:
                fetch_server_ip()

            if server_ip is None:
                log_message("⚠️ [WARNING] No server IP detected yet; will retry shortly...")
                time.sleep(CHECK_INTERVAL)
                continue

            # Primary connection check:
            # Optimization: only sniff UDP traffic when GMod is actually running.
            if gmod_running:
                connected = check_udp_traffic(server_ip)
            else:
                connected = False

            # Secondary check: is the server itself online? (A2S_INFO)
            # We only bother checking this when we don't see traffic.
            if connected:
                server_online = True
            else:
                server_online = is_server_online(server_ip)

            healthy = gmod_running and connected

            debug_log(
                f"Loop={loop_count}, gmod_running={gmod_running}, server_ip={server_ip}, "
                f"server_online={server_online}, connected={connected}, "
                f"failure_ticks={failure_ticks}, "
                f"patch_triggered_after_failures={patch_triggered_after_failures}, "
                f"post_patch_failure_attempts={post_patch_failure_attempts}, "
                f"validated_and_patched_recently={validated_and_patched_recently}, "
                f"had_success_since_validate={had_success_since_validate}"
            )

            if healthy:
                # Reset failure counters on success
                log_state_change("gmod", True, "🟢 [INFO] GMod is running.")
                log_state_change("connection", True, "🟢 [INFO] UDP traffic to Swamp server detected. Connection looks healthy.")
                failure_ticks = 0
                patch_triggered_after_failures = False
                post_patch_failure_attempts = 0

                if validated_and_patched_recently and not had_success_since_validate:
                    had_success_since_validate = True
                    log_message("✅ [INFO] Successful connection after validation+patch.")
            else:
                # If the server itself looks offline, don't escalate locally.
                if not server_online:
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
                    log_state_change("connection", False, "🔴 [INFO] No UDP traffic and server appears offline.")
                    failure_ticks = 0
                    patch_triggered_after_failures = False
                    post_patch_failure_attempts = 0
                    time.sleep(CHECK_INTERVAL)
                    continue

                # Server is online, so this is our side misbehaving
                if gmod_running and not connected:
                    log_state_change(
                        "gmod",
                        True,
                        "🟡 [INFO] GMod is running but appears disconnected from the server.",
                    )
                elif not gmod_running:
                    log_state_change("gmod", False, "🟡 [INFO] GMod is not running while the Swamp server is online.")

                log_state_change(
                    "connection",
                    False,
                    "🔴 [INFO] No UDP traffic to Swamp server while it is online.",
                )

                # Update failure counter and log in a less noisy but more meaningful way
                failure_ticks += 1
                if failure_ticks == 1:
                    log_message(
                        "⚠️ [INFO] First failed connection check while server is online. "
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

                if patch_triggered_after_failures:
                    # We already ran a patch; now track post-patch failures.
                    post_patch_failure_attempts += 1
                    log_message(
                        f"⚠️ [INFO] Still failing after patch; post-patch failure count: "
                        f"{post_patch_failure_attempts}."
                    )

                    # If we *just* validated+patched and never saw success, escalate faster.
                    if validated_and_patched_recently and not had_success_since_validate:
                        log_message(
                            "⚠️ [INFO] Failure after recent validation+patch; "
                            "escalating immediately to validate_and_restart_gmod()."
                        )
                        validate_and_restart_gmod()
                        failure_ticks = 0
                        post_patch_failure_attempts = 0
                    elif post_patch_failure_attempts >= POST_PATCH_VALIDATION_THRESHOLD:
                        log_message(
                            "⚠️ [INFO] Post-patch failures exceeded threshold; performing validate+patch cycle."
                        )
                        validate_and_restart_gmod()
                        failure_ticks = 0
                        post_patch_failure_attempts = 0
                else:
                    # We haven't patched yet; once failures hit the threshold, run a patch.
                    if failure_ticks >= PATCH_FAILURE_THRESHOLD:
                        if run_gmod_patch_tool():
                            patch_triggered_after_failures = True
                            post_patch_failure_attempts = 0
                            log_message(
                                "✅ [INFO] Patch applied after repeated failures; watching for a successful reconnect."
                            )
                        else:
                            log_message(
                                "⚠️ [ERROR] Patch tool failed after repeated failures; "
                                "will continue monitoring and may escalate to validation."
                            )

                # Auto-relaunch GMod if:
                # - server is online,
                # - and we have at least PATCH_FAILURE_THRESHOLD failures,
                # regardless of whether GMod is already running (we kill stale instances first).
                if server_online and failure_ticks >= PATCH_FAILURE_THRESHOLD:
                    log_message(
                        "🚀 [INFO] Connection has failed multiple times while the server is online; "
                        "attempting to relaunch GMod..."
                    )
                    launch_gmod()

            time.sleep(CHECK_INTERVAL)

        except KeyboardInterrupt:
            log_message("👋 [INFO] Swamp reconnect script stopped by user (Ctrl+C).")
            break
        except Exception as e:
            log_message(f"⚠️ [ERROR] Unexpected exception in main loop: {e}")
            time.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    main()

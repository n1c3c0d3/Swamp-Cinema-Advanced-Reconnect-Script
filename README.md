# Swamp-Cinema-Advanced-Reconnect-Script
A python-based automation script for Windows or Linux users for keeping your Garry's Mod game client reconnecting to the Swamp Cinema GMOD server indefinitely.
It features minimal logging, will inform you relevant information for reconnection and warns user of points of failure.
It also handles automatically running the GMOD CEF FIX patch if the game fails to launch due to game-breaking steam updates.

## How it works
As long as the script is running, it will check the following information and conditions:

- Checks the gameserver current IP listed on its website, or uses last known IP.
- Checks if the gameserver is online. If yes, will continue running the rest of the conditions below.
- Checks if the game is running. If not, will launch and autoconnect at least twice. If it is not able to connect and the server is online, it will try to revalidate the game files and apply the CEF patch.
- If the CEF patch fails, it will check if there is a newer patch available, attempt to download newer patch, revalidate, and try again. (Work in Progress)
- From here, it will keep trying to reconnect as long the gameserver is still online.
- If you disconnect from the gameserver, it will keep trying to loop the above.

## Basic Instructions
- Download the file swamp_reconnect.py
- Run the file from your preferred CLI / terminal

## Important Notes
Please install the utilities below. This script uses these utilities to detect network traffic, monitor the status of Garry's Mod (GMod) and automatically reapply patches if needed.

## Windows Requirements
- Python 3 (3.6+).
- Python packages: install via `pip install -r requirements.txt`.
- Npcap: download from npcap.org; enable non‑administrator mode during installation.
- Wireshark: ensure its folder is in your PATH.
- Own + have a working Garry's MOD game client installed
- Have a working internet connection

### Windows Instructions
Before running the script in powershell or command prompt, make sure you are running from the root directory where the file is stored on your PC.

For example, to run the script from a folder on your desktop, you would enter the typical commands below

```
cd C:/users/username/Desktop/swamp_reconnect/
python swamp_reconnect.py
```

Assuming you have Python installed before using this script, you should either have a Python System PATH set or a Python Virtual Environment (For more information see https://docs.python.org/3/using/windows.html). As long as you are able to run Python commands in your CLI, you should be able to at least launch the script and can move on to review the additional instructions.

After installing Wireshark, you should also set the PATH in Windows System Environment Variables to the Wireshark.exe file location on your system. This will make it easier for the script to run wireshark commands from almost any directory path you're using. If you forget to set the PATH, the script may not have access to the needed wireshark commands for detecting the connection to the gameserver.

From Windows Start, look for 'Edit the system environment variables'. Then look for the "Environment Variables" button. Now under System variables, look for `Path` and click `Edit...` Next, paste the directory to your Wireshark install. A standard path would be: `C:\Program Files\Wireshark`

### Linux Instructions
To run this script, simply set executable permissions on the file using the chmod command and open in your preferred linux terminal (e.g. gnome, konsole, kitty)

## Requirements
- Python 3 (3.6+).
- Python packages: install via `pip install -r requirements.txt`.
- GMOD CEF Fix (will download the file automatically to its root location unless you specify a path) *WIP
- Basic linux CLI knowledge
- Own + have a working Garry's MOD game client installed
- Have a working internet connection

## Linux packages used
- tcpdump – for monitoring UDP packets
- pgrep – typically provided by the procps (or procps-ng) package
- xdg-open – from xdg-utils, used to launch the game via Steam connect URL

## Python packages used
See requirements.txt

This script is fully open source, feel free to take inspiration as you please.

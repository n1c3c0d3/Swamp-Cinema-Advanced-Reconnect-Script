# Swamp-Cinema-Advanced-Reconnect-Script
An easy to run script for Linux users that will keep reconnecting to the Swamp Cinema GMOD server

## Important Notes
Don't forget to edit the contents of the file in your preferred text editor to add the directory path of your GMOD CEF Fix patch binary executable location.
Look for the variable at the top: GMOD_CEF_FIX_PATH

To run this script, simply set executable permissions on the file using the chmod command and open in your preferred linux terminal (e.g. gnome, konsole, kitty)

As long as the script is running and the device stays on, it will check the following information and conditions:

- Checks the gameserver current IP listed on its website, or uses last known IP.
- Checks if the gameserver is online. If yes, will continue running the rest of the conditions below.
- Checks if the game is running. If not, will launch and autoconnect at least twice. If it is not able to connect and the server is online, it will try to revalidate the game files and apply the CEF patch.
- If the CEF patch fails, it will check if there is a newer patch available, revalidate, and try again.
- From here, it will keep trying to reconnect as long the gameserver is still online.
- If you disconnect from the gameserver, it will keep trying to loop the above.

HTTP Packet Sniffer - Install and Run

Overview
--------
This project is a packet sniffer that captures HTTP traffic and displays it in a Tkinter GUI with advanced filtering capabilities. It uses only Python standard library modules (socket, struct, tkinter, etc.).

Features
--------
✅ Phase 1: Raw Packet Capture - Captures all TCP packets from the network
✅ Phase 2: HTTP Packet Identification - Filters and identifies HTTP traffic
✅ Phase 3: Real-Time Display - Shows HTTP requests/responses with timestamps
✅ Phase 4: Request Filtering - Filter by HTTP method (GET, POST, etc.) and IP addresses

Dependencies
------------
- Python 3.8+ (or system Python 3)
- System package: `python3-tk` (provides `tkinter`) — necessary for the GUI

On Debian/Ubuntu (recommended):

```bash
sudo apt update
sudo apt install -y python3-tk
```

On Fedora/CentOS (dnf/yum):

```bash
sudo dnf install python3-tkinter
# or
sudo yum install python3-tkinter
```

On Arch Linux:

```bash
sudo pacman -S tk
```

macOS:
- Tkinter is often included with the Python from python.org. If you installed Python via Homebrew, you may need to install the `tcl-tk` and reinstall Python linking to it.

Running the application
-----------------------
The program requires elevated privileges to capture raw packets. The recommended setup has been completed:

```bash
# This has already been done for you:
# sudo setcap cap_net_raw,cap_net_admin+ep /usr/bin/python3.10

# Now you can run without sudo:
python3 main.py
```

Alternative methods if needed:

1) Run the GUI as root (not recommended due to display permission issues):

```bash
sudo python3 main.py
```

2) Use sudo with environment preservation:

```bash
sudo -E python3 main.py
```

Using the Filters (Phase 4)
----------------------------
The GUI includes powerful filtering options:

1. **Enable Filters**: Check the "Enable Filters" checkbox
2. **Method Filter**: Select HTTP method (GET, POST, PUT, DELETE, etc.) or "All"
3. **Source IP Filter**: Enter partial or full source IP address (e.g., "192.168" or "10.0.0.1")
4. **Destination IP Filter**: Enter partial or full destination IP address
5. Click "Apply Filters" or press Enter in the IP fields
6. Use "Clear Filters" to reset all filter settings

Filters work in real-time and also retrospectively on already captured packets.

Notes
-----
- `requirements.txt` is intentionally empty of pip packages because all functionality uses standard library modules.
- If you prefer not to change interpreter capabilities, use `sudo` but be aware of possible display permission issues (you may need to allow the root user to access your display).

Troubleshooting
---------------
- If after installing `python3-tk` you still get import errors, ensure you're using the system Python that has tkinter linked.
- If the GUI doesn't appear when running with `sudo`, try running with `sudo -E` to preserve environment variables like `DISPLAY`, or use the `setcap` approach above to avoid running the GUI as root.

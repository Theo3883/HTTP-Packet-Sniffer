# HTTP Packet Sniffer - Phase 2

## Phase 2: HTTP Packet Identification

Filter captured packets to identify HTTP traffic using proper OOP structure.

### Features
- Decode packet headers using struct/ctypes
- Parse Ethernet, IP, and TCP headers
- Identify HTTP requests by port and method
- Separate HTTP requests from other traffic
- Display only HTTP request packets in real-time

### Project Structure
```
.
├── main.py              # Entry point
├── config/              # Configuration settings
│   └── settings.py      # SnifferConfig class
├── core/                # Core packet capture
│   └── sniffer.py       # PacketSniffer class
└── parsers/             # Protocol parsers
    ├── ethernet_parser.py  # EthernetParser class
    ├── ip_parser.py        # IPv4Parser class
    ├── tcp_parser.py       # TCPParser class
    └── http_parser.py      # HTTPParser class
```

### Requirements
- Python 3.6+
- Root/sudo privileges (required for raw socket access)
- Linux operating system (AF_PACKET is Linux-specific)

### Usage

Run with sudo to grant raw socket privileges:

```bash
sudo python3 main.py
```

### Output

Functional Output: Only HTTP request packets are displayed and processed.

Example:
```
[HTTP #1] GET / | 192.168.1.100:54321 -> 93.184.216.34:80
[HTTP #2] POST /api/users | 192.168.1.100:54322 -> 10.0.0.5:8080
[HTTP #3] GET /index.html | 192.168.1.100:54323 -> 93.184.216.34:80
```

### Technical Details

**OOP Design:**
- `PacketSniffer`: Main orchestrator class
- `EthernetParser`, `IPv4Parser`, `TCPParser`: Protocol parsers using dependency injection
- `HTTPParser`: HTTP request identification
- `SnifferConfig`: Centralized configuration

**Packet Processing Pipeline:**
1. Raw socket capture (AF_PACKET)
2. Ethernet frame parsing
3. IP header decoding
4. TCP header parsing
5. HTTP port filtering (80, 8080, 8000, 8888, 3000, 5000)
6. HTTP method detection (GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH, TRACE, CONNECT)

### Next Phase
- Phase 3: Full HTTP Data Extraction (Parse complete headers and body)

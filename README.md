# HTTP Packet Sniffer - Phase 4

## Phase 4: Request Filtering

Implement filters for captured HTTP requests, allowing users to view only requests matching selected filters.

### Features
- Real-time HTTP packet capture and parsing
- **Filter by HTTP method type** (GET, POST, DELETE, etc.)
- **Filter by source IP address**
- **Filter by destination IP address**
- Structured display with timestamp, headers, and request details
- Interactive console-based filter configuration

### Project Structure
```
.
├── main.py              # Entry point with filter configuration
├── config/              # Configuration settings
│   └── settings.py      # SnifferConfig class
├── core/                # Core packet capture
│   └── sniffer.py       # PacketSniffer class with filter support
├── parsers/             # Protocol parsers
│   ├── ethernet_parser.py  # EthernetParser class
│   ├── ip_parser.py        # IPv4Parser class
│   ├── tcp_parser.py       # TCPParser class
│   └── http_parser.py      # HTTPParser class (with headers/body parsing)
├── models/              # Data models
│   └── packet_info.py   # HTTPRequestInfo dataclass
└── filters/             # Filtering system
    └── packet_filter.py # PacketFilter, MethodFilter, IPFilter, FilterManager
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

### Filter Configuration

When starting the application, you'll be prompted to configure filters:

```
Enable filtering? (y/n) [n]: y

[1] Method Filter
Available methods: GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH, TRACE, CONNECT
Filter by HTTP method (leave empty for all): GET

[2] IP Address Filter
Filter by source IP (leave empty for all): 
Filter by destination IP (leave empty for all): 192.168.1
```

**Filter Examples:**

1. **Show only GET requests:**
   - Enable filtering: `y`
   - Method: `GET`
   - Source IP: (empty)
   - Dest IP: (empty)

2. **Show POST requests to specific server:**
   - Enable filtering: `y`
   - Method: `POST`
   - Source IP: (empty)
   - Dest IP: `10.0.0.5`

3. **Show all requests from specific client:**
   - Enable filtering: `y`
   - Method: (empty)
   - Source IP: `192.168.1.100`
   - Dest IP: (empty)

4. **No filtering (show all):**
   - Enable filtering: `n`

### Output

Functional Output: Users can view real-time HTTP requests with detailed information, filtered by method and IP addresses.

Example output with filtering enabled:

```
======================================================================
HTTP REQUEST DETAILS
======================================================================
Timestamp:    2025-12-22 14:30:45.123
Method:       GET
URI:          /api/data
Version:      HTTP/1.1

Network Info:
  Source:     192.168.1.100:54321 (aa:bb:cc:dd:ee:ff)
  Dest:       93.184.216.34:80 (11:22:33:44:55:66)
  TCP Seq:    1234567890
  TCP Ack:    987654321
  TCP Flags:  ACK, PSH

HTTP Headers: (4 headers)
  Host: example.com
  User-Agent: Mozilla/5.0
  Accept: application/json
  Connection: keep-alive
======================================================================
```

### Technical Details

**OOP Design Patterns:**
- **Strategy Pattern**: `PacketFilter` abstract base with concrete filters
- **Composite Pattern**: `CompositeFilter` combines multiple filters
- **Dependency Injection**: Parsers and filters injected into `PacketSniffer`

**Filter Architecture:**
- `PacketFilter`: Abstract base class
- `MethodFilter`: Filter by HTTP method
- `IPFilter`: Filter by source/destination IP (supports partial matching)
- `CompositeFilter`: Combines multiple filters with AND logic
- `FilterManager`: Manages filter enable/disable state

**Packet Processing Pipeline:**
1. Raw socket capture (AF_PACKET)
2. Protocol parsing (Ethernet → IP → TCP → HTTP)
3. HTTP request identification with headers and body
4. **Filter evaluation** (method and IP checks)
5. Display only matching requests

### Statistics

When stopped (Ctrl+C), the sniffer displays:
- Total packets captured
- TCP packets
- HTTP requests identified
- **Filtered requests displayed** (when filtering enabled)

### Next Phase
- Phase 5: GUI Implementation with Tkinter

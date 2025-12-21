#!/usr/bin/env python3
"""
HTTP Packet Sniffer

Project Structure:
- models/: Data structures (HTTPRequestInfo, HTTPResponseInfo)
- parsers/: Protocol parsers (Ethernet, IP, TCP, HTTP)
- core/: Packet sniffing logic (PacketSniffer)
- filters/: Packet filtering (Strategy pattern)
- gui/: User interface (MVC pattern)
- config/: Configuration settings
"""

from gui import HTTPSnifferGUI


def main():
    """Main entry point for the HTTP packet sniffer application."""
    print("=" * 80)
    print(" HTTP PACKET SNIFFER")
    print("=" * 80)
    print("\nStarting GUI application...")
    print("Features: Real-time capture, filtering by method and IP addresses")
    print("Note: Python3 has been granted raw socket capabilities.\n")
    
    app = HTTPSnifferGUI()
    app.run()


if __name__ == "__main__":
    main()


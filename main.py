#!/usr/bin/env python3
"""
Phase 2: HTTP Packet Identification

Main entry point for the HTTP packet sniffer.
This phase focuses on identifying HTTP traffic from captured TCP packets.
"""

from core import PacketSniffer


def main():
    """Main entry point for the HTTP packet sniffer application."""
    print("=" * 80)
    print(" PHASE 2: HTTP PACKET IDENTIFICATION")
    print("=" * 80)
    print("\nStarting packet capture...")
    print("Features: Decode packet headers, identify HTTP requests")
    print("Note: Requires root/sudo privileges.\n")
    
    sniffer = PacketSniffer()
    sniffer.capture_packets()


if __name__ == "__main__":
    main()

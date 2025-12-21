#!/usr/bin/env python3
"""
Phase 1: Raw Packet Capture

This module captures all incoming and outgoing TCP packets in real-time
using low-level Python sockets.

Requirements:
- Capture raw TCP packets from the network interface
- Real-time capture without packet loss
- Use raw sockets (AF_PACKET)
"""

import socket
import struct
import sys


class RawPacketCapture:
    """Captures raw TCP packets from the network interface."""
    
    # Protocol constants
    ETH_P_ALL = 0x0003  # Capture all protocols
    ETH_PROTOCOL_IP = 8  # IPv4 protocol number in Ethernet frame
    IP_PROTOCOL_TCP = 6  # TCP protocol number in IP header
    
    def __init__(self):
        """Initialize the packet capture."""
        self.running = False
        self.socket = None
        self._init_socket()
    
    def _init_socket(self):
        """Initialize raw socket for packet capture.
        
        Requires root/sudo privileges to create raw socket.
        """
        try:
            # AF_PACKET: Low-level packet interface
            # SOCK_RAW: Raw socket to receive packets at layer 2
            # ETH_P_ALL: Capture all ethernet protocols
            self.socket = socket.socket(
                socket.AF_PACKET, 
                socket.SOCK_RAW, 
                socket.ntohs(self.ETH_P_ALL)
            )
            print("[+] Raw socket created successfully")
        except PermissionError:
            print("[-] Error: Root privileges required to create raw socket")
            print("[-] Please run with sudo: sudo python3 packet_capture.py")
            sys.exit(1)
        except Exception as e:
            print(f"[-] Error creating socket: {e}")
            sys.exit(1)
    
    def _parse_ethernet_header(self, raw_data):
        """Parse Ethernet frame header.
        
        Ethernet Frame Structure (14 bytes):
        - Destination MAC (6 bytes)
        - Source MAC (6 bytes)
        - EtherType (2 bytes)
        
        Returns:
            tuple: (eth_protocol, data)
        """
        dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', raw_data[:14])
        return socket.htons(proto), raw_data[14:]
    
    def _parse_ip_header(self, data):
        """Parse IP header to extract protocol.
        
        IP Header Structure (minimum 20 bytes):
        - Version and IHL (1 byte)
        - Total length, ID, flags, etc.
        - Protocol (1 byte at offset 9)
        
        Returns:
            tuple: (ip_protocol, remaining_data)
        """
        # Ensure we have enough data
        if len(data) < 20:
            return None, data
        
        # Get version and header length from first byte
        version_header_length = data[0]
        header_length = (version_header_length & 15) * 4
        
        # Extract protocol field (at byte offset 9 in IP header)
        proto = data[9]
        
        # Return protocol and data after IP header
        return proto, data[header_length:]
    
    def start_capture(self):
        """Start capturing packets.
        
        Captures all packets and filters for TCP packets in real-time.
        Displays count of captured packets and TCP packets.
        """
        self.running = True
        packet_count = 0
        tcp_count = 0
        
        print("[+] Starting packet capture...")
        print("[*] Capturing all TCP packets in real-time")
        print("[*] Press Ctrl+C to stop\n")
        
        try:
            while self.running:
                try:
                    # Receive packet from socket
                    raw_data, addr = self.socket.recvfrom(65535)
                    packet_count += 1
                    
                    # Parse Ethernet header
                    eth_protocol, data = self._parse_ethernet_header(raw_data)
                    
                    # Check if it's an IPv4 packet
                    if eth_protocol == self.ETH_PROTOCOL_IP:
                        # Parse IP header to get protocol
                        ip_protocol, ip_data = self._parse_ip_header(data)
                        
                        # Check if it's a TCP packet (and ip_protocol is valid)
                        if ip_protocol is not None and ip_protocol == self.IP_PROTOCOL_TCP:
                            tcp_count += 1
                            # Print periodic updates
                            if tcp_count % 100 == 0:
                                print(f"[*] Packets captured: {packet_count} | TCP packets: {tcp_count}")
                except Exception as e:
                    # Skip malformed packets
                    continue
                    # Skip malformed packets
                    continue
        
        except KeyboardInterrupt:
            print("\n[+] Capture stopped by user")
            print(f"[+] Total packets captured: {packet_count}")
            print(f"[+] TCP packets captured: {tcp_count}")
            self.stop()
        except Exception as e:
            print(f"[-] Error during packet capture: {e}")
            self.stop()
    
    def stop(self):
        """Stop packet capture and close socket."""
        self.running = False
        if self.socket:
            self.socket.close()
            print("[+] Socket closed")


def main():
    """Main entry point."""
    print("=" * 60)
    print(" PHASE 1: RAW PACKET CAPTURE")
    print("=" * 60)
    print("\nCapturing raw TCP packets from network interface...")
    print("Note: Requires root/sudo privileges\n")
    
    capture = RawPacketCapture()
    capture.start_capture()


if __name__ == "__main__":
    main()

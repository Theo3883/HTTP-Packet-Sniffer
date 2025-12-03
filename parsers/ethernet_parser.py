"""Ethernet frame parser"""

import socket
import struct
from typing import Tuple


class EthernetParser:
    """Parser for Ethernet frame headers."""
    
    @staticmethod
    def parse(data: bytes) -> Tuple[str, str, int, bytes]:
        """
        Parse Ethernet frame header.
        
        Args:
            data: Raw packet data
            
        Returns:
            Tuple of (dest_mac, src_mac, protocol, remaining_data)
        """
        dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
        return (
            EthernetParser._format_mac(dest_mac),
            EthernetParser._format_mac(src_mac),
            socket.htons(proto),
            data[14:]
        )
    
    @staticmethod
    def _format_mac(mac_bytes: bytes) -> str:
        """Format MAC address to readable string."""
        return ':'.join(map('{:02x}'.format, mac_bytes))

"""IPv4 header parser"""

import struct
from typing import Tuple


class IPv4Parser:
    """Parser for IPv4 headers."""
    
    @staticmethod
    def parse(data: bytes) -> Tuple[int, int, int, int, str, str, bytes]:
        """
        Parse IPv4 header.
        
        Args:
            data: Raw IP packet data
            
        Returns:
            Tuple of (version, header_length, ttl, protocol, src_ip, dest_ip, remaining_data)
        """
        version_header_length = data[0]
        version = version_header_length >> 4
        header_length = (version_header_length & 15) * 4
        ttl, proto, src, dest = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
        
        return (
            version,
            header_length,
            ttl,
            proto,
            IPv4Parser._format_ipv4(src),
            IPv4Parser._format_ipv4(dest),
            data[header_length:]
        )
    
    @staticmethod
    def _format_ipv4(addr: bytes) -> str:
        """Format IPv4 address to readable string."""
        return '.'.join(map(str, addr))

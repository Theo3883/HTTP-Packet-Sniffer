"""TCP header parser"""

import struct
from typing import Tuple


class TCPParser:
    """Parser for TCP headers."""
    
    @staticmethod
    def parse(data: bytes) -> Tuple[int, int, int, int, int, int, int, int, int, int, bytes]:
        """
        Parse TCP header.
        
        Args:
            data: Raw TCP packet data
            
        Returns:
            Tuple of (src_port, dest_port, sequence, acknowledgment, 
                     flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, payload)
        """
        src_port, dest_port, sequence, acknowledgment, offset_reserved_flags = struct.unpack(
            '! H H L L H', data[:14]
        )
        
        offset = (offset_reserved_flags >> 12) * 4
        flag_urg = (offset_reserved_flags & 32) >> 5
        flag_ack = (offset_reserved_flags & 16) >> 4
        flag_psh = (offset_reserved_flags & 8) >> 3
        flag_rst = (offset_reserved_flags & 4) >> 2
        flag_syn = (offset_reserved_flags & 2) >> 1
        flag_fin = offset_reserved_flags & 1
        
        return (
            src_port,
            dest_port,
            sequence,
            acknowledgment,
            flag_urg,
            flag_ack,
            flag_psh,
            flag_rst,
            flag_syn,
            flag_fin,
            data[offset:]
        )

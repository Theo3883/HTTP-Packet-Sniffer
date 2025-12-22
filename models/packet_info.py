"""Data classes for packet information."""

from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Optional


@dataclass
class HTTPRequestInfo:
    """HTTP Request packet information."""
    
    timestamp: datetime
    src_mac: str
    dest_mac: str
    src_ip: str
    dest_ip: str
    src_port: int
    dest_port: int
    sequence: int
    acknowledgment: int
    flag_urg: int
    flag_ack: int
    flag_psh: int
    flag_rst: int
    flag_syn: int
    flag_fin: int
    http_method: str
    http_uri: str
    http_version: str
    http_headers: Dict[str, str]
    http_body: Optional[str] = None
    
    def get_tcp_flags(self) -> str:
        """Get formatted TCP flags string."""
        flags = []
        if self.flag_syn:
            flags.append('SYN')
        if self.flag_ack:
            flags.append('ACK')
        if self.flag_psh:
            flags.append('PSH')
        if self.flag_fin:
            flags.append('FIN')
        if self.flag_rst:
            flags.append('RST')
        return ', '.join(flags) if flags else 'None'
    
    def print_console_details(self) -> None:
        """Print detailed request information to console."""
        print("\n" + "="*70)
        print("HTTP REQUEST DETAILS")
        print("="*70)
        print(f"Timestamp:    {self.timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}")
        print(f"Method:       {self.http_method}")
        print(f"URI:          {self.http_uri}")
        print(f"Version:      {self.http_version}")
        print("\nNetwork Info:")
        print(f"  Source:     {self.src_ip}:{self.src_port} ({self.src_mac})")
        print(f"  Dest:       {self.dest_ip}:{self.dest_port} ({self.dest_mac})")
        print(f"  TCP Seq:    {self.sequence}")
        print(f"  TCP Ack:    {self.acknowledgment}")
        print(f"  TCP Flags:  {self.get_tcp_flags()}")
        
        if self.http_headers:
            print(f"\nHTTP Headers: ({len(self.http_headers)} headers)")
            for key, value in sorted(self.http_headers.items()):
                print(f"  {key}: {value}")
        
        if self.http_body:
            print("\nRequest Body:")
            print(f"  {self.http_body}")
        
        print("="*70 + "\n")

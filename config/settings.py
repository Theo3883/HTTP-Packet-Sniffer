"""Configuration settings for the HTTP packet sniffer."""

from typing import Set


class SnifferConfig:
    """Configuration settings for the packet sniffer.

    Attributes:
        HTTP_PORTS (Set[int]): Known HTTP ports to consider.
        ETH_PROTOCOL_IP (int): IPv4 protocol number in Ethernet frame.
        IP_PROTOCOL_TCP (int): TCP protocol number in IP header.
        SOCKET_BUFFER_SIZE (int): Size of the receive buffer for the socket.
    """

    HTTP_PORTS: Set[int] = {80, 8080, 8000, 8888, 3000, 5000}
    HTTPS_PORT: int = 443

    ETH_PROTOCOL_IP: int = 8
    IP_PROTOCOL_TCP: int = 6

    SOCKET_BUFFER_SIZE: int = 65565
    
    @classmethod
    def get_http_ports_display(cls) -> str:
        """Get formatted string of HTTP ports."""
        return ', '.join(map(str, sorted(cls.HTTP_PORTS)))

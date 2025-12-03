"""Configuration settings for the HTTP packet sniffer."""

from typing import Set


class SnifferConfig:
    """Configuration settings for packet sniffer."""
    
    # Network settings
    HTTP_PORTS: Set[int] = {80, 8080, 8000, 8888, 3000, 5000}
    HTTPS_PORT: int = 443
    
    # Protocol constants
    ETH_PROTOCOL_IP: int = 8  # IPv4
    IP_PROTOCOL_TCP: int = 6  # TCP
    
    # Buffer settings
    SOCKET_BUFFER_SIZE: int = 65565
    
    # GUI settings
    GUI_UPDATE_INTERVAL_MS: int = 100
    
    # Display settings
    MAX_URL_DISPLAY_LENGTH: int = 50
    
    @classmethod
    def get_http_ports_display(cls) -> str:
        """Get formatted string of HTTP ports."""
        return ', '.join(map(str, sorted(cls.HTTP_PORTS)))

"""Configuration settings for the HTTP packet sniffer."""

from typing import Set


class SnifferConfig:
    """Configuration settings for the packet sniffer.

    Attributes (grouped):
        HTTP_PORTS (Set[int]): Known HTTP ports to consider.
        HTTPS_PORT (int): Port number reserved for HTTPS.
        ETH_PROTOCOL_IP (int), IP_PROTOCOL_TCP (int): Protocol numeric constants.
        SOCKET_BUFFER_SIZE (int): Size of the receive buffer for the socket.
        GUI_UPDATE_INTERVAL_MS (int): GUI refresh interval in milliseconds.
        MAX_URL_DISPLAY_LENGTH (int): Max characters of URL shown in UI.
    """

    HTTP_PORTS: Set[int] = {80, 8080, 8000, 8888, 3000, 5000}
    HTTPS_PORT: int = 443

    ETH_PROTOCOL_IP: int = 8
    IP_PROTOCOL_TCP: int = 6

    SOCKET_BUFFER_SIZE: int = 65565

    GUI_UPDATE_INTERVAL_MS: int = 100

    MAX_URL_DISPLAY_LENGTH: int = 50
    
    @classmethod
    def get_http_ports_display(cls) -> str:
        """Get formatted string of HTTP ports."""
        return ', '.join(map(str, sorted(cls.HTTP_PORTS)))

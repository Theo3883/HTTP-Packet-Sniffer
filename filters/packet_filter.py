"""Packet filtering """

from abc import ABC, abstractmethod
from typing import List

from models import HTTPRequestInfo, HTTPResponseInfo


class PacketFilter(ABC):
    """
    Abstract base class for packet filters.
    """
    
    @abstractmethod
    def matches(self, packet_info, packet_type: str = 'request') -> bool:
        """
        Check if packet matches filter criteria.
        
        Args:
            packet_info: HTTPRequestInfo or HTTPResponseInfo
            packet_type: 'request' or 'response'
            
        Returns:
            True if packet matches filter, False otherwise
        """
        pass


class MethodFilter(PacketFilter):
    """Filter packets by HTTP method."""
    
    def __init__(self, method: str):
        """
        Initialize method filter.
        
        Args:
            method: HTTP method to filter by (e.g., 'GET', 'POST')
        """
        self.method = method
    
    def matches(self, packet_info, packet_type: str = 'request') -> bool:
        """Check if packet matches method filter."""
        if packet_type != 'request':
            return True  # Method filter only applies to requests
        
        if self.method == "All":
            return True
        
        if isinstance(packet_info, HTTPRequestInfo):
            return packet_info.http_method == self.method
        
        # Handle dict for backward compatibility
        if isinstance(packet_info, dict):
            return packet_info.get('http_method') == self.method
        
        return True


class IPFilter(PacketFilter):
    """Filter packets by IP address."""
    
    def __init__(self, src_ip: str = "", dest_ip: str = ""):
        """
        Initialize IP filter.
        
        Args:
            src_ip: Source IP address to filter by
            dest_ip: Destination IP address to filter by
        """
        self.src_ip = src_ip.strip()
        self.dest_ip = dest_ip.strip()
    
    def matches(self, packet_info, packet_type: str = 'request') -> bool:
        """Check if packet matches IP filter."""
        if isinstance(packet_info, (HTTPRequestInfo, HTTPResponseInfo)):
            src_match = not self.src_ip or self.src_ip in packet_info.src_ip
            dest_match = not self.dest_ip or self.dest_ip in packet_info.dest_ip
        elif isinstance(packet_info, dict):
            # Handle dict for backward compatibility
            src_match = not self.src_ip or self.src_ip in packet_info.get('src_ip', '')
            dest_match = not self.dest_ip or self.dest_ip in packet_info.get('dest_ip', '')
        else:
            return True
        
        return src_match and dest_match


class CompositeFilter(PacketFilter):
    """
    Composite filter that combines multiple filters.
    
    Implements Composite pattern for combining filters.
    """
    
    def __init__(self, filters: List[PacketFilter] = None):
        """
        Initialize composite filter.
        
        Args:
            filters: List of filters to apply
        """
        self.filters = filters or []
    
    def add_filter(self, filter: PacketFilter) -> None:
        """Add a filter to the composite."""
        self.filters.append(filter)
    
    def remove_filter(self, filter: PacketFilter) -> None:
        """Remove a filter from the composite."""
        if filter in self.filters:
            self.filters.remove(filter)
    
    def matches(self, packet_info, packet_type: str = 'request') -> bool:
        """Check if packet matches all filters in composite."""
        if not self.filters:
            return True
        
        return all(f.matches(packet_info, packet_type) for f in self.filters)


class FilterManager:
    """
    Manages packet filtering with enable/disable functionality.
    
    """
    
    def __init__(self):
        """Initialize filter manager."""
        self.enabled = False
        self.filter = CompositeFilter()
    
    def set_enabled(self, enabled: bool) -> None:
        """Enable or disable filtering."""
        self.enabled = enabled
    
    def is_enabled(self) -> bool:
        """Check if filtering is enabled."""
        return self.enabled
    
    def set_filter(self, filter: PacketFilter) -> None:
        """Set the active filter."""
        self.filter = filter
    
    def matches(self, packet_info, packet_type: str = 'request') -> bool:
        """
        Check if packet matches filter.
        
        If filtering is disabled, all packets match.
        """
        if not self.enabled:
            return True
        
        return self.filter.matches(packet_info, packet_type)

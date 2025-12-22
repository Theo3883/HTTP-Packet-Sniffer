#!/usr/bin/env python3
"""
Phase 4: Request Filtering

Main entry point for the HTTP packet sniffer with filtering capabilities.
Users can filter captured HTTP requests by method type and IP addresses.
"""

from core import PacketSniffer
from filters import FilterManager, MethodFilter, IPFilter, CompositeFilter


def configure_filters() -> FilterManager:
    """Configure packet filters based on user input.
    
    Returns:
        FilterManager: Configured filter manager
    """
    filter_manager = FilterManager()
    
    print("\n" + "="*80)
    print(" FILTER CONFIGURATION")
    print("="*80)
    
    # Ask if user wants to enable filtering
    enable_filter = input("\nEnable filtering? (y/n) [n]: ").strip().lower()
    
    if enable_filter != 'y':
        print("[*] Filtering disabled - all HTTP requests will be displayed")
        return filter_manager
    
    filter_manager.set_enabled(True)
    composite = CompositeFilter()
    
    # Method filter
    print("\n[1] Method Filter")
    print("Available methods: GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH, TRACE, CONNECT")
    method = input("Filter by HTTP method (leave empty for all): ").strip().upper()
    
    if method:
        if method in ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH', 'TRACE', 'CONNECT']:
            composite.add_filter(MethodFilter(method))
            print(f"[✓] Method filter set to: {method}")
        else:
            print(f"[!] Invalid method '{method}', skipping method filter")
    
    # IP filter
    print("\n[2] IP Address Filter")
    src_ip = input("Filter by source IP (leave empty for all): ").strip()
    dest_ip = input("Filter by destination IP (leave empty for all): ").strip()
    
    if src_ip or dest_ip:
        composite.add_filter(IPFilter(src_ip=src_ip, dest_ip=dest_ip))
        if src_ip:
            print(f"[✓] Source IP filter set to: {src_ip}")
        if dest_ip:
            print(f"[✓] Destination IP filter set to: {dest_ip}")
    
    filter_manager.set_filter(composite)
    
    print("\n[*] Filtering enabled")
    print("="*80)
    
    return filter_manager


def main():
    """Main entry point for the HTTP packet sniffer application."""
    print("=" * 80)
    print(" PHASE 4: HTTP PACKET SNIFFER WITH REQUEST FILTERING")
    print("=" * 80)
    print("\nFeatures:")
    print("  • Real-time HTTP packet capture")
    print("  • Filter by HTTP method (GET, POST, DELETE, etc.)")
    print("  • Filter by source or destination IP addresses")
    print("  • Detailed request information display")
    print("\nNote: Requires root/sudo privileges.")
    
    # Configure filters
    filter_manager = configure_filters()
    
    print("\n[*] Starting packet capture...")
    print("[*] Press Ctrl+C to stop\n")
    
    sniffer = PacketSniffer(filter_manager=filter_manager)
    sniffer.capture_packets()


if __name__ == "__main__":
    main()


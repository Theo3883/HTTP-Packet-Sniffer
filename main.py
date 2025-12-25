#!/usr/bin/env python3
"""
Phase 5: Detailed Request Inspection

Main entry point for the HTTP packet sniffer with filtering and inspection capabilities.
Users can filter captured HTTP requests and inspect individual requests for full details.
"""

from core import PacketSniffer
from filters import FilterManager, MethodFilter, IPFilter, CompositeFilter
from models import HTTPRequestInfo
from typing import List


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


def inspect_requests(captured_requests: List[HTTPRequestInfo]) -> None:
    """Interactive menu to inspect individual HTTP requests.
    
    Args:
        captured_requests: List of captured HTTPRequestInfo objects
    """
    if not captured_requests:
        print("\n[!] No requests captured to inspect.")
        return
    
    while True:
        print("\n" + "="*80)
        print(" REQUEST INSPECTION MENU")
        print("="*80)
        print(f"\nTotal captured requests: {len(captured_requests)}")
        print("\nOptions:")
        print("  1. List all requests (summary)")
        print("  2. Inspect specific request by number")
        print("  3. Search requests by method")
        print("  4. Search requests by IP address")
        print("  5. Exit inspection mode")
        
        choice = input("\nEnter your choice (1-5): ").strip()
        
        if choice == '1':
            list_all_requests(captured_requests)
        elif choice == '2':
            inspect_by_number(captured_requests)
        elif choice == '3':
            search_by_method(captured_requests)
        elif choice == '4':
            search_by_ip(captured_requests)
        elif choice == '5':
            print("\n[+] Exiting inspection mode")
            break
        else:
            print("\n[!] Invalid choice. Please enter a number between 1 and 5.")


def list_all_requests(captured_requests: List[HTTPRequestInfo]) -> None:
    """Display summary of all captured requests.
    
    Args:
        captured_requests: List of captured HTTPRequestInfo objects
    """
    print("\n" + "="*80)
    print(" ALL CAPTURED REQUESTS (SUMMARY)")
    print("="*80)
    print(f"{'#':<6} {'Time':<12} {'Method':<8} {'Source IP:Port':<22} {'URI':<30}")
    print("-"*80)
    
    for idx, req in enumerate(captured_requests, 1):
        timestamp = req.timestamp.strftime('%H:%M:%S.%f')[:-3]
        source = f"{req.src_ip}:{req.src_port}"
        uri = req.http_uri[:30] if len(req.http_uri) <= 30 else req.http_uri[:27] + "..."
        print(f"{idx:<6} {timestamp:<12} {req.http_method:<8} {source:<22} {uri:<30}")
    
    print("-"*80)


def inspect_by_number(captured_requests: List[HTTPRequestInfo]) -> None:
    """Inspect a specific request by its number.
    
    Args:
        captured_requests: List of captured HTTPRequestInfo objects
    """
    try:
        request_num = input(f"\nEnter request number (1-{len(captured_requests)}): ").strip()
        num = int(request_num)
        
        if 1 <= num <= len(captured_requests):
            print_detailed_inspection(captured_requests[num - 1])
        else:
            print(f"\n[!] Invalid request number. Must be between 1 and {len(captured_requests)}.")
    except ValueError:
        print("\n[!] Please enter a valid number.")


def search_by_method(captured_requests: List[HTTPRequestInfo]) -> None:
    """Search and display requests by HTTP method.
    
    Args:
        captured_requests: List of captured HTTPRequestInfo objects
    """
    method = input("\nEnter HTTP method (GET, POST, etc.): ").strip().upper()
    
    matching = [req for req in captured_requests if req.http_method == method]
    
    if not matching:
        print(f"\n[!] No requests found with method: {method}")
        return
    
    print(f"\n[*] Found {len(matching)} request(s) with method: {method}")
    print("\n" + "="*80)
    print(f"{'#':<6} {'Time':<12} {'Source IP:Port':<22} {'URI':<40}")
    print("-"*80)
    
    for idx, req in enumerate(matching, 1):
        timestamp = req.timestamp.strftime('%H:%M:%S.%f')[:-3]
        source = f"{req.src_ip}:{req.src_port}"
        uri = req.http_uri[:40] if len(req.http_uri) <= 40 else req.http_uri[:37] + "..."
        print(f"{idx:<6} {timestamp:<12} {source:<22} {uri:<40}")
    
    print("-"*80)
    
    # Option to inspect one of the matching requests
    inspect = input("\nInspect a request from this list? (y/n): ").strip().lower()
    if inspect == 'y':
        try:
            num = int(input(f"Enter number (1-{len(matching)}): ").strip())
            if 1 <= num <= len(matching):
                print_detailed_inspection(matching[num - 1])
            else:
                print(f"\n[!] Invalid number.")
        except ValueError:
            print("\n[!] Please enter a valid number.")


def search_by_ip(captured_requests: List[HTTPRequestInfo]) -> None:
    """Search and display requests by IP address (source or destination).
    
    Args:
        captured_requests: List of captured HTTPRequestInfo objects
    """
    ip = input("\nEnter IP address (partial match supported): ").strip()
    
    matching = [req for req in captured_requests 
                if ip in req.src_ip or ip in req.dest_ip]
    
    if not matching:
        print(f"\n[!] No requests found matching IP: {ip}")
        return
    
    print(f"\n[*] Found {len(matching)} request(s) matching IP: {ip}")
    print("\n" + "="*80)
    print(f"{'#':<6} {'Time':<12} {'Method':<8} {'Source':<22} {'Dest':<22}")
    print("-"*80)
    
    for idx, req in enumerate(matching, 1):
        timestamp = req.timestamp.strftime('%H:%M:%S.%f')[:-3]
        source = f"{req.src_ip}:{req.src_port}"
        dest = f"{req.dest_ip}:{req.dest_port}"
        print(f"{idx:<6} {timestamp:<12} {req.http_method:<8} {source:<22} {dest:<22}")
    
    print("-"*80)
    
    # Option to inspect one of the matching requests
    inspect = input("\nInspect a request from this list? (y/n): ").strip().lower()
    if inspect == 'y':
        try:
            num = int(input(f"Enter number (1-{len(matching)}): ").strip())
            if 1 <= num <= len(matching):
                print_detailed_inspection(matching[num - 1])
            else:
                print(f"\n[!] Invalid number.")
        except ValueError:
            print("\n[!] Please enter a valid number.")


def print_detailed_inspection(request: HTTPRequestInfo) -> None:
    """Print comprehensive details of an HTTP request.
    
    Displays all metadata, headers, payload, and network information
    in a structured format based on the old project's GUI detail view.
    
    Args:
        request: HTTPRequestInfo object to display
    """
    print("\n" + "="*80)
    print(" HTTP REQUEST DETAILS")
    print("="*80)
    
    # Request Line
    print("\nRequest Line:")
    print(f"  {request.http_method} {request.http_uri} {request.http_version}")
    
    # Timestamp
    print(f"\nTimestamp: {request.timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}")
    
    # Network Information
    print("\nNetwork Information:")
    print(f"  Source MAC:        {request.src_mac}")
    print(f"  Destination MAC:   {request.dest_mac}")
    print(f"  Source IP:Port:    {request.src_ip}:{request.src_port}")
    print(f"  Destination IP:Port: {request.dest_ip}:{request.dest_port}")
    
    # TCP Metadata
    print("\nTCP Metadata:")
    print(f"  Sequence Number:   {request.sequence}")
    print(f"  Acknowledgment:    {request.acknowledgment}")
    print(f"  Flags:             {request.get_tcp_flags()}")
    
    # HTTP Headers
    if request.http_headers:
        print(f"\nHTTP Headers: ({len(request.http_headers)} headers)")
        for key, value in sorted(request.http_headers.items()):
            print(f"  {key}: {value}")
    else:
        print("\nHTTP Headers: (none)")
    
    # Request Body/Payload
    if request.http_body:
        print("\nRequest Body/Payload:")
        print("-"*80)
        print(request.http_body)
        print("-"*80)
    else:
        print("\nRequest Body: (empty)")
    
    print("="*80)


def main():
    """Main entry point for the HTTP packet sniffer application."""
    print("=" * 80)
    print(" PHASE 5: HTTP PACKET SNIFFER WITH REQUEST INSPECTION")
    print("=" * 80)
    print("\nFeatures:")
    print("  • Real-time HTTP packet capture")
    print("  • Filter by HTTP method (GET, POST, DELETE, etc.)")
    print("  • Filter by source or destination IP addresses")
    print("  • Detailed request inspection after capture")
    print("  • Search captured requests by method or IP")
    print("\nNote: Requires root/sudo privileges.")
    
    # Configure filters
    filter_manager = configure_filters()
    
    print("\n[*] Starting packet capture...")
    print("[*] Press Ctrl+C to stop\n")
    
    sniffer = PacketSniffer(filter_manager=filter_manager)
    sniffer.capture_packets()
    
    # Phase 5: Offer request inspection after capture stops
    if sniffer.captured_requests:
        print("\n" + "="*80)
        print(f"[*] {len(sniffer.captured_requests)} HTTP request(s) captured")
        inspect = input("Would you like to inspect captured requests? (y/n): ").strip().lower()
        
        if inspect == 'y':
            inspect_requests(sniffer.captured_requests)
    else:
        print("\n[!] No HTTP requests were captured.")


if __name__ == "__main__":
    main()


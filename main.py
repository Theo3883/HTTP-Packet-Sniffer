#!/usr/bin/env python3
"""
Main entry point for the HTTP packet sniffer GUI application.
"""

from gui import HTTPSnifferGUI


def main():
    """Main entry point for the HTTP packet sniffer GUI application."""
    print("=" * 80)
    print(" HTTP PACKET SNIFFER - GUI VERSION")
    print("=" * 80)
    print("\nFeatures:")
    print("  • Real-time HTTP packet capture with GUI")
    print("  • Filter by HTTP method (GET, POST, DELETE, etc.)")
    print("  • Filter by source or destination IP addresses")
    print("  • Tree view of captured requests")
    print("  • Detailed request inspection panel")
    print("  • Performance monitoring")
    print("  • Log viewer")
    print("\nNote: Requires root/sudo privileges.")
    print("\nStarting GUI...")
    print("=" * 80)
    print()
    
    app = HTTPSnifferGUI()
    app.run()


if __name__ == "__main__":
    main()

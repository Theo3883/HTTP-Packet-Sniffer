#!/usr/bin/env python3
"""
HTTP Packet Sniffer - Phase 4: Request Filtering
Captures and displays HTTP traffic with filtering capabilities
"""

import socket
import struct
import sys
import textwrap
import re
from datetime import datetime
import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import queue

class PacketSniffer:
    def __init__(self, gui_queue=None):
        """Initialize the packet sniffer with raw socket"""
        self.gui_queue = gui_queue
        self.running = False
        
        try:
            # Create a raw socket to capture all IP packets
            # AF_PACKET: Low-level packet interface (Linux)
            # SOCK_RAW: Raw socket protocol
            # socket.ntohs(0x0003): All packets (ETH_P_ALL)
            self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            
            # HTTP traffic statistics
            self.http_request_count = 0
            self.http_response_count = 0
            self.total_http_packets = 0
            
            if gui_queue:
                self.log("[+] Raw socket created successfully")
                self.log("[+] Starting HTTP packet capture...")
            else:
                print("[+] Raw socket created successfully")
                print("[+] Starting HTTP packet capture... (Press Ctrl+C to stop)\n")
        except PermissionError:
            error_msg = "[-] Error: Root privileges required to create raw socket\n    Run with: sudo python3 main.py"
            if gui_queue:
                self.log(error_msg)
            else:
                print(error_msg)
            sys.exit(1)
        except Exception as e:
            error_msg = f"[-] Error creating socket: {e}"
            if gui_queue:
                self.log(error_msg)
            else:
                print(error_msg)
            sys.exit(1)
    
    def log(self, message):
        """Send log message to GUI queue"""
        if self.gui_queue:
            self.gui_queue.put(('log', message))
    
    def stop(self):
        """Stop the packet capture"""
        self.running = False
        if self.socket:
            self.socket.close()
    
    def parse_ethernet_frame(self, data):
        """Parse Ethernet frame header"""
        dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
        return self.format_mac(dest_mac), self.format_mac(src_mac), socket.htons(proto), data[14:]
    
    def format_mac(self, mac_bytes):
        """Format MAC address to readable string"""
        return ':'.join(map('{:02x}'.format, mac_bytes))
    
    def parse_ipv4_header(self, data):
        """Parse IPv4 header"""
        version_header_length = data[0]
        version = version_header_length >> 4
        header_length = (version_header_length & 15) * 4
        ttl, proto, src, dest = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
        return version, header_length, ttl, proto, self.format_ipv4(src), self.format_ipv4(dest), data[header_length:]
    
    def format_ipv4(self, addr):
        """Format IPv4 address to readable string"""
        return '.'.join(map(str, addr))
    
    def parse_tcp_header(self, data):
        """Parse TCP header"""
        src_port, dest_port, sequence, acknowledgment, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
        offset = (offset_reserved_flags >> 12) * 4
        flag_urg = (offset_reserved_flags & 32) >> 5
        flag_ack = (offset_reserved_flags & 16) >> 4
        flag_psh = (offset_reserved_flags & 8) >> 3
        flag_rst = (offset_reserved_flags & 4) >> 2
        flag_syn = (offset_reserved_flags & 2) >> 1
        flag_fin = offset_reserved_flags & 1
        
        return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]
    
    def format_multi_line(self, prefix, data, size=80):
        """Format data for display in multiple lines"""
        size -= len(prefix)
        if isinstance(data, bytes):
            data = ''.join(r'\x{:02x}'.format(byte) for byte in data)
        return '\n'.join([prefix + line for line in textwrap.wrap(data, size)])
    
    def is_http_request(self, payload):
        """
        Identify if payload contains HTTP request
        Returns: (is_http, method, uri, version, headers) or (False, None, None, None, None)
        """
        if not payload or len(payload) < 10:
            return False, None, None, None, None
        
        try:
            # Try to decode as ASCII/UTF-8
            payload_str = payload.decode('ascii', errors='ignore')
            
            # Remove null bytes and clean up
            payload_str = payload_str.replace('\x00', '')
            
            # HTTP request methods
            http_methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH', 'TRACE', 'CONNECT']
            
            # Check if payload starts with HTTP method
            lines = payload_str.split('\r\n') if '\r\n' in payload_str else payload_str.split('\n')
            if not lines:
                return False, None, None, None, None
                
            first_line = lines[0].strip()
            
            for method in http_methods:
                if first_line.startswith(method + ' '):
                    # Parse HTTP request line: METHOD URI HTTP/VERSION
                    parts = first_line.split(' ', 2)
                    if len(parts) >= 3 and 'HTTP/' in parts[2]:
                        # Extract headers
                        headers = {}
                        for line in lines[1:]:
                            if ':' in line and line.strip():
                                key, value = line.split(':', 1)
                                headers[key.strip()] = value.strip()
                            elif line.strip() == '':
                                break
                        
                        return True, parts[0], parts[1], parts[2], headers
                    elif len(parts) >= 2:
                        # Sometimes HTTP/1.0 requests don't include version
                        return True, parts[0], parts[1], 'HTTP/1.0', {}
            
            return False, None, None, None, None
        except Exception as e:
            return False, None, None, None, None
    
    def is_http_response(self, payload):
        """
        Identify if payload contains HTTP response
        Returns: (is_http, version, status_code, status_text, headers) or (False, None, None, None, None)
        """
        if not payload or len(payload) < 10:
            return False, None, None, None, None
        
        try:
            # Try to decode as ASCII/UTF-8
            payload_str = payload.decode('ascii', errors='ignore')
            
            # Remove null bytes and clean up
            payload_str = payload_str.replace('\x00', '')
            
            # Check if payload starts with HTTP version
            lines = payload_str.split('\r\n') if '\r\n' in payload_str else payload_str.split('\n')
            if not lines:
                return False, None, None, None, None
                
            first_line = lines[0].strip()
            
            if first_line.startswith('HTTP/'):
                # Parse HTTP response line: HTTP/VERSION STATUS_CODE STATUS_TEXT
                parts = first_line.split(' ', 2)
                if len(parts) >= 2:
                    # Extract headers
                    headers = {}
                    for line in lines[1:]:
                        if ':' in line and line.strip():
                            key, value = line.split(':', 1)
                            headers[key.strip()] = value.strip()
                        elif line.strip() == '':
                            break
                    
                    status_code = parts[1] if len(parts) > 1 else '200'
                    status_text = parts[2] if len(parts) > 2 else 'OK'
                    return True, parts[0], status_code, status_text, headers
            
            return False, None, None, None, None
        except Exception as e:
            return False, None, None, None, None
    
    def display_http_request(self, packet_info):
        """Send HTTP request data to GUI"""
        if self.gui_queue:
            self.gui_queue.put(('request', packet_info))
        else:
            # Fallback to console display
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
            print(f"\n{'='*80}")
            print(f"║ HTTP REQUEST #{self.http_request_count:<65}║")
            print(f"{'='*80}")
            print(f"┌─ Timestamp: {timestamp}")
            print(f"├─ Method: {packet_info['http_method']}")
            print(f"├─ URL: {packet_info['http_uri']}")
            print(f"└─ {packet_info['src_ip']}:{packet_info['src_port']} → {packet_info['dest_ip']}:{packet_info['dest_port']}")
    
    def display_http_response(self, packet_info):
        """Send HTTP response data to GUI"""
        if self.gui_queue:
            self.gui_queue.put(('response', packet_info))
        else:
            # Fallback to console display
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
            print(f"\n{'='*80}")
            print(f"║ HTTP RESPONSE #{self.http_response_count:<64}║")
            print(f"{'='*80}")
            print(f"┌─ Timestamp: {timestamp}")
            print(f"├─ Status: {packet_info['http_status_code']} {packet_info['http_status_text']}")
            print(f"└─ {packet_info['src_ip']}:{packet_info['src_port']} → {packet_info['dest_ip']}:{packet_info['dest_port']}")
    
    def capture_packets(self):
        """Main packet capture loop - filters and displays only HTTP traffic"""
        packet_count = 0
        tcp_count = 0
        http_ports = {80, 8080, 8000, 8888, 3000, 5000}  # Common HTTP ports
        
        self.running = True
        self.log("[*] Monitoring HTTP traffic on common ports: 80, 8080, 8000, 8888, 3000, 5000")
        self.log("[*] Note: HTTPS (port 443) traffic is encrypted and won't be visible")
        
        try:
            while self.running:
                # Receive packet (65565 is max packet size)
                raw_data, addr = self.socket.recvfrom(65565)
                packet_count += 1
                
                # Parse Ethernet frame
                dest_mac, src_mac, eth_proto, data = self.parse_ethernet_frame(raw_data)
                
                # Check if it's an IPv4 packet (0x0800)
                if eth_proto == 8:
                    # Parse IPv4 header
                    version, header_length, ttl, proto, src_ip, dest_ip, data = self.parse_ipv4_header(data)
                    
                    # Check if it's a TCP packet (protocol number 6)
                    if proto == 6:
                        tcp_count += 1
                        
                        # Parse TCP header
                        src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, payload = self.parse_tcp_header(data)
                        
                        # Only check packets on common HTTP ports or with payload
                        if (src_port in http_ports or dest_port in http_ports) and len(payload) > 0:
                            
                            # Check for HTTP request
                            is_request, method, uri, version, headers = self.is_http_request(payload)
                            if is_request:
                                self.http_request_count += 1
                                self.total_http_packets += 1
                                
                                packet_info = {
                                    'timestamp': datetime.now(),
                                    'src_mac': src_mac,
                                    'dest_mac': dest_mac,
                                    'src_ip': src_ip,
                                    'dest_ip': dest_ip,
                                    'src_port': src_port,
                                    'dest_port': dest_port,
                                    'sequence': sequence,
                                    'acknowledgment': acknowledgment,
                                    'flag_urg': flag_urg,
                                    'flag_ack': flag_ack,
                                    'flag_psh': flag_psh,
                                    'flag_rst': flag_rst,
                                    'flag_syn': flag_syn,
                                    'flag_fin': flag_fin,
                                    'http_method': method,
                                    'http_uri': uri,
                                    'http_version': version,
                                    'http_headers': headers
                                }
                                
                                self.display_http_request(packet_info)
                            
                            # Check for HTTP response
                            is_response, version, status_code, status_text, headers = self.is_http_response(payload)
                            if is_response:
                                self.http_response_count += 1
                                self.total_http_packets += 1
                                
                                packet_info = {
                                    'timestamp': datetime.now(),
                                    'src_ip': src_ip,
                                    'dest_ip': dest_ip,
                                    'src_port': src_port,
                                    'dest_port': dest_port,
                                    'http_version': version,
                                    'http_status_code': status_code,
                                    'http_status_text': status_text,
                                    'http_headers': headers
                                }
                                
                                self.display_http_response(packet_info)
        
        except KeyboardInterrupt:
            self.log(f"\n[+] Capture stopped")
            self.log(f"Total packets: {packet_count}, TCP: {tcp_count}, HTTP: {self.total_http_packets}")
            self.socket.close()
        except Exception as e:
            self.log(f"\n[-] Error during packet capture: {e}")
            if self.socket:
                self.socket.close()


class HTTPSnifferGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("HTTP Packet Sniffer - Real-Time Monitor")
        self.root.geometry("1200x800")
        self.root.configure(bg='#1e1e1e')
        
        # Queue for thread-safe communication
        self.queue = queue.Queue()
        
        # Sniffer instance
        self.sniffer = None
        self.sniffer_thread = None
        
        # Setup UI
        self.setup_ui()
        
        # Start queue processing
        self.process_queue()
        
    def setup_ui(self):
        """Create the modern GUI interface"""
        # Style configuration
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TFrame', background='#1e1e1e')
        style.configure('TLabel', background='#1e1e1e', foreground='#ffffff', font=('Arial', 10))
        style.configure('Title.TLabel', font=('Arial', 16, 'bold'), foreground='#4CAF50')
        style.configure('TButton', font=('Arial', 10, 'bold'))
        
        # Main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = ttk.Label(main_frame, text="🌐 HTTP Packet Sniffer", style='Title.TLabel')
        title_label.pack(pady=(0, 10))
        
        # Control panel
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.start_button = tk.Button(control_frame, text="▶ Start Capture", command=self.start_capture,
                                       bg='#4CAF50', fg='white', font=('Arial', 10, 'bold'),
                                       padx=20, pady=5, relief=tk.FLAT, cursor='hand2')
        self.start_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = tk.Button(control_frame, text="⏹ Stop Capture", command=self.stop_capture,
                                      bg='#f44336', fg='white', font=('Arial', 10, 'bold'),
                                      padx=20, pady=5, relief=tk.FLAT, cursor='hand2', state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        self.clear_button = tk.Button(control_frame, text="🗑 Clear", command=self.clear_displays,
                                       bg='#FF9800', fg='white', font=('Arial', 10, 'bold'),
                                       padx=20, pady=5, relief=tk.FLAT, cursor='hand2')
        self.clear_button.pack(side=tk.LEFT, padx=5)
        
        # Statistics
        stats_frame = ttk.Frame(main_frame)
        stats_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.stats_label = ttk.Label(stats_frame, text="Requests: 0 | Responses: 0 | Total: 0", 
                                      font=('Arial', 10))
        self.stats_label.pack()
        
        # Notebook for tabs
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Request tab
        request_frame = ttk.Frame(self.notebook)
        self.notebook.add(request_frame, text='📤 HTTP Requests')
        
        # Treeview for requests
        request_tree_frame = ttk.Frame(request_frame)
        request_tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.request_tree = ttk.Treeview(request_tree_frame, 
                                          columns=('Time', 'Method', 'URL', 'Source', 'Destination'),
                                          show='tree headings', height=15)
        
        self.request_tree.heading('#0', text='#')
        self.request_tree.heading('Time', text='Timestamp')
        self.request_tree.heading('Method', text='Method')
        self.request_tree.heading('URL', text='URL')
        self.request_tree.heading('Source', text='Source IP:Port')
        self.request_tree.heading('Destination', text='Destination IP:Port')
        
        self.request_tree.column('#0', width=50)
        self.request_tree.column('Time', width=180)
        self.request_tree.column('Method', width=80)
        self.request_tree.column('URL', width=300)
        self.request_tree.column('Source', width=180)
        self.request_tree.column('Destination', width=180)
        
        request_scroll = ttk.Scrollbar(request_tree_frame, orient=tk.VERTICAL, command=self.request_tree.yview)
        self.request_tree.configure(yscrollcommand=request_scroll.set)
        
        self.request_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        request_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Request details
        request_detail_label = ttk.Label(request_frame, text="Request Details:", font=('Arial', 10, 'bold'))
        request_detail_label.pack(anchor=tk.W, padx=5, pady=(5, 0))
        
        self.request_detail = scrolledtext.ScrolledText(request_frame, height=10, bg='#2b2b2b', 
                                                         fg='#ffffff', font=('Courier', 9),
                                                         insertbackground='white')
        self.request_detail.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.request_tree.bind('<<TreeviewSelect>>', self.on_request_select)
        
        # Response tab
        response_frame = ttk.Frame(self.notebook)
        self.notebook.add(response_frame, text='📥 HTTP Responses')
        
        # Treeview for responses
        response_tree_frame = ttk.Frame(response_frame)
        response_tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.response_tree = ttk.Treeview(response_tree_frame,
                                           columns=('Time', 'Status', 'Source', 'Destination'),
                                           show='tree headings', height=15)
        
        self.response_tree.heading('#0', text='#')
        self.response_tree.heading('Time', text='Timestamp')
        self.response_tree.heading('Status', text='Status')
        self.response_tree.heading('Source', text='Source IP:Port')
        self.response_tree.heading('Destination', text='Destination IP:Port')
        
        self.response_tree.column('#0', width=50)
        self.response_tree.column('Time', width=180)
        self.response_tree.column('Status', width=200)
        self.response_tree.column('Source', width=200)
        self.response_tree.column('Destination', width=200)
        
        response_scroll = ttk.Scrollbar(response_tree_frame, orient=tk.VERTICAL, command=self.response_tree.yview)
        self.response_tree.configure(yscrollcommand=response_scroll.set)
        
        self.response_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        response_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Response details
        response_detail_label = ttk.Label(response_frame, text="Response Details:", font=('Arial', 10, 'bold'))
        response_detail_label.pack(anchor=tk.W, padx=5, pady=(5, 0))
        
        self.response_detail = scrolledtext.ScrolledText(response_frame, height=10, bg='#2b2b2b',
                                                          fg='#ffffff', font=('Courier', 9),
                                                          insertbackground='white')
        self.response_detail.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.response_tree.bind('<<TreeviewSelect>>', self.on_response_select)
        
        # Log tab
        log_frame = ttk.Frame(self.notebook)
        self.notebook.add(log_frame, text='📋 Logs')
        
        self.log_text = scrolledtext.ScrolledText(log_frame, bg='#2b2b2b', fg='#00ff00',
                                                   font=('Courier', 9), insertbackground='white')
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Status bar
        self.status_label = ttk.Label(main_frame, text="Status: Idle", font=('Arial', 9))
        self.status_label.pack(side=tk.BOTTOM, fill=tk.X, pady=(5, 0))
        
        # Store packet data
        self.request_data = {}
        self.response_data = {}
        self.request_count = 0
        self.response_count = 0
        
        # Filter settings
        self.filter_method = tk.StringVar(value="All")
        self.filter_src_ip = tk.StringVar(value="")
        self.filter_dest_ip = tk.StringVar(value="")
        self.filter_enabled = tk.BooleanVar(value=False)
        
        # Add filter panel
        self.add_filter_panel(main_frame)
    
    def start_capture(self):
        """Start packet capture in a separate thread"""
        if self.sniffer_thread and self.sniffer_thread.is_alive():
            return
        
        self.log_message("[+] Starting packet capture...")
        self.status_label.config(text="Status: Capturing...")
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        
        # Create sniffer and start thread
        self.sniffer = PacketSniffer(gui_queue=self.queue)
        self.sniffer_thread = threading.Thread(target=self.sniffer.capture_packets, daemon=True)
        self.sniffer_thread.start()
    
    def add_filter_panel(self, parent):
        """Add filter panel to the GUI"""
        filter_frame = ttk.LabelFrame(parent, text="🔍 Filters (Phase 4)", padding="10")
        filter_frame.pack(fill=tk.X, pady=(0, 10), after=self.notebook)
        
        # Enable/Disable filters
        filter_toggle_frame = ttk.Frame(filter_frame)
        filter_toggle_frame.pack(fill=tk.X, pady=(0, 5))
        
        self.filter_checkbox = tk.Checkbutton(filter_toggle_frame, text="Enable Filters", 
                                               variable=self.filter_enabled,
                                               command=self.apply_filters,
                                               bg='#1e1e1e', fg='#ffffff', selectcolor='#2b2b2b',
                                               font=('Arial', 10, 'bold'))
        self.filter_checkbox.pack(side=tk.LEFT)
        
        # Filter controls
        controls_frame = ttk.Frame(filter_frame)
        controls_frame.pack(fill=tk.X)
        
        # Method filter
        method_frame = ttk.Frame(controls_frame)
        method_frame.pack(side=tk.LEFT, padx=5)
        
        method_label = ttk.Label(method_frame, text="Method:")
        method_label.pack(side=tk.LEFT, padx=(0, 5))
        
        method_combo = ttk.Combobox(method_frame, textvariable=self.filter_method, 
                                     values=["All", "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"],
                                     width=10, state='readonly')
        method_combo.pack(side=tk.LEFT)
        method_combo.bind('<<ComboboxSelected>>', lambda e: self.apply_filters())
        
        # Source IP filter
        src_ip_frame = ttk.Frame(controls_frame)
        src_ip_frame.pack(side=tk.LEFT, padx=5)
        
        src_ip_label = ttk.Label(src_ip_frame, text="Source IP:")
        src_ip_label.pack(side=tk.LEFT, padx=(0, 5))
        
        src_ip_entry = tk.Entry(src_ip_frame, textvariable=self.filter_src_ip, width=15,
                                bg='#2b2b2b', fg='#ffffff', insertbackground='white')
        src_ip_entry.pack(side=tk.LEFT)
        src_ip_entry.bind('<Return>', lambda e: self.apply_filters())
        
        # Destination IP filter
        dest_ip_frame = ttk.Frame(controls_frame)
        dest_ip_frame.pack(side=tk.LEFT, padx=5)
        
        dest_ip_label = ttk.Label(dest_ip_frame, text="Dest IP:")
        dest_ip_label.pack(side=tk.LEFT, padx=(0, 5))
        
        dest_ip_entry = tk.Entry(dest_ip_frame, textvariable=self.filter_dest_ip, width=15,
                                 bg='#2b2b2b', fg='#ffffff', insertbackground='white')
        dest_ip_entry.pack(side=tk.LEFT)
        dest_ip_entry.bind('<Return>', lambda e: self.apply_filters())
        
        # Apply button
        apply_button = tk.Button(controls_frame, text="Apply Filters", command=self.apply_filters,
                                 bg='#2196F3', fg='white', font=('Arial', 9, 'bold'),
                                 padx=10, pady=2, relief=tk.FLAT, cursor='hand2')
        apply_button.pack(side=tk.LEFT, padx=5)
        
        # Clear filters button
        clear_filter_button = tk.Button(controls_frame, text="Clear Filters", command=self.clear_filters,
                                        bg='#9E9E9E', fg='white', font=('Arial', 9, 'bold'),
                                        padx=10, pady=2, relief=tk.FLAT, cursor='hand2')
        clear_filter_button.pack(side=tk.LEFT, padx=5)
        
        # Filter status
        self.filter_status_label = ttk.Label(filter_frame, text="Filters: Disabled", 
                                             font=('Arial', 9, 'italic'))
        self.filter_status_label.pack(pady=(5, 0))
    
    def matches_filter(self, packet_info, packet_type='request'):
        """Check if packet matches current filter settings"""
        if not self.filter_enabled.get():
            return True
        
        # For requests, check method and IPs
        if packet_type == 'request':
            # Check method filter
            method_filter = self.filter_method.get()
            if method_filter != "All" and packet_info['http_method'] != method_filter:
                return False
            
            # Check source IP filter
            src_ip_filter = self.filter_src_ip.get().strip()
            if src_ip_filter and src_ip_filter not in packet_info['src_ip']:
                return False
            
            # Check destination IP filter
            dest_ip_filter = self.filter_dest_ip.get().strip()
            if dest_ip_filter and dest_ip_filter not in packet_info['dest_ip']:
                return False
        
        # For responses, check IPs only
        elif packet_type == 'response':
            # Check source IP filter
            src_ip_filter = self.filter_src_ip.get().strip()
            if src_ip_filter and src_ip_filter not in packet_info['src_ip']:
                return False
            
            # Check destination IP filter
            dest_ip_filter = self.filter_dest_ip.get().strip()
            if dest_ip_filter and dest_ip_filter not in packet_info['dest_ip']:
                return False
        
        return True
    
    def apply_filters(self):
        """Apply current filters to displayed packets"""
        if self.filter_enabled.get():
            method = self.filter_method.get()
            src_ip = self.filter_src_ip.get().strip()
            dest_ip = self.filter_dest_ip.get().strip()
            
            filters = []
            if method != "All":
                filters.append(f"Method={method}")
            if src_ip:
                filters.append(f"SrcIP={src_ip}")
            if dest_ip:
                filters.append(f"DestIP={dest_ip}")
            
            status = f"Filters: Active ({', '.join(filters)})" if filters else "Filters: Active (None)"
            self.filter_status_label.config(text=status)
            self.log_message(f"[*] Filters applied: {status}")
        else:
            self.filter_status_label.config(text="Filters: Disabled")
            self.log_message("[*] Filters disabled")
        
        # Refresh display
        self.refresh_filtered_display()
    
    def clear_filters(self):
        """Clear all filter settings"""
        self.filter_method.set("All")
        self.filter_src_ip.set("")
        self.filter_dest_ip.set("")
        self.filter_enabled.set(False)
        self.apply_filters()
    
    def refresh_filtered_display(self):
        """Refresh the display based on current filter settings"""
        # Store all data temporarily
        all_request_data = dict(self.request_data)
        all_response_data = dict(self.response_data)
        
        # Clear trees
        self.request_tree.delete(*self.request_tree.get_children())
        self.response_tree.delete(*self.response_tree.get_children())
        
        # Clear stored data
        self.request_data.clear()
        self.response_data.clear()
        
        # Re-add filtered items
        req_count = 0
        for item_id, packet_info in all_request_data.items():
            if self.matches_filter(packet_info, 'request'):
                req_count += 1
                timestamp = packet_info['timestamp'].strftime('%H:%M:%S.%f')[:-3]
                
                new_item = self.request_tree.insert('', tk.END, text=str(req_count),
                                                     values=(timestamp,
                                                            packet_info['http_method'],
                                                            packet_info['http_uri'][:50],
                                                            f"{packet_info['src_ip']}:{packet_info['src_port']}",
                                                            f"{packet_info['dest_ip']}:{packet_info['dest_port']}"))
                
                self.request_data[new_item] = packet_info
        
        resp_count = 0
        for item_id, packet_info in all_response_data.items():
            if self.matches_filter(packet_info, 'response'):
                resp_count += 1
                timestamp = packet_info['timestamp'].strftime('%H:%M:%S.%f')[:-3]
                status = f"{packet_info['http_status_code']} {packet_info['http_status_text']}"
                
                new_item = self.response_tree.insert('', tk.END, text=str(resp_count),
                                                      values=(timestamp,
                                                             status,
                                                             f"{packet_info['src_ip']}:{packet_info['src_port']}",
                                                             f"{packet_info['dest_ip']}:{packet_info['dest_port']}"))
                
                self.response_data[new_item] = packet_info
        
        # Log results
        self.log_message(f"[*] Filtered: {req_count} requests, {resp_count} responses")
    
    def stop_capture(self):
        """Stop packet capture"""
        if self.sniffer:
            self.log_message("[+] Stopping packet capture...")
            self.sniffer.stop()
            self.status_label.config(text="Status: Stopped")
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
    
    def clear_displays(self):
        """Clear all displays"""
        self.request_tree.delete(*self.request_tree.get_children())
        self.response_tree.delete(*self.response_tree.get_children())
        self.request_detail.delete('1.0', tk.END)
        self.response_detail.delete('1.0', tk.END)
        self.request_data.clear()
        self.response_data.clear()
        self.request_count = 0
        self.response_count = 0
        self.update_stats()
        self.log_message("[+] Display cleared")
    
    def log_message(self, message):
        """Add message to log"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)
    
    def update_stats(self):
        """Update statistics display"""
        total = self.request_count + self.response_count
        self.stats_label.config(text=f"Requests: {self.request_count} | Responses: {self.response_count} | Total: {total}")
    
    def on_request_select(self, event):
        """Handle request selection"""
        selection = self.request_tree.selection()
        if selection:
            item = selection[0]
            if item in self.request_data:
                data = self.request_data[item]
                self.display_request_details(data)
    
    def on_response_select(self, event):
        """Handle response selection"""
        selection = self.response_tree.selection()
        if selection:
            item = selection[0]
            if item in self.response_data:
                data = self.response_data[item]
                self.display_response_details(data)
    
    def display_request_details(self, packet_info):
        """Display detailed request information"""
        self.request_detail.delete('1.0', tk.END)
        
        details = f"HTTP Request Details\n{'='*60}\n\n"
        details += f"Timestamp: {packet_info['timestamp'].strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}\n"
        details += f"Method: {packet_info['http_method']}\n"
        details += f"URL: {packet_info['http_uri']}\n"
        details += f"Version: {packet_info['http_version']}\n\n"
        
        details += f"Network Information:\n"
        details += f"  Source: {packet_info['src_ip']}:{packet_info['src_port']}\n"
        details += f"  Destination: {packet_info['dest_ip']}:{packet_info['dest_port']}\n\n"
        
        flags = []
        if packet_info['flag_syn']: flags.append('SYN')
        if packet_info['flag_ack']: flags.append('ACK')
        if packet_info['flag_psh']: flags.append('PSH')
        if packet_info['flag_fin']: flags.append('FIN')
        if packet_info['flag_rst']: flags.append('RST')
        details += f"TCP Flags: {', '.join(flags) if flags else 'None'}\n\n"
        
        if packet_info['http_headers']:
            details += f"HTTP Headers:\n"
            for key, value in packet_info['http_headers'].items():
                details += f"  {key}: {value}\n"
        
        self.request_detail.insert('1.0', details)
    
    def display_response_details(self, packet_info):
        """Display detailed response information"""
        self.response_detail.delete('1.0', tk.END)
        
        details = f"HTTP Response Details\n{'='*60}\n\n"
        details += f"Timestamp: {packet_info['timestamp'].strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}\n"
        details += f"Status: {packet_info['http_status_code']} {packet_info['http_status_text']}\n"
        details += f"Version: {packet_info['http_version']}\n\n"
        
        details += f"Network Information:\n"
        details += f"  Source: {packet_info['src_ip']}:{packet_info['src_port']}\n"
        details += f"  Destination: {packet_info['dest_ip']}:{packet_info['dest_port']}\n\n"
        
        if packet_info['http_headers']:
            details += f"HTTP Headers:\n"
            for key, value in packet_info['http_headers'].items():
                details += f"  {key}: {value}\n"
        
        self.response_detail.insert('1.0', details)
    
    def process_queue(self):
        """Process messages from the sniffer thread"""
        try:
            while True:
                msg_type, data = self.queue.get_nowait()
                
                if msg_type == 'log':
                    self.log_message(data)
                elif msg_type == 'request':
                    self.add_request(data)
                elif msg_type == 'response':
                    self.add_response(data)
        except queue.Empty:
            pass
        
        # Schedule next check
        self.root.after(100, self.process_queue)
    
    def add_request(self, packet_info):
        """Add HTTP request to the tree"""
        # Check if packet matches filter
        if not self.matches_filter(packet_info, 'request'):
            return
        
        self.request_count += 1
        timestamp = packet_info['timestamp'].strftime('%H:%M:%S.%f')[:-3]
        
        item = self.request_tree.insert('', tk.END, text=str(self.request_count),
                                         values=(timestamp,
                                                packet_info['http_method'],
                                                packet_info['http_uri'][:50],
                                                f"{packet_info['src_ip']}:{packet_info['src_port']}",
                                                f"{packet_info['dest_ip']}:{packet_info['dest_port']}"))
        
        self.request_data[item] = packet_info
        self.update_stats()
        
        # Auto-scroll to bottom
        self.request_tree.see(item)
    
    def add_response(self, packet_info):
        """Add HTTP response to the tree"""
        # Check if packet matches filter
        if not self.matches_filter(packet_info, 'response'):
            return
        
        self.response_count += 1
        timestamp = packet_info['timestamp'].strftime('%H:%M:%S.%f')[:-3]
        status = f"{packet_info['http_status_code']} {packet_info['http_status_text']}"
        
        item = self.response_tree.insert('', tk.END, text=str(self.response_count),
                                          values=(timestamp,
                                                 status,
                                                 f"{packet_info['src_ip']}:{packet_info['src_port']}",
                                                 f"{packet_info['dest_ip']}:{packet_info['dest_port']}"))
        
        self.response_data[item] = packet_info
        self.update_stats()
        
        # Auto-scroll to bottom
        self.response_tree.see(item)
    
    def run(self):
        """Run the GUI"""
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.root.mainloop()
    
    def on_closing(self):
        """Handle window close"""
        if self.sniffer:
            self.sniffer.stop()
        self.root.destroy()


def main():
    """Main function to run the HTTP sniffer GUI"""
    print("="*80)
    print(" HTTP PACKET SNIFFER - Phase 4: Request Filtering")
    print("="*80)
    print("\nStarting GUI application...")
    print("Features: Real-time capture, filtering by method and IP addresses")
    print("Note: Requires root/administrator privileges to capture packets.")
    print("      Python3 has been granted raw socket capabilities.\n")
    
    app = HTTPSnifferGUI()
    app.run()

if __name__ == "__main__":
    main()

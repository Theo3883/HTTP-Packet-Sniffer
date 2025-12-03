#!/usr/bin/env python3
"""
HTTP Packet Sniffer - Phase 4: Request Filtering
Simplified stable GUI version
"""

import socket
import struct
import sys
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
            self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            self.http_request_count = 0
            self.http_response_count = 0
            self.total_http_packets = 0
            
            if gui_queue:
                self.log("[+] Raw socket created successfully")
                self.log("[+] Starting HTTP packet capture...")
        except PermissionError:
            error_msg = "[-] Error: Root privileges required to create raw socket"
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
    
    def is_http_request(self, payload):
        """Identify if payload contains HTTP request"""
        if not payload or len(payload) < 10:
            return False, None, None, None, None
        
        try:
            payload_str = payload.decode('ascii', errors='ignore')
            payload_str = payload_str.replace('\x00', '')
            http_methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH', 'TRACE', 'CONNECT']
            lines = payload_str.split('\r\n') if '\r\n' in payload_str else payload_str.split('\n')
            if not lines:
                return False, None, None, None, None
                
            first_line = lines[0].strip()
            
            for method in http_methods:
                if first_line.startswith(method + ' '):
                    parts = first_line.split(' ', 2)
                    if len(parts) >= 3 and 'HTTP/' in parts[2]:
                        headers = {}
                        for line in lines[1:]:
                            if ':' in line and line.strip():
                                key, value = line.split(':', 1)
                                headers[key.strip()] = value.strip()
                            elif line.strip() == '':
                                break
                        return True, parts[0], parts[1], parts[2], headers
                    elif len(parts) >= 2:
                        return True, parts[0], parts[1], 'HTTP/1.0', {}
            
            return False, None, None, None, None
        except Exception as e:
            return False, None, None, None, None
    
    def is_http_response(self, payload):
        """Identify if payload contains HTTP response"""
        if not payload or len(payload) < 10:
            return False, None, None, None, None
        
        try:
            payload_str = payload.decode('ascii', errors='ignore')
            payload_str = payload_str.replace('\x00', '')
            lines = payload_str.split('\r\n') if '\r\n' in payload_str else payload_str.split('\n')
            if not lines:
                return False, None, None, None, None
                
            first_line = lines[0].strip()
            
            if first_line.startswith('HTTP/'):
                parts = first_line.split(' ', 2)
                if len(parts) >= 2:
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
    
    def display_http_response(self, packet_info):
        """Send HTTP response data to GUI"""
        if self.gui_queue:
            self.gui_queue.put(('response', packet_info))
    
    def capture_packets(self):
        """Main packet capture loop"""
        packet_count = 0
        tcp_count = 0
        http_ports = {80, 8080, 8000, 8888, 3000, 5000}
        
        self.running = True
        self.log("[*] Monitoring HTTP traffic on ports: 80, 8080, 8000, 8888, 3000, 5000")
        self.log("[*] Note: HTTPS (port 443) traffic is encrypted and won't be visible")
        
        try:
            while self.running:
                raw_data, addr = self.socket.recvfrom(65565)
                packet_count += 1
                
                dest_mac, src_mac, eth_proto, data = self.parse_ethernet_frame(raw_data)
                
                if eth_proto == 8:
                    version, header_length, ttl, proto, src_ip, dest_ip, data = self.parse_ipv4_header(data)
                    
                    if proto == 6:
                        tcp_count += 1
                        src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, payload = self.parse_tcp_header(data)
                        
                        if (src_port in http_ports or dest_port in http_ports) and len(payload) > 0:
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
        self.root.title("HTTP Packet Sniffer - Phase 4")
        self.root.geometry("1400x900")
        
        self.queue = queue.Queue()
        self.sniffer = None
        self.sniffer_thread = None
        
        self.request_data = {}
        self.response_data = {}
        self.request_count = 0
        self.response_count = 0
        
        # Filter settings
        self.filter_method = tk.StringVar(value="All")
        self.filter_src_ip = tk.StringVar(value="")
        self.filter_dest_ip = tk.StringVar(value="")
        self.filter_enabled = tk.BooleanVar(value=False)
        
        self.setup_ui()
        self.process_queue()
        
    def setup_ui(self):
        """Create the GUI interface"""
        # Title
        title_frame = tk.Frame(self.root, bg='#2c3e50', height=60)
        title_frame.pack(fill=tk.X)
        title_frame.pack_propagate(False)
        
        title_label = tk.Label(title_frame, text="HTTP Packet Sniffer - Phase 4", 
                              bg='#2c3e50', fg='white', font=('Arial', 18, 'bold'))
        title_label.pack(pady=15)
        
        # Control panel
        control_frame = tk.Frame(self.root, bg='#ecf0f1', height=50)
        control_frame.pack(fill=tk.X)
        control_frame.pack_propagate(False)
        
        self.start_button = tk.Button(control_frame, text="Start Capture", command=self.start_capture,
                                       bg='#27ae60', fg='white', font=('Arial', 11, 'bold'),
                                       padx=20, pady=8, relief=tk.RAISED, cursor='hand2')
        self.start_button.pack(side=tk.LEFT, padx=10, pady=8)
        
        self.stop_button = tk.Button(control_frame, text="Stop Capture", command=self.stop_capture,
                                      bg='#e74c3c', fg='white', font=('Arial', 11, 'bold'),
                                      padx=20, pady=8, relief=tk.RAISED, cursor='hand2', state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5, pady=8)
        
        self.clear_button = tk.Button(control_frame, text="Clear Display", command=self.clear_displays,
                                       bg='#f39c12', fg='white', font=('Arial', 11, 'bold'),
                                       padx=20, pady=8, relief=tk.RAISED, cursor='hand2')
        self.clear_button.pack(side=tk.LEFT, padx=5, pady=8)
        
        # Stats
        self.stats_label = tk.Label(control_frame, text="Requests: 0 | Responses: 0 | Total: 0", 
                                    bg='#ecf0f1', font=('Arial', 11, 'bold'))
        self.stats_label.pack(side=tk.RIGHT, padx=10)
        
        # Filter panel
        filter_frame = tk.LabelFrame(self.root, text=" Filters (Phase 4) ", 
                                     font=('Arial', 11, 'bold'), bg='#ecf0f1', fg='#2c3e50')
        filter_frame.pack(fill=tk.X, padx=10, pady=5)
        
        filter_inner = tk.Frame(filter_frame, bg='#ecf0f1')
        filter_inner.pack(fill=tk.X, padx=5, pady=5)
        
        self.filter_checkbox = tk.Checkbutton(filter_inner, text="Enable Filters", 
                                             variable=self.filter_enabled,
                                             command=self.apply_filters,
                                             bg='#ecf0f1', font=('Arial', 10, 'bold'))
        self.filter_checkbox.pack(side=tk.LEFT, padx=5)
        
        tk.Label(filter_inner, text="Method:", bg='#ecf0f1', font=('Arial', 10)).pack(side=tk.LEFT, padx=(15, 5))
        method_combo = ttk.Combobox(filter_inner, textvariable=self.filter_method, 
                                   values=["All", "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"],
                                   width=10, state='readonly')
        method_combo.pack(side=tk.LEFT, padx=5)
        method_combo.bind('<<ComboboxSelected>>', lambda e: self.apply_filters())
        
        tk.Label(filter_inner, text="Source IP:", bg='#ecf0f1', font=('Arial', 10)).pack(side=tk.LEFT, padx=(15, 5))
        src_ip_entry = tk.Entry(filter_inner, textvariable=self.filter_src_ip, width=15, font=('Arial', 10))
        src_ip_entry.pack(side=tk.LEFT, padx=5)
        src_ip_entry.bind('<Return>', lambda e: self.apply_filters())
        
        tk.Label(filter_inner, text="Dest IP:", bg='#ecf0f1', font=('Arial', 10)).pack(side=tk.LEFT, padx=(15, 5))
        dest_ip_entry = tk.Entry(filter_inner, textvariable=self.filter_dest_ip, width=15, font=('Arial', 10))
        dest_ip_entry.pack(side=tk.LEFT, padx=5)
        dest_ip_entry.bind('<Return>', lambda e: self.apply_filters())
        
        tk.Button(filter_inner, text="Apply", command=self.apply_filters,
                 bg='#3498db', fg='white', font=('Arial', 9, 'bold'),
                 padx=15, pady=3, relief=tk.RAISED, cursor='hand2').pack(side=tk.LEFT, padx=5)
        
        tk.Button(filter_inner, text="Clear", command=self.clear_filters,
                 bg='#95a5a6', fg='white', font=('Arial', 9, 'bold'),
                 padx=15, pady=3, relief=tk.RAISED, cursor='hand2').pack(side=tk.LEFT, padx=5)
        
        self.filter_status_label = tk.Label(filter_inner, text="Filters: Disabled", 
                                           bg='#ecf0f1', font=('Arial', 9, 'italic'))
        self.filter_status_label.pack(side=tk.LEFT, padx=15)
        
        # Main notebook
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Requests tab
        req_frame = tk.Frame(notebook)
        notebook.add(req_frame, text='HTTP Requests')
        
        tree_frame = tk.Frame(req_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.request_tree = ttk.Treeview(tree_frame, 
                                        columns=('Time', 'Method', 'URL', 'Source', 'Destination'),
                                        show='tree headings', height=12)
        
        self.request_tree.heading('#0', text='#')
        self.request_tree.heading('Time', text='Timestamp')
        self.request_tree.heading('Method', text='Method')
        self.request_tree.heading('URL', text='URL')
        self.request_tree.heading('Source', text='Source IP:Port')
        self.request_tree.heading('Destination', text='Destination IP:Port')
        
        self.request_tree.column('#0', width=50)
        self.request_tree.column('Time', width=150)
        self.request_tree.column('Method', width=80)
        self.request_tree.column('URL', width=350)
        self.request_tree.column('Source', width=180)
        self.request_tree.column('Destination', width=180)
        
        req_scroll = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.request_tree.yview)
        self.request_tree.configure(yscrollcommand=req_scroll.set)
        
        self.request_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        req_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        tk.Label(req_frame, text="Request Details:", font=('Arial', 10, 'bold')).pack(anchor=tk.W, padx=5)
        
        self.request_detail = scrolledtext.ScrolledText(req_frame, height=10, font=('Courier', 9))
        self.request_detail.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.request_tree.bind('<<TreeviewSelect>>', self.on_request_select)
        
        # Responses tab
        resp_frame = tk.Frame(notebook)
        notebook.add(resp_frame, text='HTTP Responses')
        
        resp_tree_frame = tk.Frame(resp_frame)
        resp_tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.response_tree = ttk.Treeview(resp_tree_frame,
                                         columns=('Time', 'Status', 'Source', 'Destination'),
                                         show='tree headings', height=12)
        
        self.response_tree.heading('#0', text='#')
        self.response_tree.heading('Time', text='Timestamp')
        self.response_tree.heading('Status', text='Status')
        self.response_tree.heading('Source', text='Source IP:Port')
        self.response_tree.heading('Destination', text='Destination IP:Port')
        
        self.response_tree.column('#0', width=50)
        self.response_tree.column('Time', width=150)
        self.response_tree.column('Status', width=250)
        self.response_tree.column('Source', width=220)
        self.response_tree.column('Destination', width=220)
        
        resp_scroll = ttk.Scrollbar(resp_tree_frame, orient=tk.VERTICAL, command=self.response_tree.yview)
        self.response_tree.configure(yscrollcommand=resp_scroll.set)
        
        self.response_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        resp_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        tk.Label(resp_frame, text="Response Details:", font=('Arial', 10, 'bold')).pack(anchor=tk.W, padx=5)
        
        self.response_detail = scrolledtext.ScrolledText(resp_frame, height=10, font=('Courier', 9))
        self.response_detail.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.response_tree.bind('<<TreeviewSelect>>', self.on_response_select)
        
        # Logs tab
        log_frame = tk.Frame(notebook)
        notebook.add(log_frame, text='Logs')
        
        self.log_text = scrolledtext.ScrolledText(log_frame, font=('Courier', 9))
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Status bar
        status_frame = tk.Frame(self.root, bg='#34495e', height=25)
        status_frame.pack(fill=tk.X, side=tk.BOTTOM)
        status_frame.pack_propagate(False)
        
        self.status_label = tk.Label(status_frame, text="Status: Idle", 
                                     bg='#34495e', fg='white', font=('Arial', 9))
        self.status_label.pack(side=tk.LEFT, padx=10)
    
    def start_capture(self):
        """Start packet capture"""
        if self.sniffer_thread and self.sniffer_thread.is_alive():
            return
        
        self.log_message("[+] Starting packet capture...")
        self.status_label.config(text="Status: Capturing...")
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        
        self.sniffer = PacketSniffer(gui_queue=self.queue)
        self.sniffer_thread = threading.Thread(target=self.sniffer.capture_packets, daemon=True)
        self.sniffer_thread.start()
    
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
    
    def matches_filter(self, packet_info, packet_type='request'):
        """Check if packet matches filter"""
        if not self.filter_enabled.get():
            return True
        
        if packet_type == 'request':
            method_filter = self.filter_method.get()
            if method_filter != "All" and packet_info['http_method'] != method_filter:
                return False
            
            src_ip_filter = self.filter_src_ip.get().strip()
            if src_ip_filter and src_ip_filter not in packet_info['src_ip']:
                return False
            
            dest_ip_filter = self.filter_dest_ip.get().strip()
            if dest_ip_filter and dest_ip_filter not in packet_info['dest_ip']:
                return False
        
        elif packet_type == 'response':
            src_ip_filter = self.filter_src_ip.get().strip()
            if src_ip_filter and src_ip_filter not in packet_info['src_ip']:
                return False
            
            dest_ip_filter = self.filter_dest_ip.get().strip()
            if dest_ip_filter and dest_ip_filter not in packet_info['dest_ip']:
                return False
        
        return True
    
    def apply_filters(self):
        """Apply filters"""
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
        
        self.refresh_filtered_display()
    
    def clear_filters(self):
        """Clear filters"""
        self.filter_method.set("All")
        self.filter_src_ip.set("")
        self.filter_dest_ip.set("")
        self.filter_enabled.set(False)
        self.apply_filters()
    
    def refresh_filtered_display(self):
        """Refresh display with filters"""
        all_request_data = dict(self.request_data)
        all_response_data = dict(self.response_data)
        
        self.request_tree.delete(*self.request_tree.get_children())
        self.response_tree.delete(*self.response_tree.get_children())
        self.request_data.clear()
        self.response_data.clear()
        
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
                                                    values=(timestamp, status,
                                                           f"{packet_info['src_ip']}:{packet_info['src_port']}",
                                                           f"{packet_info['dest_ip']}:{packet_info['dest_port']}"))
                self.response_data[new_item] = packet_info
        
        self.log_message(f"[*] Filtered: {req_count} requests, {resp_count} responses")
    
    def log_message(self, message):
        """Add log message"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)
    
    def update_stats(self):
        """Update stats"""
        total = self.request_count + self.response_count
        self.stats_label.config(text=f"Requests: {self.request_count} | Responses: {self.response_count} | Total: {total}")
    
    def on_request_select(self, event):
        """Handle request selection"""
        selection = self.request_tree.selection()
        if selection:
            item = selection[0]
            if item in self.request_data:
                self.display_request_details(self.request_data[item])
    
    def on_response_select(self, event):
        """Handle response selection"""
        selection = self.response_tree.selection()
        if selection:
            item = selection[0]
            if item in self.response_data:
                self.display_response_details(self.response_data[item])
    
    def display_request_details(self, packet_info):
        """Display request details"""
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
        """Display response details"""
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
        """Process queue messages"""
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
        
        self.root.after(100, self.process_queue)
    
    def add_request(self, packet_info):
        """Add request to tree"""
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
        self.request_tree.see(item)
    
    def add_response(self, packet_info):
        """Add response to tree"""
        if not self.matches_filter(packet_info, 'response'):
            return
        
        self.response_count += 1
        timestamp = packet_info['timestamp'].strftime('%H:%M:%S.%f')[:-3]
        status = f"{packet_info['http_status_code']} {packet_info['http_status_text']}"
        
        item = self.response_tree.insert('', tk.END, text=str(self.response_count),
                                        values=(timestamp, status,
                                               f"{packet_info['src_ip']}:{packet_info['src_port']}",
                                               f"{packet_info['dest_ip']}:{packet_info['dest_port']}"))
        
        self.response_data[item] = packet_info
        self.update_stats()
        self.response_tree.see(item)
    
    def run(self):
        """Run GUI"""
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.root.mainloop()
    
    def on_closing(self):
        """Handle window close"""
        if self.sniffer:
            self.sniffer.stop()
        self.root.destroy()


def main():
    print("="*80)
    print(" HTTP PACKET SNIFFER - Phase 4: Request Filtering")
    print("="*80)
    print("\nStarting simplified stable GUI...")
    print("Features: Real-time capture, filtering by method and IP addresses")
    print("Note: Python3 has been granted raw socket capabilities.\n")
    
    app = HTTPSnifferGUI()
    app.run()

if __name__ == "__main__":
    main()

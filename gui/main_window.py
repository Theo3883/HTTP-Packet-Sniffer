"""Main GUI window implementing MVC pattern."""

import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import queue
from datetime import datetime

from core import PacketSniffer
from models import HTTPRequestInfo, HTTPResponseInfo
from filters import FilterManager, MethodFilter, IPFilter, CompositeFilter
from config import SnifferConfig


class HTTPSnifferGUI:
    """
    Main GUI window for HTTP packet sniffer.
    
    Implements MVC pattern:
    - Model: PacketSniffer and packet data
    - View: Tkinter widgets
    - Controller: Event handlers and business logic
    """
    
    def __init__(self):
        """Initialize the GUI."""
        self.root = tk.Tk()
        self.root.title("HTTP Packet Sniffer")
        self.root.geometry("1400x900")
        
        # Model components
        self.queue = queue.Queue(maxsize=5000)  # Large queue to buffer bursts
        self.sniffer = None
        self.sniffer_thread = None
        self.filter_manager = FilterManager()
        
        # Data storage
        self.request_data = {}
        self.response_data = {}
        self.request_count = 0
        self.response_count = 0
        
        # Filter settings (View state)
        self.filter_method = tk.StringVar(value="All")
        self.filter_src_ip = tk.StringVar(value="")
        self.filter_dest_ip = tk.StringVar(value="")
        self.filter_enabled = tk.BooleanVar(value=False)
        
        self._setup_ui()
        self._process_queue()
    
    def _setup_ui(self):
        """Create the GUI interface."""
        self._create_title_bar()
        self._create_control_panel()
        self._create_filter_panel()
        self._create_main_notebook()
        self._create_status_bar()
    
    def _create_title_bar(self):
        """Create title bar."""
        title_frame = tk.Frame(self.root, bg='#2c3e50', height=60)
        title_frame.pack(fill=tk.X)
        title_frame.pack_propagate(False)
        
        title_label = tk.Label(title_frame, text="HTTP Packet Sniffer", 
                              bg='#2c3e50', fg='white', font=('Arial', 18, 'bold'))
        title_label.pack(pady=15)
    
    def _create_control_panel(self):
        """Create control panel with start/stop buttons."""
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
        
        # Console output button
        self.console_button = tk.Button(control_frame, text="Print to Console", command=self.print_selected_to_console,
                                       bg='#9b59b6', fg='white', font=('Arial', 11, 'bold'),
                                       padx=20, pady=8, relief=tk.RAISED, cursor='hand2')
        self.console_button.pack(side=tk.LEFT, padx=5, pady=8)
        
        # Stats label
        self.stats_label = tk.Label(control_frame, text="Requests: 0 | Responses: 0 | Total: 0 | Rate: 0/s", 
                                    bg='#ecf0f1', font=('Arial', 10, 'bold'))
        self.stats_label.pack(side=tk.RIGHT, padx=10)
    
    def _create_filter_panel(self):
        """Create filter panel."""
        filter_frame = tk.LabelFrame(self.root, text=" Filters ", 
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
    
    def _create_main_notebook(self):
        """Create main notebook with tabs."""
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Requests tab
        self._create_requests_tab(notebook)
        
        # Responses tab
        self._create_responses_tab(notebook)
        
        # Logs tab
        self._create_logs_tab(notebook)
    
    def _create_requests_tab(self, notebook):
        """Create requests tab."""
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
    
    def _create_responses_tab(self, notebook):
        """Create responses tab."""
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
    
    def _create_logs_tab(self, notebook):
        """Create logs tab."""
        log_frame = tk.Frame(notebook)
        notebook.add(log_frame, text='Logs')
        
        self.log_text = scrolledtext.ScrolledText(log_frame, font=('Courier', 9))
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def _create_status_bar(self):
        """Create status bar."""
        status_frame = tk.Frame(self.root, bg='#34495e', height=25)
        status_frame.pack(fill=tk.X, side=tk.BOTTOM)
        status_frame.pack_propagate(False)
        
        self.status_label = tk.Label(status_frame, text="Status: Idle", 
                                     bg='#34495e', fg='white', font=('Arial', 9))
        self.status_label.pack(side=tk.LEFT, padx=10)
    
    # Controller methods
    
    def start_capture(self):
        """Start packet capture."""
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
        """Stop packet capture."""
        if self.sniffer:
            self.log_message("[+] Stopping packet capture...")
            self.sniffer.stop()
            self.status_label.config(text="Status: Stopped")
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
    
    def clear_displays(self):
        """Clear all displays."""
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
    
    def apply_filters(self):
        """Apply filters using filter manager."""
        self.filter_manager.set_enabled(self.filter_enabled.get())
        
        if self.filter_enabled.get():
            # Create composite filter
            composite = CompositeFilter()
            composite.add_filter(MethodFilter(self.filter_method.get()))
            composite.add_filter(IPFilter(self.filter_src_ip.get(), self.filter_dest_ip.get()))
            
            self.filter_manager.set_filter(composite)
            
            # Update status
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
        """Clear all filters."""
        self.filter_method.set("All")
        self.filter_src_ip.set("")
        self.filter_dest_ip.set("")
        self.filter_enabled.set(False)
        self.apply_filters()
    
    def refresh_filtered_display(self):
        """Refresh display with current filters."""
        all_request_data = dict(self.request_data)
        all_response_data = dict(self.response_data)
        
        self.request_tree.delete(*self.request_tree.get_children())
        self.response_tree.delete(*self.response_tree.get_children())
        self.request_data.clear()
        self.response_data.clear()
        
        req_count = 0
        for item_id, packet_info in all_request_data.items():
            if self.filter_manager.matches(packet_info, 'request'):
                req_count += 1
                timestamp = packet_info.timestamp.strftime('%H:%M:%S.%f')[:-3]
                new_item = self.request_tree.insert('', tk.END, text=str(req_count),
                                                   values=(timestamp,
                                                          packet_info.http_method,
                                                          packet_info.http_uri[:SnifferConfig.MAX_URL_DISPLAY_LENGTH],
                                                          f"{packet_info.src_ip}:{packet_info.src_port}",
                                                          f"{packet_info.dest_ip}:{packet_info.dest_port}"))
                self.request_data[new_item] = packet_info
        
        resp_count = 0
        for item_id, packet_info in all_response_data.items():
            if self.filter_manager.matches(packet_info, 'response'):
                resp_count += 1
                timestamp = packet_info.timestamp.strftime('%H:%M:%S.%f')[:-3]
                status = packet_info.get_status_line()
                new_item = self.response_tree.insert('', tk.END, text=str(resp_count),
                                                    values=(timestamp, status,
                                                           f"{packet_info.src_ip}:{packet_info.src_port}",
                                                           f"{packet_info.dest_ip}:{packet_info.dest_port}"))
                self.response_data[new_item] = packet_info
        
        self.log_message(f"[*] Filtered: {req_count} requests, {resp_count} responses")
    
    def log_message(self, message: str):
        """Add log message to log text widget."""
        timestamp = datetime.now().strftime('%H:%M:%S')
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)
    
    def update_stats(self):
        """Update statistics display with performance metrics."""
        total = self.request_count + self.response_count
        
        # Get performance stats if sniffer is running
        rate_str = "0/s"
        if self.sniffer:
            try:
                stats = self.sniffer.get_performance_stats()
                rate = stats.get('packets_per_second', 0)
                rate_str = f"{rate:.1f}/s"
            except:
                pass
        
        self.stats_label.config(
            text=f"Requests: {self.request_count} | Responses: {self.response_count} | "
                 f"Total: {total} | Rate: {rate_str}"
        )
    
    def on_request_select(self, event):
        """Handle request selection."""
        selection = self.request_tree.selection()
        if selection:
            item = selection[0]
            if item in self.request_data:
                self.display_request_details(self.request_data[item])
    
    def on_response_select(self, event):
        """Handle response selection."""
        selection = self.response_tree.selection()
        if selection:
            item = selection[0]
            if item in self.response_data:
                self.display_response_details(self.response_data[item])
    
    def display_request_details(self, packet_info: HTTPRequestInfo):
        """Display request details."""
        self.request_detail.delete('1.0', tk.END)
        
        details = f"HTTP Request Details\n{'='*60}\n\n"
        
        # Request Line
        details += f"Request Line:\n"
        details += f"  {packet_info.http_method} {packet_info.http_uri} {packet_info.http_version}\n\n"
        
        # Timestamp and Network Info
        details += f"Timestamp: {packet_info.timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}\n\n"
        
        details += f"Network Information:\n"
        details += f"  Source MAC:        {packet_info.src_mac}\n"
        details += f"  Destination MAC:   {packet_info.dest_mac}\n"
        details += f"  Source IP:Port:    {packet_info.src_ip}:{packet_info.src_port}\n"
        details += f"  Destination IP:Port: {packet_info.dest_ip}:{packet_info.dest_port}\n\n"
        
        # TCP Metadata
        details += f"TCP Metadata:\n"
        details += f"  Sequence Number:   {packet_info.sequence}\n"
        details += f"  Acknowledgment:    {packet_info.acknowledgment}\n"
        details += f"  Flags:             {packet_info.get_tcp_flags()}\n\n"
        
        # HTTP Headers
        if packet_info.http_headers:
            details += f"HTTP Headers: ({len(packet_info.http_headers)} headers)\n"
            for key, value in sorted(packet_info.http_headers.items()):
                details += f"  {key}: {value}\n"
            details += "\n"
        
        # Request Body/Payload
        if packet_info.http_body:
            details += f"Request Body/Payload:\n"
            details += f"{'-'*60}\n"
            details += f"{packet_info.http_body}\n"
            details += f"{'-'*60}\n"
        else:
            details += f"Request Body: (empty)\n"
        
        self.request_detail.insert('1.0', details)
    
    def display_response_details(self, packet_info: HTTPResponseInfo):
        """Display response details."""
        self.response_detail.delete('1.0', tk.END)
        
        details = f"HTTP Response Details\n{'='*60}\n\n"
        
        # Status Line
        details += f"Status Line:\n"
        details += f"  {packet_info.http_version} {packet_info.get_status_line()}\n\n"
        
        # Timestamp and Network Info
        details += f"Timestamp: {packet_info.timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}\n\n"
        
        details += f"Network Information:\n"
        details += f"  Source IP:Port:    {packet_info.src_ip}:{packet_info.src_port}\n"
        details += f"  Destination IP:Port: {packet_info.dest_ip}:{packet_info.dest_port}\n\n"
        
        # HTTP Headers
        if packet_info.http_headers:
            details += f"HTTP Headers: ({len(packet_info.http_headers)} headers)\n"
            for key, value in sorted(packet_info.http_headers.items()):
                details += f"  {key}: {value}\n"
            details += "\n"
        
        # Response Body
        if packet_info.http_body:
            details += f"Response Body:\n"
            details += f"{'-'*60}\n"
            details += f"{packet_info.http_body}\n"
            details += f"{'-'*60}\n"
        else:
            details += f"Response Body: (empty or not captured)\n"
        
        self.response_detail.insert('1.0', details)
    
    def print_selected_to_console(self):
        """Print selected packet details to console."""
        # Check if request is selected
        request_selection = self.request_tree.selection()
        if request_selection:
            item = request_selection[0]
            if item in self.request_data:
                packet_info = self.request_data[item]
                packet_info.print_console_details()
                self.log_message("[*] Request details printed to console")
                return
        
        # Check if response is selected
        response_selection = self.response_tree.selection()
        if response_selection:
            item = response_selection[0]
            if item in self.response_data:
                packet_info = self.response_data[item]
                packet_info.print_console_details()
                self.log_message("[*] Response details printed to console")
                return
        
        # Nothing selected
        self.log_message("[!] No packet selected. Please select a request or response first.")
    
    def _process_queue(self):
        """Process messages from queue (batch processing for performance)."""
        batch_count = 0
        max_batch = 50  # Process up to 50 items per cycle
        
        try:
            while batch_count < max_batch:
                msg_type, data = self.queue.get_nowait()
                
                if msg_type == 'log':
                    self.log_message(data)
                elif msg_type == 'request':
                    self.add_request(data)
                elif msg_type == 'response':
                    self.add_response(data)
                
                batch_count += 1
        except queue.Empty:
            pass
        
        self.root.after(SnifferConfig.GUI_UPDATE_INTERVAL_MS, self._process_queue)
    
    def add_request(self, packet_info: HTTPRequestInfo):
        """Add request to tree view."""
        if not self.filter_manager.matches(packet_info, 'request'):
            return
        
        self.request_count += 1
        timestamp = packet_info.timestamp.strftime('%H:%M:%S.%f')[:-3]
        
        item = self.request_tree.insert('', tk.END, text=str(self.request_count),
                                       values=(timestamp,
                                              packet_info.http_method,
                                              packet_info.http_uri[:SnifferConfig.MAX_URL_DISPLAY_LENGTH],
                                              f"{packet_info.src_ip}:{packet_info.src_port}",
                                              f"{packet_info.dest_ip}:{packet_info.dest_port}"))
        
        self.request_data[item] = packet_info
        self.update_stats()
        self.request_tree.see(item)
    
    def add_response(self, packet_info: HTTPResponseInfo):
        """Add response to tree view."""
        if not self.filter_manager.matches(packet_info, 'response'):
            return
        
        self.response_count += 1
        timestamp = packet_info.timestamp.strftime('%H:%M:%S.%f')[:-3]
        status = packet_info.get_status_line()
        
        item = self.response_tree.insert('', tk.END, text=str(self.response_count),
                                        values=(timestamp, status,
                                               f"{packet_info.src_ip}:{packet_info.src_port}",
                                               f"{packet_info.dest_ip}:{packet_info.dest_port}"))
        
        self.response_data[item] = packet_info
        self.update_stats()
        self.response_tree.see(item)
    
    def run(self):
        """Run the GUI main loop."""
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.root.mainloop()
    
    def on_closing(self):
        """Handle window close event."""
        if self.sniffer:
            self.sniffer.stop()
        self.root.destroy()

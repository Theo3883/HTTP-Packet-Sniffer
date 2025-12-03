"""Packet sniffer core module"""

import socket
import sys
from datetime import datetime
from queue import Queue
from typing import Optional, Callable

from models import HTTPRequestInfo, HTTPResponseInfo
from parsers import EthernetParser, IPv4Parser, TCPParser, HTTPParser
from config import SnifferConfig
from utils import PerformanceMonitor, ErrorHandler, RateLimiter


class PacketSniffer:
    """
    Packet sniffer that captures and parses HTTP traffic.

    """
    
    def __init__(
        self,
        gui_queue: Optional[Queue] = None,
        ethernet_parser: Optional[EthernetParser] = None,
        ipv4_parser: Optional[IPv4Parser] = None,
        tcp_parser: Optional[TCPParser] = None,
        http_parser: Optional[HTTPParser] = None
    ):
        """
        Initialize the packet sniffer with optional parser dependencies.
        
        Args:
            gui_queue: Queue for sending data to GUI
            ethernet_parser: Parser for Ethernet frames
            ipv4_parser: Parser for IPv4 headers
            tcp_parser: Parser for TCP headers
            http_parser: Parser for HTTP messages
        """
        self.gui_queue = gui_queue
        self.running = False
        
        # Dependency injection with defaults
        self.ethernet_parser = ethernet_parser or EthernetParser()
        self.ipv4_parser = ipv4_parser or IPv4Parser()
        self.tcp_parser = tcp_parser or TCPParser()
        self.http_parser = http_parser or HTTPParser()
        
        # Statistics
        self.http_request_count = 0
        self.http_response_count = 0
        self.total_http_packets = 0
        
        # Performance monitoring 
        self.performance_monitor = PerformanceMonitor()
        self.error_handler = ErrorHandler()
        self.gui_rate_limiter = RateLimiter(max_per_second=200)  # Limit GUI updates
        
        # Initialize socket
        self._init_socket()
    
    def _init_socket(self) -> None:
        """Initialize raw socket for packet capture."""
        try:
            self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            self.log("[+] Raw socket created successfully")
            self.log("[+] Starting HTTP packet capture...")
        except PermissionError:
            error_msg = "[-] Error: Root privileges required to create raw socket"
            self.log(error_msg)
            sys.exit(1)
        except Exception as e:
            error_msg = f"[-] Error creating socket: {e}"
            self.log(error_msg)
            sys.exit(1)
    
    def log(self, message: str) -> None:
        """
        Send log message to GUI queue or print to console.
        
        Args:
            message: Log message to send
        """
        if self.gui_queue:
            self.gui_queue.put(('log', message))
        else:
            print(message)
    
    def stop(self) -> None:
        """Stop the packet capture."""
        self.running = False
        if self.socket:
            self.socket.close()
    
    def capture_packets(self) -> None:
        """
        Main packet capture loop.
        
        Captures raw packets and processes them through the parsing pipeline.
        """
        packet_count = 0
        tcp_count = 0
        
        self.running = True
        self.log(f"[*] Monitoring HTTP traffic on ports: {SnifferConfig.get_http_ports_display()}")
        self.log(f"[*] Note: HTTPS (port {SnifferConfig.HTTPS_PORT}) traffic is encrypted and won't be visible")
        
        try:
            while self.running:
                try:
                    raw_data, addr = self.socket.recvfrom(SnifferConfig.SOCKET_BUFFER_SIZE)
                    packet_count += 1
                    self.performance_monitor.increment_packets()
                    
                    # Parse Ethernet frame
                    dest_mac, src_mac, eth_proto, data = self.ethernet_parser.parse(raw_data)
                    
                    # Check if IPv4
                    if eth_proto == SnifferConfig.ETH_PROTOCOL_IP:
                        version, header_length, ttl, proto, src_ip, dest_ip, data = self.ipv4_parser.parse(data)
                        
                        # Check if TCP
                        if proto == SnifferConfig.IP_PROTOCOL_TCP:
                            tcp_count += 1
                            (src_port, dest_port, sequence, acknowledgment,
                             flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin,
                             payload) = self.tcp_parser.parse(data)
                            
                            # Process HTTP traffic
                            if self._is_http_port(src_port, dest_port) and len(payload) > 0:
                                self._process_http_payload(
                                    payload, src_mac, dest_mac, src_ip, dest_ip,
                                    src_port, dest_port, sequence, acknowledgment,
                                    flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin
                                )
                except Exception as e:
                    # Log parsing errors but continue capture
                    self.performance_monitor.increment_errors()
                    self.error_handler.log_error('parse_error', str(e), {'packet_count': packet_count})
                    continue
        
        except KeyboardInterrupt:
            self.log(f"\n[+] Capture stopped")
            self.log(f"Total packets: {packet_count}, TCP: {tcp_count}, HTTP: {self.total_http_packets}")
            self.socket.close()
        except Exception as e:
            self.log(f"\n[-] Error during packet capture: {e}")
            if self.socket:
                self.socket.close()
    
    def _is_http_port(self, src_port: int, dest_port: int) -> bool:
        """Check if either port is an HTTP port."""
        return src_port in SnifferConfig.HTTP_PORTS or dest_port in SnifferConfig.HTTP_PORTS
    
    def _process_http_payload(
        self,
        payload: bytes,
        src_mac: str,
        dest_mac: str,
        src_ip: str,
        dest_ip: str,
        src_port: int,
        dest_port: int,
        sequence: int,
        acknowledgment: int,
        flag_urg: int,
        flag_ack: int,
        flag_psh: int,
        flag_rst: int,
        flag_syn: int,
        flag_fin: int
    ) -> None:
        """Process HTTP payload and check for requests/responses."""
        # Check for HTTP request
        is_request, method, uri, version, headers, body = self.http_parser.is_http_request(payload)
        if is_request:
            self.http_request_count += 1
            self.total_http_packets += 1
            
            request_info = HTTPRequestInfo(
                timestamp=datetime.now(),
                src_mac=src_mac,
                dest_mac=dest_mac,
                src_ip=src_ip,
                dest_ip=dest_ip,
                src_port=src_port,
                dest_port=dest_port,
                sequence=sequence,
                acknowledgment=acknowledgment,
                flag_urg=flag_urg,
                flag_ack=flag_ack,
                flag_psh=flag_psh,
                flag_rst=flag_rst,
                flag_syn=flag_syn,
                flag_fin=flag_fin,
                http_method=method,
                http_uri=uri,
                http_version=version,
                http_headers=headers,
                http_body=body
            )
            self._send_request(request_info)
        
        # Check for HTTP response
        is_response, version, status_code, status_text, headers, body = self.http_parser.is_http_response(payload)
        if is_response:
            self.http_response_count += 1
            self.total_http_packets += 1
            
            response_info = HTTPResponseInfo(
                timestamp=datetime.now(),
                src_ip=src_ip,
                dest_ip=dest_ip,
                src_port=src_port,
                dest_port=dest_port,
                http_version=version,
                http_status_code=status_code,
                http_status_text=status_text,
                http_headers=headers,
                http_body=body
            )
            self._send_response(response_info)
    
    def _send_request(self, request_info: HTTPRequestInfo) -> None:
        """Send HTTP request data to GUI."""
        if self.gui_queue:
            try:
                # Use blocking put with short timeout to avoid packet loss
                self.gui_queue.put(('request', request_info), block=True, timeout=0.1)
            except Exception as e:
                # Queue full after timeout - packet will be dropped
                self.error_handler.log_error('queue_full', str(e), {'type': 'request'})
    
    def _send_response(self, response_info: HTTPResponseInfo) -> None:
        """Send HTTP response data to GUI."""
        if self.gui_queue:
            try:
                # Use blocking put with short timeout to avoid packet loss
                self.gui_queue.put(('response', response_info), block=True, timeout=0.1)
            except Exception as e:
                # Queue full after timeout - packet will be dropped
                self.error_handler.log_error('queue_full', str(e), {'type': 'response'})
    
    def get_performance_stats(self) -> dict:
        """Get current performance statistics."""
        stats = self.performance_monitor.get_stats()
        stats['http_requests'] = self.http_request_count
        stats['http_responses'] = self.http_response_count
        stats['total_http'] = self.total_http_packets
        stats['error_count'] = self.error_handler.get_error_count()
        return stats

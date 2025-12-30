"""Packet sniffer core module.

Provides the PacketSniffer class which captures raw packets and parses
HTTP traffic. The sniffer is designed for dependency injection of
protocol parsers and includes statistics and performance monitoring
helpers. Key responsibilities:

- Initialize raw socket for packet capture
- Parse Ethernet / IPv4 / TCP layers
- Identify and parse HTTP requests and responses
- Send parsed objects to a GUI queue for display
"""

import socket
import sys
from datetime import datetime
from queue import Queue
from typing import Optional

from models import HTTPRequestInfo, HTTPResponseInfo
from parsers import EthernetParser, IPv4Parser, TCPParser, HTTPParser
from config import SnifferConfig
from utils import PerformanceMonitor, ErrorHandler, RateLimiter


class PacketSniffer:
    """Packet sniffer that captures and parses HTTP traffic.

    The sniffer coordinates the packet processing pipeline. It accepts
    optional parser instances for ethernet, ipv4, tcp and http so that
    callers can inject mocks for testing.

    Attributes:
        gui_queue (Optional[Queue]): Queue for GUI messages.
        running (bool): True when capture loop is active.
        ethernet_parser, ipv4_parser, tcp_parser, http_parser: Parser
            instances used to decode each protocol layer.
        http_request_count, http_response_count, total_http_packets:
            Counters for HTTP statistics.
        performance_monitor (PerformanceMonitor): Tracks performance
            metrics such as packets/sec and errors.
        error_handler (ErrorHandler): Centralized error logging.
        gui_rate_limiter (RateLimiter): Limits GUI update rate.
    """
    
    def __init__(
        self,
        gui_queue: Optional[Queue] = None,
        ethernet_parser: Optional[EthernetParser] = None,
        ipv4_parser: Optional[IPv4Parser] = None,
        tcp_parser: Optional[TCPParser] = None,
        http_parser: Optional[HTTPParser] = None
    ):
        """Initialize the packet sniffer with optional parser dependencies.

        Args:
            gui_queue (Optional[Queue]): Queue for sending data to GUI.
            ethernet_parser (Optional[EthernetParser]): Parser for Ethernet frames.
            ipv4_parser (Optional[IPv4Parser]): Parser for IPv4 headers.
            tcp_parser (Optional[TCPParser]): Parser for TCP headers.
            http_parser (Optional[HTTPParser]): Parser for HTTP messages.
        """
        self.gui_queue = gui_queue
        self.running = False
        
        self.ethernet_parser = ethernet_parser or EthernetParser()
        self.ipv4_parser = ipv4_parser or IPv4Parser()
        self.tcp_parser = tcp_parser or TCPParser()
        self.http_parser = http_parser or HTTPParser()

        self.http_request_count = 0
        self.http_response_count = 0
        self.total_http_packets = 0

        self.performance_monitor = PerformanceMonitor()
        self.error_handler = ErrorHandler()
        self.gui_rate_limiter = RateLimiter(max_per_second=200)

        self._init_socket()
    
    def _init_socket(self) -> None:
        """Initialize raw socket for packet capture.

        Exits the process on unrecoverable socket errors (for example,
        missing privileges to open a raw socket).
        """
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
        """Main packet capture loop.

        The pipeline steps are:
        1. Receive raw frame from socket
        2. Parse Ethernet frame
        3. If IPv4, parse IPv4 header
        4. If TCP, parse TCP header
        5. If ports indicate HTTP and payload exists, process HTTP payload
        
        Parsing errors are logged and do not stop the capture loop.
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
                    
                    dest_mac, src_mac, eth_proto, data = self.ethernet_parser.parse(raw_data)

                    if eth_proto == SnifferConfig.ETH_PROTOCOL_IP:
                        version, header_length, ttl, proto, src_ip, dest_ip, data = self.ipv4_parser.parse(data)

                        if proto == SnifferConfig.IP_PROTOCOL_TCP:
                            tcp_count += 1
                            (src_port, dest_port, sequence, acknowledgment,
                             flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin,
                             payload) = self.tcp_parser.parse(data)
                            
                            if self._is_http_port(src_port, dest_port) and len(payload) > 0:
                                self._process_http_payload(
                                    payload, src_mac, dest_mac, src_ip, dest_ip,
                                    src_port, dest_port, sequence, acknowledgment,
                                    flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin
                                )
                except Exception as e:
                    self.performance_monitor.increment_errors()
                    self.error_handler.log_error('parse_error', str(e), {'packet_count': packet_count})
                    continue
        
        except KeyboardInterrupt:
            self.log("\n[+] Capture stopped")
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
        """Process HTTP payload and check for requests/responses.

        This method uses the injected `http_parser` to determine whether the
        TCP payload contains an HTTP request or response, then wraps parsed
        data into model classes and forwards them to the GUI queue.
        """
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
        """Send HTTP request data to GUI.

        Uses a short blocking `put` to avoid dropping bursts when possible.
        If the queue remains full the packet is dropped and an error is logged.
        """
        if self.gui_queue:
            try:
                self.gui_queue.put(('request', request_info), block=True, timeout=0.1)
            except Exception as e:
                self.error_handler.log_error('queue_full', str(e), {'type': 'request'})
    
    def _send_response(self, response_info: HTTPResponseInfo) -> None:
        """Send HTTP response data to GUI.

        See `_send_request` for behavior when the GUI queue is full.
        """
        if self.gui_queue:
            try:
                self.gui_queue.put(('response', response_info), block=True, timeout=0.1)
            except Exception as e:
                self.error_handler.log_error('queue_full', str(e), {'type': 'response'})
    
    def get_performance_stats(self) -> dict:
        """Get current performance statistics."""
        stats = self.performance_monitor.get_stats()
        stats['http_requests'] = self.http_request_count
        stats['http_responses'] = self.http_response_count
        stats['total_http'] = self.total_http_packets
        stats['error_count'] = self.error_handler.get_error_count()
        return stats

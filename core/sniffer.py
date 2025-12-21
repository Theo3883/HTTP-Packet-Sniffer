"""Packet sniffer core module.

Provides the PacketSniffer class which captures raw packets and identifies
HTTP traffic. Phase 2 implementation focuses on HTTP packet identification.

Key responsibilities:
- Initialize raw socket for packet capture
- Parse Ethernet / IPv4 / TCP layers
- Identify HTTP requests by port and method
- Display HTTP requests in real-time
"""

import socket
import sys

from parsers import EthernetParser, IPv4Parser, TCPParser, HTTPParser
from config import SnifferConfig


class PacketSniffer:
    """Packet sniffer that captures and identifies HTTP traffic.

    The sniffer coordinates the packet processing pipeline. It uses
    protocol parsers to decode each layer and identifies HTTP requests.

    Attributes:
        running (bool): True when capture loop is active.
        ethernet_parser, ipv4_parser, tcp_parser, http_parser: Parser
            instances used to decode each protocol layer.
        http_request_count: Counter for HTTP requests identified.
    """
    
    def __init__(
        self,
        ethernet_parser: EthernetParser = None,
        ipv4_parser: IPv4Parser = None,
        tcp_parser: TCPParser = None,
        http_parser: HTTPParser = None
    ):
        """Initialize the packet sniffer with optional parser dependencies.

        Args:
            ethernet_parser: Parser for Ethernet frames.
            ipv4_parser: Parser for IPv4 headers.
            tcp_parser: Parser for TCP headers.
            http_parser: Parser for HTTP messages.
        """
        self.running = False
        
        self.ethernet_parser = ethernet_parser or EthernetParser()
        self.ipv4_parser = ipv4_parser or IPv4Parser()
        self.tcp_parser = tcp_parser or TCPParser()
        self.http_parser = http_parser or HTTPParser()

        self.http_request_count = 0

        self._init_socket()
    
    def _init_socket(self) -> None:
        """Initialize raw socket for packet capture.

        Exits the process on unrecoverable socket errors (for example,
        missing privileges to open a raw socket).
        """
        try:
            self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            self.log("[+] Raw socket created successfully")
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
        Send log message to console.
        
        Args:
            message: Log message to print
        """
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
        5. If ports indicate HTTP and payload exists, check for HTTP request
        
        Parsing errors are logged and do not stop the capture loop.
        """
        packet_count = 0
        tcp_count = 0
        
        self.running = True
        self.log(f"[*] Monitoring HTTP traffic on ports: {SnifferConfig.get_http_ports_display()}")
        self.log("[*] Press Ctrl+C to stop\n")
        
        try:
            while self.running:
                try:
                    raw_data, addr = self.socket.recvfrom(SnifferConfig.SOCKET_BUFFER_SIZE)
                    packet_count += 1
                    
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
                                    payload, src_ip, dest_ip, src_port, dest_port
                                )
                except Exception as e:
                    continue
        
        except KeyboardInterrupt:
            self.log("\n[+] Capture stopped")
            self.log(f"Total packets: {packet_count}, TCP: {tcp_count}, HTTP: {self.http_request_count}")
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
        src_ip: str,
        dest_ip: str,
        src_port: int,
        dest_port: int
    ) -> None:
        """Process HTTP payload and check for requests.

        This method uses the http_parser to determine whether the
        TCP payload contains an HTTP request and displays it.
        """
        is_request, method, uri, version = self.http_parser.is_http_request(payload)
        if is_request:
            self.http_request_count += 1
            self.log(f"[HTTP #{self.http_request_count}] {method} {uri} | {src_ip}:{src_port} -> {dest_ip}:{dest_port}")

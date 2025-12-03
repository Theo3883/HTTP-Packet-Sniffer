"""
Test suite for HTTP Packet Sniffer
"""

import unittest
from datetime import datetime
from models import HTTPRequestInfo, HTTPResponseInfo
from parsers import EthernetParser, IPv4Parser, TCPParser, HTTPParser
from filters import PacketFilter, MethodFilter, IPFilter, CompositeFilter, FilterManager
from utils import PacketBuffer, PerformanceMonitor, RateLimiter, ErrorHandler


class TestModels(unittest.TestCase):
    """Test data models."""
    
    def test_http_request_info_creation(self):
        """Test HTTPRequestInfo can be created with all fields."""
        request = HTTPRequestInfo(
            timestamp=datetime.now(),
            src_mac="aa:bb:cc:dd:ee:ff",
            dest_mac="11:22:33:44:55:66",
            src_ip="192.168.1.1",
            dest_ip="93.184.216.34",
            src_port=52341,
            dest_port=80,
            sequence=1234567890,
            acknowledgment=9876543210,
            flag_urg=0,
            flag_ack=1,
            flag_psh=1,
            flag_rst=0,
            flag_syn=0,
            flag_fin=0,
            http_method="GET",
            http_uri="/index.html",
            http_version="HTTP/1.1",
            http_headers={"Host": "example.com"},
            http_body=None
        )
        self.assertEqual(request.http_method, "GET")
        self.assertEqual(request.http_uri, "/index.html")
        self.assertEqual(request.get_tcp_flags(), "ACK, PSH")
    
    def test_http_response_info_creation(self):
        """Test HTTPResponseInfo can be created."""
        response = HTTPResponseInfo(
            timestamp=datetime.now(),
            src_ip="93.184.216.34",
            dest_ip="192.168.1.1",
            src_port=80,
            dest_port=52341,
            http_version="HTTP/1.1",
            http_status_code="200",
            http_status_text="OK",
            http_headers={"Content-Type": "text/html"},
            http_body="<html></html>"
        )
        self.assertEqual(response.get_status_line(), "200 OK")


class TestParsers(unittest.TestCase):
    """Test protocol parsers."""
    
    def test_ethernet_parser(self):
        """Test Ethernet frame parsing."""
        # Create mock Ethernet frame
        import struct
        frame = struct.pack('! 6s 6s H', 
                           b'\xaa\xbb\xcc\xdd\xee\xff',
                           b'\x11\x22\x33\x44\x55\x66',
                           0x0800) + b'payload'
        
        dest_mac, src_mac, proto, data = EthernetParser.parse(frame)
        self.assertEqual(dest_mac, 'aa:bb:cc:dd:ee:ff')
        self.assertEqual(src_mac, '11:22:33:44:55:66')
        self.assertEqual(data, b'payload')
    
    def test_http_parser_request(self):
        """Test HTTP request parsing."""
        payload = b"GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n"
        is_request, method, uri, version, headers, body = HTTPParser.is_http_request(payload)
        
        self.assertTrue(is_request)
        self.assertEqual(method, "GET")
        self.assertEqual(uri, "/test")
        self.assertEqual(version, "HTTP/1.1")
        self.assertIn("Host", headers)
    
    def test_http_parser_request_with_body(self):
        """Test HTTP request parsing with body."""
        payload = b"POST /api HTTP/1.1\r\nHost: example.com\r\n\r\n{\"test\":\"data\"}"
        is_request, method, uri, version, headers, body = HTTPParser.is_http_request(payload)
        
        self.assertTrue(is_request)
        self.assertEqual(method, "POST")
        self.assertIsNotNone(body)
        self.assertIn("test", body)
    
    def test_http_parser_response(self):
        """Test HTTP response parsing."""
        payload = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
        is_response, version, code, text, headers, body = HTTPParser.is_http_response(payload)
        
        self.assertTrue(is_response)
        self.assertEqual(version, "HTTP/1.1")
        self.assertEqual(code, "200")
        self.assertEqual(text, "OK")
        self.assertIn("Content-Type", headers)
    
    def test_http_parser_invalid_data(self):
        """Test HTTP parser with invalid data."""
        payload = b"INVALID DATA HERE"
        is_request, *_ = HTTPParser.is_http_request(payload)
        is_response, *_ = HTTPParser.is_http_response(payload)
        
        self.assertFalse(is_request)
        self.assertFalse(is_response)


class TestFilters(unittest.TestCase):
    """Test filtering system."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.request = HTTPRequestInfo(
            timestamp=datetime.now(),
            src_mac="aa:bb:cc:dd:ee:ff",
            dest_mac="11:22:33:44:55:66",
            src_ip="192.168.1.1",
            dest_ip="93.184.216.34",
            src_port=52341,
            dest_port=80,
            sequence=1,
            acknowledgment=1,
            flag_urg=0, flag_ack=1, flag_psh=1,
            flag_rst=0, flag_syn=0, flag_fin=0,
            http_method="GET",
            http_uri="/test",
            http_version="HTTP/1.1",
            http_headers={},
            http_body=None
        )
    
    def test_method_filter_match(self):
        """Test method filter matches correctly."""
        filter = MethodFilter("GET")
        self.assertTrue(filter.matches(self.request, 'request'))
    
    def test_method_filter_no_match(self):
        """Test method filter rejects non-matching."""
        filter = MethodFilter("POST")
        self.assertFalse(filter.matches(self.request, 'request'))
    
    def test_ip_filter_src_match(self):
        """Test IP filter matches source IP."""
        filter = IPFilter(src_ip="192.168.1")
        self.assertTrue(filter.matches(self.request, 'request'))
    
    def test_ip_filter_dest_match(self):
        """Test IP filter matches destination IP."""
        filter = IPFilter(dest_ip="93.184")
        self.assertTrue(filter.matches(self.request, 'request'))
    
    def test_ip_filter_no_match(self):
        """Test IP filter rejects non-matching."""
        filter = IPFilter(src_ip="10.0.0")
        self.assertFalse(filter.matches(self.request, 'request'))
    
    def test_composite_filter(self):
        """Test composite filter combines filters."""
        composite = CompositeFilter()
        composite.add_filter(MethodFilter("GET"))
        composite.add_filter(IPFilter(src_ip="192.168"))
        
        self.assertTrue(composite.matches(self.request, 'request'))
    
    def test_composite_filter_partial_match(self):
        """Test composite filter requires all filters to match."""
        composite = CompositeFilter()
        composite.add_filter(MethodFilter("GET"))
        composite.add_filter(IPFilter(src_ip="10.0.0"))
        
        self.assertFalse(composite.matches(self.request, 'request'))
    
    def test_filter_manager(self):
        """Test filter manager enable/disable."""
        manager = FilterManager()
        manager.set_filter(MethodFilter("POST"))
        
        # When disabled, should match all
        manager.set_enabled(False)
        self.assertTrue(manager.matches(self.request, 'request'))
        
        # When enabled, should apply filter
        manager.set_enabled(True)
        self.assertFalse(manager.matches(self.request, 'request'))


class TestPerformanceUtilities(unittest.TestCase):
    """Test performance and robustness utilities."""
    
    def test_packet_buffer_add(self):
        """Test packet buffer can add items."""
        buffer = PacketBuffer(maxlen=10)
        self.assertTrue(buffer.add("packet1"))
        self.assertEqual(buffer.size(), 1)
    
    def test_packet_buffer_overflow(self):
        """Test packet buffer handles overflow."""
        buffer = PacketBuffer(maxlen=3)
        buffer.add("p1")
        buffer.add("p2")
        buffer.add("p3")
        buffer.add("p4")  # Should drop oldest
        
        self.assertEqual(buffer.size(), 3)
    
    def test_performance_monitor(self):
        """Test performance monitor tracks stats."""
        monitor = PerformanceMonitor()
        monitor.increment_packets(10)
        monitor.increment_errors(2)
        
        stats = monitor.get_stats()
        self.assertEqual(stats['total_packets'], 10)
        self.assertEqual(stats['total_errors'], 2)
        self.assertGreater(stats['elapsed_time'], 0)
    
    def test_rate_limiter(self):
        """Test rate limiter controls rate."""
        limiter = RateLimiter(max_per_second=100)
        
        # First call should be allowed
        self.assertTrue(limiter.should_allow())
        
        # Immediate second call should be blocked
        self.assertFalse(limiter.should_allow())
    
    def test_error_handler(self):
        """Test error handler logs errors."""
        handler = ErrorHandler()
        handler.log_error('test_error', 'Test message', {'key': 'value'})
        
        self.assertEqual(handler.get_error_count(), 1)
        
        errors = handler.get_recent_errors(1)
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0]['type'], 'test_error')


class TestIntegration(unittest.TestCase):
    """Integration tests."""
    
    def test_end_to_end_parsing(self):
        """Test complete parsing pipeline."""
        # This would require more complex setup with actual packet data
        # For now, test individual components work together
        
        parser = HTTPParser()
        request_data = b"GET /api/users HTTP/1.1\r\nHost: example.com\r\n\r\n"
        
        is_request, method, uri, version, headers, body = parser.is_http_request(request_data)
        
        if is_request:
            request_info = HTTPRequestInfo(
                timestamp=datetime.now(),
                src_mac="00:00:00:00:00:00",
                dest_mac="00:00:00:00:00:00",
                src_ip="192.168.1.1",
                dest_ip="93.184.216.34",
                src_port=52341,
                dest_port=80,
                sequence=1,
                acknowledgment=1,
                flag_urg=0, flag_ack=1, flag_psh=1,
                flag_rst=0, flag_syn=0, flag_fin=0,
                http_method=method,
                http_uri=uri,
                http_version=version,
                http_headers=headers,
                http_body=body
            )
            
            # Test filtering
            filter_mgr = FilterManager()
            filter_mgr.set_enabled(True)
            filter_mgr.set_filter(MethodFilter("GET"))
            
            self.assertTrue(filter_mgr.matches(request_info, 'request'))


def run_tests():
    """Run all tests and display results."""
    print("="*70)
    print("HTTP PACKET SNIFFER - TEST SUITE")
    print("Phase 6: Testing, Performance, and Robustness")
    print("="*70)
    print()
    
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestModels))
    suite.addTests(loader.loadTestsFromTestCase(TestParsers))
    suite.addTests(loader.loadTestsFromTestCase(TestFilters))
    suite.addTests(loader.loadTestsFromTestCase(TestPerformanceUtilities))
    suite.addTests(loader.loadTestsFromTestCase(TestIntegration))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Summary
    print()
    print("="*70)
    print("TEST SUMMARY")
    print("="*70)
    print(f"Tests run: {result.testsRun}")
    print(f"Successes: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print()
    
    if result.wasSuccessful():
        print(" ALL TESTS PASSED!")
        print(" Phase 6: Testing complete")
        return 0
    else:
        print(" SOME TESTS FAILED")
        return 1


if __name__ == '__main__':
    exit(run_tests())

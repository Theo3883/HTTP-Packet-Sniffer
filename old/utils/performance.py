"""Performance and robustness utilities for packet sniffer."""

import threading
from collections import deque
from typing import Optional
import time


class PacketBuffer:
    """
    Thread-safe circular buffer for packet storage.
    
    Prevents memory overflow under high load by limiting buffer size.
    """
    
    def __init__(self, maxlen: int = 10000):
        """
        Initialize packet buffer.
        
        Args:
            maxlen: Maximum number of packets to store
        """
        self.buffer = deque(maxlen=maxlen)
        self.lock = threading.Lock()
        self.dropped_count = 0
    
    def add(self, packet) -> bool:
        """
        Add packet to buffer.
        
        Args:
            packet: Packet data to add
            
        Returns:
            True if added, False if buffer full
        """
        with self.lock:
            if len(self.buffer) >= self.buffer.maxlen:
                self.dropped_count += 1
                return False
            self.buffer.append(packet)
            return True
    
    def get_all(self) -> list:
        """Get all packets from buffer and clear it."""
        with self.lock:
            packets = list(self.buffer)
            self.buffer.clear()
            return packets
    
    def size(self) -> int:
        """Get current buffer size."""
        with self.lock:
            return len(self.buffer)
    
    def get_dropped_count(self) -> int:
        """Get count of dropped packets."""
        with self.lock:
            return self.dropped_count


class PerformanceMonitor:
    """
    Monitor performance metrics for the packet sniffer.
    """
    
    def __init__(self):
        """Initialize performance monitor."""
        self.start_time = time.time()
        self.packet_count = 0
        self.error_count = 0
        self.lock = threading.Lock()
    
    def increment_packets(self, count: int = 1):
        """Increment packet counter."""
        with self.lock:
            self.packet_count += count
    
    def increment_errors(self, count: int = 1):
        """Increment error counter."""
        with self.lock:
            self.error_count += count
    
    def get_stats(self) -> dict:
        """Get current performance statistics."""
        with self.lock:
            elapsed = time.time() - self.start_time
            return {
                'total_packets': self.packet_count,
                'total_errors': self.error_count,
                'elapsed_time': elapsed,
                'packets_per_second': self.packet_count / elapsed if elapsed > 0 else 0,
                'error_rate': self.error_count / self.packet_count if self.packet_count > 0 else 0
            }
    
    def reset(self):
        """Reset all counters."""
        with self.lock:
            self.start_time = time.time()
            self.packet_count = 0
            self.error_count = 0


class RateLimiter:
    """
    Rate limiter to prevent GUI overload.
    """
    
    def __init__(self, max_per_second: int = 100):
        """
        Initialize rate limiter.
        
        Args:
            max_per_second: Maximum operations per second
        """
        self.max_per_second = max_per_second
        self.min_interval = 1.0 / max_per_second
        self.last_time = 0
        self.lock = threading.Lock()
    
    def should_allow(self) -> bool:
        """Check if operation should be allowed based on rate limit."""
        with self.lock:
            current_time = time.time()
            if current_time - self.last_time >= self.min_interval:
                self.last_time = current_time
                return True
            return False
    
    def wait_if_needed(self):
        """Wait if necessary to maintain rate limit."""
        with self.lock:
            current_time = time.time()
            time_since_last = current_time - self.last_time
            if time_since_last < self.min_interval:
                time.sleep(self.min_interval - time_since_last)
            self.last_time = time.time()


class ErrorHandler:
    """
    Centralized error handling and logging.
    """
    
    def __init__(self, max_errors: int = 1000):
        """
        Initialize error handler.
        
        Args:
            max_errors: Maximum errors to store
        """
        self.errors = deque(maxlen=max_errors)
        self.lock = threading.Lock()
    
    def log_error(self, error_type: str, message: str, context: Optional[dict] = None):
        """
        Log an error.
        
        Args:
            error_type: Type of error
            message: Error message
            context: Additional context
        """
        with self.lock:
            error_entry = {
                'timestamp': time.time(),
                'type': error_type,
                'message': message,
                'context': context or {}
            }
            self.errors.append(error_entry)
    
    def get_recent_errors(self, count: int = 10) -> list:
        """Get most recent errors."""
        with self.lock:
            return list(self.errors)[-count:]
    
    def get_error_count(self) -> int:
        """Get total error count."""
        with self.lock:
            return len(self.errors)
    
    def clear_errors(self):
        """Clear all logged errors."""
        with self.lock:
            self.errors.clear()

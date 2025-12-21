"""HTTP parser"""

from typing import Tuple, Dict, Optional


class HTTPParser:
    """Parser for HTTP requests and responses."""
    
    HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH', 'TRACE', 'CONNECT']
    
    @staticmethod
    def is_http_request(payload: bytes) -> Tuple[bool, Optional[str], Optional[str], Optional[str]]:
        """
        Identify if payload contains HTTP request.
        
        Args:
            payload: TCP payload data
            
        Returns:
            Tuple of (is_request, method, uri, version)
        """
        if not payload or len(payload) < 10:
            return False, None, None, None
        
        try:
            payload_str = payload.decode('ascii', errors='ignore')
            payload_str = payload_str.replace('\x00', '')
            lines = payload_str.split('\r\n') if '\r\n' in payload_str else payload_str.split('\n')
            
            if not lines:
                return False, None, None, None
            
            first_line = lines[0].strip()
            
            for method in HTTPParser.HTTP_METHODS:
                if first_line.startswith(method + ' '):
                    parts = first_line.split(' ', 2)
                    if len(parts) >= 3 and 'HTTP/' in parts[2]:
                        return True, parts[0], parts[1], parts[2]
                    elif len(parts) >= 2:
                        return True, parts[0], parts[1], 'HTTP/1.0'
            
            return False, None, None, None
        except Exception:
            return False, None, None, None

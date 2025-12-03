"""HTTP parser"""

from typing import Tuple, Dict, Optional


class HTTPParser:
    """Parser for HTTP requests and responses."""
    
    HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH', 'TRACE', 'CONNECT']
    
    @staticmethod
    def is_http_request(payload: bytes) -> Tuple[bool, Optional[str], Optional[str], Optional[str], Optional[Dict[str, str]], Optional[str]]:
        """
        Identify if payload contains HTTP request.
        
        Args:
            payload: TCP payload data
            
        Returns:
            Tuple of (is_request, method, uri, version, headers, body)
        """
        if not payload or len(payload) < 10:
            return False, None, None, None, None, None
        
        try:
            payload_str = payload.decode('ascii', errors='ignore')
            payload_str = payload_str.replace('\x00', '')
            lines = payload_str.split('\r\n') if '\r\n' in payload_str else payload_str.split('\n')
            
            if not lines:
                return False, None, None, None, None, None
            
            first_line = lines[0].strip()
            
            for method in HTTPParser.HTTP_METHODS:
                if first_line.startswith(method + ' '):
                    parts = first_line.split(' ', 2)
                    if len(parts) >= 3 and 'HTTP/' in parts[2]:
                        headers, body = HTTPParser._parse_headers_and_body(lines[1:])
                        return True, parts[0], parts[1], parts[2], headers, body
                    elif len(parts) >= 2:
                        return True, parts[0], parts[1], 'HTTP/1.0', {}, None
            
            return False, None, None, None, None, None
        except Exception:
            return False, None, None, None, None, None
    
    @staticmethod
    def is_http_response(payload: bytes) -> Tuple[bool, Optional[str], Optional[str], Optional[str], Optional[Dict[str, str]], Optional[str]]:
        """
        Identify if payload contains HTTP response.
        
        Args:
            payload: TCP payload data
            
        Returns:
            Tuple of (is_response, version, status_code, status_text, headers, body)
        """
        if not payload or len(payload) < 10:
            return False, None, None, None, None, None
        
        try:
            payload_str = payload.decode('ascii', errors='ignore')
            payload_str = payload_str.replace('\x00', '')
            lines = payload_str.split('\r\n') if '\r\n' in payload_str else payload_str.split('\n')
            
            if not lines:
                return False, None, None, None, None, None
            
            first_line = lines[0].strip()
            
            if first_line.startswith('HTTP/'):
                parts = first_line.split(' ', 2)
                if len(parts) >= 2:
                    headers, body = HTTPParser._parse_headers_and_body(lines[1:])
                    status_code = parts[1] if len(parts) > 1 else '200'
                    status_text = parts[2] if len(parts) > 2 else 'OK'
                    return True, parts[0], status_code, status_text, headers, body
            
            return False, None, None, None, None, None
        except Exception:
            return False, None, None, None, None, None
    
    @staticmethod
    def _parse_headers(lines: list) -> Dict[str, str]:
        """Parse HTTP headers from lines."""
        headers = {}
        for line in lines:
            if ':' in line and line.strip():
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
            elif line.strip() == '':
                break
        return headers
    
    @staticmethod
    def _parse_headers_and_body(lines: list) -> Tuple[Dict[str, str], Optional[str]]:
        """Parse HTTP headers and body from lines."""
        headers = {}
        body_start_idx = None
        
        for idx, line in enumerate(lines):
            if ':' in line and line.strip():
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
            elif line.strip() == '':
                body_start_idx = idx + 1
                break
        
        # Extract body if present
        body = None
        if body_start_idx is not None and body_start_idx < len(lines):
            body_lines = lines[body_start_idx:]
            if body_lines:
                body = '\n'.join(body_lines).strip()
                if len(body) > 500:  # Truncate large bodies
                    body = body[:500] + '... (truncated)'
        
        return headers, body

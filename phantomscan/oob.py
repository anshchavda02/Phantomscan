"""
Out-of-Band (OOB) Reverse Server for PhantomScan.

This module spins up a lightweight, background HTTP server to catch
callbacks from blind vulnerabilities (like SSRF, RCE, or XXE). 
When an attack payload forces the target to hit this server, it records the unique ID.
"""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
import time
import uuid

class OOBState:
    """Shared state to track incoming callbacks."""
    hits: set[str] = set()

class OOBRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Format: /callback/<uuid>
        path = self.path
        if "/callback/" in path:
            unique_id = path.split("/callback/")[-1].split("?")[0].strip("/")
            OOBState.hits.add(unique_id)
            
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(b"ok")
        
    def do_POST(self):
        self.do_GET()
        
    def log_message(self, format, *args):
        # Suppress standard logging to keep the console clean
        pass


class OOBServer:
    def __init__(self, host: str = "0.0.0.0", port: int = 9090):
        self.host = host
        self.port = port
        self.server = None
        self.thread = None
        self.is_running = False

    def start(self) -> str:
        """Start the OOB server in a background thread and return the listener host."""
        self.server = ThreadingHTTPServer((self.host, self.port), OOBRequestHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.is_running = True
        return f"http://127.0.0.1:{self.port}/callback"

    def stop(self):
        """Stop the OOB server."""
        if self.server:
            self.server.shutdown()
            self.server.server_close()
        self.is_running = False

    def check_hit(self, unique_id: str) -> bool:
        """Check if a specific UUID has called back to this server."""
        return unique_id in OOBState.hits

    def generate_payload_url(self) -> tuple[str, str]:
        """Returns (unique_id, full_callback_url) for injection."""
        uid = str(uuid.uuid4())
        return uid, f"http://127.0.0.1:{self.port}/callback/{uid}"

# Global instance
oob_listener = OOBServer()

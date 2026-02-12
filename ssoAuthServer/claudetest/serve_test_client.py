#!/usr/bin/env python3
"""
Simple HTTP server to serve the SSO test client
Run: python3 serve_test_client.py
Then open: http://localhost:8080
"""

import http.server
import socketserver
import os

PORT = 8080
DIRECTORY = os.path.dirname(os.path.abspath(__file__))

class MyHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)
    
    def end_headers(self):
        # Add CORS headers
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        super().end_headers()

if __name__ == '__main__':
    with socketserver.TCPServer(("", PORT), MyHTTPRequestHandler) as httpd:
        print(f"")
        print(f"╔═══════════════════════════════════════════════════════╗")
        print(f"║       SSO Test Client Server                         ║")
        print(f"╠═══════════════════════════════════════════════════════╣")
        print(f"║  Server running at: http://localhost:{PORT}           ║")
        print(f"║  Test page: http://localhost:{PORT}/test-client.html ║")
        print(f"║                                                       ║")
        print(f"║  Press Ctrl+C to stop                                ║")
        print(f"╚═══════════════════════════════════════════════════════╝")
        print(f"")
        
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n\nShutting down server...")
#!/usr/bin/env python3
"""Serveur HTTP local sans cache — pour la maquette IHBI"""
import http.server, socketserver

class NoCacheHandler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate')
        self.send_header('Pragma', 'no-cache')
        self.send_header('Expires', '0')
        super().end_headers()
    def log_message(self, fmt, *args):
        print(f"  {self.address_string()} — {fmt % args}")

PORT = 8080
with socketserver.TCPServer(("127.0.0.1", PORT), NoCacheHandler) as httpd:
    print(f"\nServeur demarre sur http://127.0.0.1:{PORT}/index.html\n")
    httpd.serve_forever()

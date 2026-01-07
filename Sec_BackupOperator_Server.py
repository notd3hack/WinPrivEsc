#!/usr/bin/env python3
import http.server
import socketserver
import os
import netifaces

PORT = 8000
UPLOAD_DIR = "backups"
os.makedirs(UPLOAD_DIR, exist_ok=True)

try:
    ip_address = netifaces.ifaddresses('eth0')[netifaces.AF_INET][0]['addr']
except Exception:
    ip_address = "Unavailable"

GREEN = "\033[92m"
CYAN = "\033[96m"
RESET = "\033[0m"

banner = f"""
{GREEN}  ____             _                 ____                       _              {RESET}
{GREEN} |  _ \\           | |               / __ \\                     | |             {RESET}
{GREEN} | |_) | __ _  ___| | ___   _ _ __ | |  | |_ __   ___ _ __ __ _| |_ ___  _ __  {RESET}
{GREEN} |  _ < / _` |/ __| |/ / | | | '_ \\| |  | | '_ \\ / _ \\ '__/ _` | __/ _ \\| '__| {RESET}
{CYAN} | |_) | (_| | (__|   <| |_| | |_) | |__| | |_) |  __/ | | (_| | || (_) | |    {RESET}
{CYAN} |____/ \\__,_|\\___|_|\\_\\\\__,_| .__/ \\____/| .__/ \\___|_|  \\__,_|\\__\\___/|_| {RESET}   
{CYAN}                             | |          | |                                  {RESET}
{CYAN}                             |_|          |_|                                  {RESET}

    Researched and Developed by d3hvck
    {GREEN}Backup{RESET} {CYAN}Operator{RESET}
    Current eth0 IP: {ip_address}
    Listening on Port: {PORT}
"""

print(banner)

class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b'<h1>File Upload Server Ready</h1><p>Use POST to /upload</p>')
        else:
            super().do_GET()

    def do_POST(self):
        if self.path == '/upload':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)

            import datetime
            filename = f"file_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
            with open(os.path.join(UPLOAD_DIR, filename), 'wb') as f:
                f.write(post_data)

            self.send_response(200)
            self.end_headers()
            self.wfile.write(f"File received: {filename}".encode())
            print(f"Received {content_length} bytes saved as {filename}")
        else:
            self.send_error(404)

print(f"Starting server on port {PORT}")
print(f"Upload directory: {os.path.abspath(UPLOAD_DIR)}")
with socketserver.TCPServer(("", PORT), Handler) as httpd:
    httpd.serve_forever()

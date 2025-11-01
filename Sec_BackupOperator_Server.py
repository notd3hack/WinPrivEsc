#!/usr/bin/env python3
import http.server
import socketserver
import os

# you can manually change port 8000
# its designed for reciving files from any machine to your linux server

banner = r"""
  ____             _                 ____                       _             
 |  _ \           | |               / __ \                     | |            
 | |_) | __ _  ___| | ___   _ _ __ | |  | |_ __   ___ _ __ __ _| |_ ___  _ __ 
 |  _ < / _` |/ __| |/ / | | | '_ \| |  | | '_ \ / _ \ '__/ _` | __/ _ \| '__|
 | |_) | (_| | (__|   <| |_| | |_) | |__| | |_) |  __/ | | (_| | || (_) | |   
 |____/ \__,_|\___|_|\_\\__,_| .__/ \____/| .__/ \___|_|  \__,_|\__\___/|_|   
                             | |          | |                                 
                             |_|          |_|                                 

    Researched and Developed by d3hvck

"""
print(banner)

PORT = 8000
UPLOAD_DIR = "backups"
os.makedirs(UPLOAD_DIR, exist_ok=True)

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
            
            # Save the raw data
            import datetime
            filename = f"upload_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.dat"
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
EOF
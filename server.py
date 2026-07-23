# server.py — minimal plaintext login form, lab use only
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(b"""
        <form method="POST">
            Username: <input name="username"><br>
            Password: <input name="password" type="password"><br>
            <input type="submit">
        </form>
        """)

    def do_POST(self):
        length = int(self.headers["Content-Length"])
        body = self.rfile.read(length).decode()
        creds = parse_qs(body)
        print(f"Captured login attempt: {creds}")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Login received (lab only)")

HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()

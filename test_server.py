"""
test_server.py - a deliberately WEAK local web app for practicing scanning.
It has no security headers and pretends to run an old server version.
Run it first, then run scanner.py against it.

Usage:  python test_server.py        (runs on http://127.0.0.1:8080)
"""
from http.server import HTTPServer, BaseHTTPRequestHandler


class WeakHandler(BaseHTTPRequestHandler):
    # Fake an outdated server banner so the scanner has something to find
    server_version = "Apache/2.2.15"
    sys_version = ""

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        # Notice: we send NO security headers on purpose
        self.send_header("X-Powered-By", "PHP/5.4.16")  # also outdated + leaks info
        self.end_headers()
        self.wfile.write(b"<h1>My weak test site</h1><p>Hello, scanner!</p>")


if __name__ == "__main__":
    server = HTTPServer(("127.0.0.1", 8080), WeakHandler)
    print("Weak test server running at http://127.0.0.1:8080  (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")

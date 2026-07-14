from http.server import BaseHTTPRequestHandler, HTTPServer


class RequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        print("Received GET request")
        print("Path:", self.path)

        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()

        self.wfile.write(b"Server is working")

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        message = self.rfile.read(content_length)

        print("Received POST request")
        print("Path:", self.path)
        print("Message:", message.decode("utf-8", errors="replace"))

        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()

        self.wfile.write(b"Message received")


server_address = ("127.0.0.1", 80)
server = HTTPServer(server_address, RequestHandler)

print("Server is running on http://127.0.0.1:80")
print("Press Ctrl+C to stop the server")

server.serve_forever()
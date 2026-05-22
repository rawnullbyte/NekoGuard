import requests
from http.server import HTTPServer, BaseHTTPRequestHandler

GUARD = "http://localhost:3000"
UPSTREAM = "https://root-workspace.net/"


class NginxSim(BaseHTTPRequestHandler):
    def forward(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else None

        try:
            res = requests.request(
                method=self.command,
                url=GUARD + self.path,
                headers={
                    "Host": self.headers.get("Host", "localhost"),
                    "X-Upstream": UPSTREAM,
                    "X-Real-IP": self.client_address[0],
                    "X-Forwarded-For": self.client_address[0],
                    "X-Forwarded-Proto": "http",
                    "Cookie": self.headers.get("Cookie", ""),
                    "User-Agent": self.headers.get("User-Agent", ""),
                    "Content-Type": self.headers.get("Content-Type", ""),
                    "Accept-Encoding": self.headers.get("Accept-Encoding", ""),
                },
                data=body,
                allow_redirects=False,
                stream=True,
            )
            # Read raw bytes without decompression so Content-Length stays accurate
            raw_body = res.raw.read(decode_content=False)
            self.send_response(res.status_code)
            for k, v in res.headers.items():
                if k.lower() not in ("transfer-encoding", "connection"):
                    self.send_header(k, v)
            self.end_headers()
            self.wfile.write(raw_body)
        except Exception as e:
            self.send_response(502)
            self.end_headers()
            self.wfile.write(str(e).encode())

    def do_GET(self):
        self.forward()

    def do_POST(self):
        self.forward()

    def log_message(self, fmt, *args):
        print(f"[sim] {self.address_string()} → {GUARD}{self.path}")


print(f"Proxy on http://localhost:8080 → NekoGuard :3000 → {UPSTREAM}")
HTTPServer(("", 8080), NginxSim).serve_forever()

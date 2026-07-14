#!/usr/bin/env python3
"""Minimal echo backend for integration tests.

Records the last request body and returns JSON with length, sha256, and
whether known markers were present — proving full-body preservation after
ngx_json_guard + ModSecurity.
"""

from __future__ import annotations

import hashlib
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = "127.0.0.1"
PORT = 9000

_lock = threading.Lock()
_last = {
    "method": None,
    "path": None,
    "content_type": None,
    "body_len": 0,
    "sha256": None,
    "has_tail_marker": False,
    "has_attack_marker": False,
    "body_prefix": "",
    "body_suffix": "",
}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args) -> None:
        # Keep container logs readable.
        sys_stderr = __import__("sys").stderr
        sys_stderr.write("[echo] " + (fmt % args) + "\n")

    def _read_body(self) -> bytes:
        n = int(self.headers.get("Content-Length") or "0")
        if n <= 0:
            return b""
        return self.rfile.read(n)

    def _json_response(self, code: int, obj: dict) -> None:
        data = json.dumps(obj, separators=(",", ":")).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802
        if self.path.startswith("/health"):
            self._json_response(200, {"ok": True})
            return
        if self.path.startswith("/last"):
            with _lock:
                self._json_response(200, dict(_last))
            return
        self._json_response(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        body = self._read_body()
        digest = hashlib.sha256(body).hexdigest()
        text = body.decode("utf-8", errors="replace")
        rec = {
            "method": "POST",
            "path": self.path,
            "content_type": self.headers.get("Content-Type"),
            "body_len": len(body),
            "sha256": digest,
            "has_tail_marker": "JG_TAIL_MARKER_7f3a9c" in text,
            "has_attack_marker": "JG_ATTACK_MARKER_sqli" in text,
            "body_prefix": text[:64],
            "body_suffix": text[-64:] if text else "",
        }
        with _lock:
            _last.clear()
            _last.update(rec)
        self._json_response(
            200,
            {
                "ok": True,
                "received": rec,
            },
        )

    def do_PUT(self) -> None:  # noqa: N802
        self.do_POST()


def main() -> None:
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"echo backend on http://{HOST}:{PORT}", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()

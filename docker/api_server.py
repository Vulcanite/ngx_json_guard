#!/usr/bin/env python3
"""Small inert upstream used by the constrained WAF performance lab."""

from __future__ import annotations

import hashlib
import html
import json
import os
import sys
import urllib.parse
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", "9000"))
APP_MODE = os.environ.get("APP_MODE", "json")
APP_NAME = os.environ.get("APP_NAME", f"{APP_MODE}-api")
MAX_LOG_PAIRS = int(os.environ.get("MAX_LOG_PAIRS", "100"))


def iter_pairs(value: Any, path: str = "$"):
    if isinstance(value, dict):
        if not value:
            yield path, {}
        for key, item in value.items():
            yield from iter_pairs(item, f"{path}.{key}")
        return
    if isinstance(value, list):
        if not value:
            yield path, []
        for idx, item in enumerate(value):
            yield from iter_pairs(item, f"{path}[{idx}]")
        return
    yield path, value


def compact(value: Any, limit: int = 200) -> str:
    if isinstance(value, str) and len(value) > limit:
        return json.dumps(value[: limit - 6] + "...", ensure_ascii=True)
    text = json.dumps(value, ensure_ascii=True, separators=(",", ":"))
    return text if len(text) <= limit else text[: limit - 3] + "..."


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: object) -> None:
        sys.stderr.write(f"[{APP_NAME}] " + (fmt % args) + "\n")

    def read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length") or "0")
        return self.rfile.read(length) if length > 0 else b""

    def json_response(self, code: int, obj: dict[str, Any]) -> None:
        data = json.dumps(obj, separators=(",", ":")).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Upstream-App", APP_NAME)
        self.end_headers()
        self.wfile.write(data)

    def body_summary(self, body: bytes) -> dict[str, Any]:
        return {
            "app": APP_NAME,
            "body_len": len(body),
            "sha256": hashlib.sha256(body).hexdigest(),
        }

    def handle_json(self, body: bytes) -> None:
        summary = self.body_summary(body)
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            summary.update(ok=False, error="invalid json", detail=str(exc)[:160])
            self.json_response(400, summary)
            return

        pairs_seen = 0
        pairs_logged = 0
        for path, value in iter_pairs(payload):
            pairs_seen += 1
            if pairs_logged < MAX_LOG_PAIRS:
                print(f"[{APP_NAME}] path={compact(path)} value={compact(value)}", flush=True)
                pairs_logged += 1

        summary.update(
            ok=True,
            top_level_type=type(payload).__name__,
            pairs_seen=pairs_seen,
            pairs_logged=pairs_logged,
        )
        self.json_response(200, summary)

    def handle_xml(self, body: bytes) -> None:
        summary = self.body_summary(body)
        try:
            root = ET.fromstring(body)
        except (ET.ParseError, ValueError) as exc:
            summary.update(ok=False, error="invalid xml", detail=str(exc)[:160])
            self.json_response(400, summary)
            return

        summary.update(ok=True, root=root.tag, elements=sum(1 for _ in root.iter()))
        self.json_response(200, summary)

    def handle_form(self, body: bytes) -> None:
        summary = self.body_summary(body)
        try:
            values = urllib.parse.parse_qs(
                body.decode("utf-8"), keep_blank_values=True, strict_parsing=False
            )
        except UnicodeDecodeError as exc:
            summary.update(ok=False, error="invalid form", detail=str(exc)[:160])
            self.json_response(400, summary)
            return

        summary.update(ok=True, fields=len(values), values=sum(len(v) for v in values.values()))
        self.json_response(200, summary)

    def handle_web_post(self, body: bytes) -> None:
        summary = self.body_summary(body)
        summary.update(ok=True, content_type=self.headers.get("Content-Type", ""))
        self.json_response(200, summary)

    def do_GET(self) -> None:  # noqa: N802
        if self.path.startswith("/health"):
            self.json_response(200, {"ok": True, "app": APP_NAME})
            return
        if APP_MODE != "web":
            self.json_response(404, {"ok": False, "app": APP_NAME, "error": "not found"})
            return

        query = urllib.parse.urlsplit(self.path).query
        values = urllib.parse.parse_qs(query, keep_blank_values=True)
        title = html.escape(values.get("title", ["WAF lab"])[0])
        data = f"<!doctype html><title>{title}</title><h1>{title}</h1>".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Upstream-App", APP_NAME)
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self) -> None:  # noqa: N802
        body = self.read_body()
        if APP_MODE == "json":
            self.handle_json(body)
        elif APP_MODE == "xml":
            self.handle_xml(body)
        elif APP_MODE == "form":
            self.handle_form(body)
        else:
            self.handle_web_post(body)

    def do_PUT(self) -> None:  # noqa: N802
        self.do_POST()

    def do_PATCH(self) -> None:  # noqa: N802
        self.do_POST()

    def do_DELETE(self) -> None:  # noqa: N802
        self.do_POST()


def main() -> None:
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"[{APP_NAME}] mode={APP_MODE} listening on {HOST}:{PORT}", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()

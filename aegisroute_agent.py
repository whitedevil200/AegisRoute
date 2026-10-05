#!/usr/bin/env python3
"""Minimal read-only AegisRoute report agent for distributed measurements."""

from __future__ import annotations

import argparse
import hmac
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description="Serve one AegisRoute JSON report to an authorized collector")
    value.add_argument("--report", required=True, help="JSON report updated atomically by a scheduled AegisRoute run")
    value.add_argument("--listen", default="127.0.0.1", help="listen address; use a TLS reverse proxy for remote access")
    value.add_argument("--port", type=int, default=8787, help="TCP listen port")
    value.add_argument("--token", default=os.environ.get("AEGISROUTE_AGENT_TOKEN"),
                       help="Bearer token; AEGISROUTE_AGENT_TOKEN is preferred to command history")
    return value


def main() -> int:
    args = parser().parse_args()
    report = Path(args.report).expanduser().resolve()
    if not report.is_file():
        raise SystemExit(f"aegisroute-agent: report not found: {report}")
    if not 1 <= args.port <= 65535:
        raise SystemExit("aegisroute-agent: port must be between 1 and 65535")

    class Handler(BaseHTTPRequestHandler):
        server_version = "AegisRouteAgent/3.0"

        def _authorized(self) -> bool:
            if not args.token:
                return True
            supplied = self.headers.get("Authorization", "")
            return hmac.compare_digest(supplied, f"Bearer {args.token}")

        def do_GET(self) -> None:  # noqa: N802 - HTTP method naming
            if not self._authorized():
                self.send_error(401, "Bearer token required")
                return
            if self.path == "/health":
                payload = b'{"status":"ok"}'
            elif self.path == "/report":
                try:
                    value = json.loads(report.read_text(encoding="utf-8"))
                    payload = json.dumps(value, separators=(",", ":")).encode()
                except (OSError, ValueError, json.JSONDecodeError):
                    self.send_error(503, "report unavailable")
                    return
            else:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, fmt: str, *values: object) -> None:
            print(f"aegisroute-agent: {self.address_string()} {fmt % values}")

    print(f"Serving {report} on http://{args.listen}:{args.port}/report")
    print("Use a TLS reverse proxy before exposing this endpoint beyond localhost.")
    try:
        ThreadingHTTPServer((args.listen, args.port), Handler).serve_forever()
    except KeyboardInterrupt:
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

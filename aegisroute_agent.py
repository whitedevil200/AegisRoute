#!/usr/bin/env python3
"""Read-only AegisRoute agent with report signing, policy checks, and optional mTLS."""
from __future__ import annotations

import argparse
import hashlib
import hmac
import ipaddress
import json
import os
import ssl
import time
from collections import defaultdict, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description="Serve one policy-approved AegisRoute JSON report to an authorized collector")
    value.add_argument("--report", required=True)
    value.add_argument("--listen", default="127.0.0.1", help="listen address; non-loopback requires TLS")
    value.add_argument("--port", type=int, default=8787)
    value.add_argument("--token", default=os.environ.get("AEGISROUTE_AGENT_TOKEN"), help="Bearer token; environment variable preferred")
    value.add_argument("--signing-key", default=os.environ.get("AEGISROUTE_AGENT_SIGNING_KEY"), metavar="SECRET")
    value.add_argument("--key-id", default=os.environ.get("AEGISROUTE_AGENT_KEY_ID", "default"), help="identifier only; never a secret")
    value.add_argument("--allowed-cidr", action="append", default=[], metavar="CIDR", help="repeatable destination policy")
    value.add_argument("--requests-per-minute", type=int, default=30, metavar="N", help="per-client ceiling")
    value.add_argument("--tls-cert", metavar="FILE", help="server certificate PEM; required for non-loopback")
    value.add_argument("--tls-key", metavar="FILE", help="server private-key PEM")
    value.add_argument("--tls-ca", metavar="FILE", help="client CA PEM; enables mandatory mutual TLS")
    value.add_argument("--require-nonce", action="store_true",
                       help="require a unique X-AegisRoute-Nonce header on every report request to reduce replay risk")
    return value


def main() -> int:
    args = parser().parse_args()
    report = Path(args.report).expanduser().resolve()
    if not report.is_file():
        raise SystemExit(f"aegisroute-agent: report not found: {report}")
    if not 1 <= args.port <= 65535 or not 1 <= args.requests_per_minute <= 600:
        raise SystemExit("aegisroute-agent: invalid port or request ceiling")
    try:
        listen_ip = ipaddress.ip_address(args.listen)
        allowed = [ipaddress.ip_network(item, strict=False) for item in args.allowed_cidr]
    except ValueError as exc:
        raise SystemExit(f"aegisroute-agent: invalid IP/CIDR policy: {exc}") from exc
    tls_enabled = bool(args.tls_cert or args.tls_key or args.tls_ca)
    if not listen_ip.is_loopback and not tls_enabled:
        raise SystemExit("aegisroute-agent: non-loopback listening requires --tls-cert and --tls-key")
    if tls_enabled and not (args.tls_cert and args.tls_key):
        raise SystemExit("aegisroute-agent: TLS requires both --tls-cert and --tls-key")
    buckets: dict[str, deque[float]] = defaultdict(deque)
    nonces: dict[str, float] = {}

    class Handler(BaseHTTPRequestHandler):
        server_version = "AegisRouteAgent/3.2"

        def _allowed(self) -> bool:
            if args.token and not hmac.compare_digest(self.headers.get("Authorization", ""), f"Bearer {args.token}"):
                return False
            now, bucket = time.monotonic(), buckets[self.client_address[0]]
            while bucket and bucket[0] <= now - 60:
                bucket.popleft()
            if len(bucket) >= args.requests_per_minute:
                return False
            bucket.append(now)
            if args.require_nonce and self.path == "/report":
                nonce = self.headers.get("X-AegisRoute-Nonce", "")
                if not 16 <= len(nonce) <= 256 or nonce in nonces:
                    return False
                nonces[nonce] = now
                for old, seen in list(nonces.items()):
                    if seen < now - 600:
                        del nonces[old]
            return True

        def _payload(self) -> bytes | None:
            try:
                value = json.loads(report.read_text(encoding="utf-8"))
                destination = ipaddress.ip_address(value.get("destination_ip"))
                if allowed and not any(destination in network for network in allowed):
                    self.send_error(403, "report destination rejected by agent policy")
                    return None
                return json.dumps(value, separators=(",", ":")).encode()
            except (OSError, ValueError, TypeError, json.JSONDecodeError):
                self.send_error(503, "report unavailable")
                return None

        def do_GET(self) -> None:  # noqa: N802
            if not self._allowed():
                self.send_error(401, "authorization missing, invalid, or rate limited")
                return
            payload = b'{"status":"ok","mode":"read-only"}' if self.path == "/health" else self._payload() if self.path == "/report" else None
            if payload is None:
                if self.path != "/report": self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            if args.signing_key:
                timestamp = str(int(time.time()))
                nonce = self.headers.get("X-AegisRoute-Nonce", "")
                digest = hmac.new(args.signing_key.encode(), timestamp.encode() + b"." + nonce.encode() + b"." + payload, hashlib.sha256).hexdigest()
                self.send_header("X-AegisRoute-Key-Id", args.key_id)
                self.send_header("X-AegisRoute-Timestamp", timestamp)
                self.send_header("X-AegisRoute-Signature", f"sha256={digest}")
                if nonce:
                    self.send_header("X-AegisRoute-Nonce", nonce)
            self.end_headers(); self.wfile.write(payload)

        def log_message(self, fmt: str, *values: object) -> None:
            print(f"aegisroute-agent: {self.address_string()} {fmt % values}")

    server = ThreadingHTTPServer((args.listen, args.port), Handler)
    if tls_enabled:
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(args.tls_cert, args.tls_key)
        if args.tls_ca:
            context.load_verify_locations(args.tls_ca); context.verify_mode = ssl.CERT_REQUIRED
        server.socket = context.wrap_socket(server.socket, server_side=True)
    scheme = "https" if tls_enabled else "http"
    print(f"Serving policy-approved report on {scheme}://{args.listen}:{args.port}/report")
    print("Mode: read-only; mTLS is active when --tls-ca is supplied. Nonce replay protection is active with --require-nonce.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return 130
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

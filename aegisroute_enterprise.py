"""Optional enterprise integrations for AegisRoute.

All network-affecting features are opt-in.  This module uses the standard
library except for the optional ``websockets`` package used by RIS Live.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import json
import os
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlencode
from urllib.request import Request, urlopen


PROFILES = {
    "fast": {"probes": 1, "wait": 0.7, "max_hops": 20, "concurrency": 12},
    "balanced": {"probes": 3, "wait": 1.0, "max_hops": 30, "concurrency": 16},
    "forensic": {"probes": 5, "wait": 2.0, "max_hops": 40, "concurrency": 8},
    "low-impact": {"probes": 1, "wait": 1.5, "max_hops": 20, "concurrency": 4},
}


def apply_profile(args: Any) -> None:
    """Apply conservative, documented probe budgets before a measurement."""
    if args.profile == "custom":
        return
    for name, value in PROFILES[args.profile].items():
        setattr(args, name, value)


def atlas_definition(target: str, args: Any) -> dict[str, Any]:
    """Create a transparent Atlas request preview; does not spend credits."""
    protocol = "ICMP" if args.protocol == "icmp" else "TCP" if args.protocol == "tcp" else "UDP"
    definition = {"target": target, "description": f"AegisRoute {args.company} route measurement",
                  "type": "traceroute", "af": 6 if args.ipv6 else 4,
                  "protocol": protocol, "packets": args.probes, "paris": args.strategy == "paris",
                  "resolve_on_probe": True}
    if args.protocol in {"tcp", "udp"}:
        definition["port"] = args.port
    probes: dict[str, Any] = {"requested": args.atlas_probes, "type": "probes", "value": ""}
    if args.atlas_countries:
        probes = {"requested": args.atlas_probes, "type": "area", "value": args.atlas_countries.split(",")}
    return {"definitions": [definition], "probes": [probes], "is_oneoff": not bool(args.atlas_interval),
            "interval": args.atlas_interval or None, "billing": {"cost_known": False,
            "notice": "RIPE Atlas determines credit cost server-side; review its response before repeating measurements."}}


def atlas_create(target: str, args: Any) -> dict[str, Any]:
    """Create an Atlas measurement only after explicit CLI approval."""
    preview = atlas_definition(target, args)
    if not args.approve_atlas_cost:
        return {"created": False, "approval_required": True, "preview": preview}
    if not args.atlas_api_key:
        raise ValueError("--atlas-create --approve-atlas-cost requires --atlas-api-key or AEGISROUTE_ATLAS_API_KEY")
    body = json.dumps(preview, separators=(",", ":")).encode()
    request = Request("https://atlas.ripe.net/api/v2/measurements/", data=body,
                      headers={"Authorization": f"Key {args.atlas_api_key}", "Content-Type": "application/json",
                               "User-Agent": "AegisRoute/3"}, method="POST")
    with urlopen(request, timeout=20) as response:
        return {"created": True, "status": response.status, "response": json.loads(response.read().decode())}


async def ris_live_events(prefixes: list[str], seconds: int, limit: int = 100) -> dict[str, Any]:
    """Collect a bounded RIS Live sample. Requires optional ``websockets``."""
    try:
        import websockets  # type: ignore
    except ImportError:
        return {"provider": "RIS Live", "events": [], "error": "optional 'websockets' package is not installed"}
    prefixes = list(dict.fromkeys(prefixes))[:25]
    if not prefixes:
        return {"provider": "RIS Live", "events": [], "error": "no observed prefixes"}
    wanted = []
    for prefix in prefixes:
        try:
            wanted.append(ipaddress.ip_network(prefix, strict=False))
        except ValueError:
            pass
    subscription = {"type": "ris_subscribe", "data": {"type": "UPDATE", "require": "", "host": "", "socketOptions": {}}}
    # RIS filtering syntax is intentionally avoided here when several prefix families are present;
    # clients filter received updates locally and cap both duration and retained event count.
    deadline, events = time.monotonic() + seconds, []
    try:
        async with websockets.connect("wss://ris-live.ripe.net/v1/ws/", open_timeout=10, close_timeout=3) as ws:
            await ws.send(json.dumps(subscription))
            while time.monotonic() < deadline and len(events) < limit:
                try:
                    message = await asyncio.wait_for(ws.recv(), timeout=max(.1, deadline - time.monotonic()))
                    value = json.loads(message)
                    data = value.get("data", {}) if isinstance(value, dict) else {}
                    path = data.get("path", [])
                    prefix = data.get("prefix") or data.get("announcements", [{}])[0].get("prefix")
                    try:
                        observed = ipaddress.ip_network(prefix, strict=False)
                    except ValueError:
                        observed = None
                    if observed and any(observed.subnet_of(item) or item.subnet_of(observed) for item in wanted):
                        events.append({"timestamp": data.get("timestamp"), "type": data.get("type", "UPDATE"),
                                       "prefix": prefix, "path": path, "origin_asn": path[-1] if path else None,
                                       "source": "RIS Live"})
                except asyncio.TimeoutError:
                    break
    except OSError as exc:
        return {"provider": "RIS Live", "events": [], "error": str(exc)}
    return {"provider": "RIS Live", "events": events, "sample_seconds": seconds,
            "truncated": len(events) >= limit, "error": None}


def evidence_timeline(report: dict[str, Any]) -> dict[str, Any]:
    """Make a deterministic incident timeline from measurement and BGP evidence."""
    timeline = [{"timestamp": report.get("started_at"), "kind": "measurement_started", "source": "AegisRoute"},
                {"timestamp": report.get("finished_at"), "kind": "measurement_finished", "source": "AegisRoute"}]
    for key in ("bgp_correlation", "ris_live"):
        for event in report.get(key, {}).get("events", []):
            timeline.append({"timestamp": event.get("timestamp"), "kind": "bgp_" + str(event.get("type", "update")).lower(),
                             "prefix": event.get("prefix"), "origin_asn": event.get("origin_asn"), "source": key})
    timeline.sort(key=lambda item: str(item.get("timestamp") or ""))
    return {"schema": "aegisroute/evidence-timeline-v1", "events": timeline,
            "correlation_note": "Temporal overlap is evidence, not proof that a BGP event caused a data-plane change."}


def measurement_confidence(report: dict[str, Any]) -> dict[str, Any]:
    """Calibrate confidence in the observation, never a claim of network health."""
    traces = report.get("traces", [])
    hops = [hop for trace in traces for hop in trace.get("hops", [])]
    observed = sum(bool(hop.get("responders")) for hop in hops)
    coverage = observed / len(hops) if hops else 0.0
    protocol_factor = min(1.0, len({trace.get("protocol") for trace in traces}) / 3)
    reached = bool(report.get("quality", {}).get("destination_reached"))
    score = round(100 * (.50 * coverage + .25 * protocol_factor + .25 * int(reached)), 1)
    level = "high" if score >= 80 else "moderate" if score >= 55 else "low"
    limits = []
    if coverage < .7: limits.append("router reply coverage is incomplete; ICMP filtering may bias the path")
    if protocol_factor < 1: limits.append("fewer than three probe protocols were observed")
    if not reached: limits.append("destination did not reply; route completion is unconfirmed")
    return {"score": score, "level": level, "coverage": round(coverage, 3),
            "protocol_count": len({trace.get("protocol") for trace in traces}), "limitations": limits,
            "meaning": "confidence in this measurement's completeness, not an availability or security verdict"}


def ingest_ioam(path: str) -> dict[str, Any]:
    """Import operator-exported IOAM evidence; AegisRoute never injects IOAM on public paths."""
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("IOAM input must be a JSON object exported by an authorized operator system")
    records = value.get("records", value.get("nodes", []))
    if not isinstance(records, list) or len(records) > 2048:
        raise ValueError("IOAM input records must be a list of at most 2048 entries")
    return {"mode": "operator-supplied-import", "record_count": len(records), "records": records,
            "warning": "IOAM data is trusted only to the degree of the authenticated operator export; it is not Internet-wide traceroute evidence."}


def sign_manifest(value: bytes, key: str | None) -> dict[str, str] | None:
    if not key:
        return None
    return {"algorithm": "HMAC-SHA256", "digest": hmac.new(key.encode(), value, hashlib.sha256).hexdigest()}


def incident_bundle(report: dict[str, Any], destination: str, signing_key: str | None = None) -> dict[str, Any]:
    """Create a portable, hash-verified investigation bundle."""
    from aegisroute_pro import html_report
    report_bytes = json.dumps(report, indent=2, sort_keys=True).encode()
    html_bytes = html_report(report).encode()
    files = {"report.json": report_bytes, "report.html": html_bytes}
    manifest = {"schema": "aegisroute/incident-manifest-v1", "created_at": datetime.now(timezone.utc).isoformat(),
                "target": report.get("target"), "tool_version": report.get("tool_version"),
                "files": {name: hashlib.sha256(content).hexdigest() for name, content in files.items()}}
    manifest_bytes = json.dumps(manifest, indent=2, sort_keys=True).encode()
    signature = sign_manifest(manifest_bytes, signing_key)
    target = Path(destination).expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in files.items():
            archive.writestr(name, content)
        archive.writestr("manifest.json", manifest_bytes)
        if signature:
            archive.writestr("manifest.signature.json", json.dumps(signature, indent=2))
    return {"path": str(target), "manifest": manifest, "signed": bool(signature)}


def otlp_json(report: dict[str, Any]) -> dict[str, Any]:
    """Dependency-free OTLP/HTTP JSON payload with bounded-cardinality attributes."""
    quality = report.get("quality", {})
    attrs = [{"key": "aegisroute.target", "value": {"stringValue": str(report.get("target", ""))}},
             {"key": "aegisroute.destination_reached", "value": {"boolValue": bool(quality.get("destination_reached"))}},
             {"key": "aegisroute.quality_score", "value": {"doubleValue": float(quality.get("score", 0))}},
             {"key": "aegisroute.finding_count", "value": {"intValue": str(len(report.get("findings", [])))}}]
    now = str(int(time.time() * 1_000_000_000))
    return {"resourceSpans": [{"resource": {"attributes": [{"key": "service.name", "value": {"stringValue": "aegisroute"}}]},
              "scopeSpans": [{"scope": {"name": "aegisroute"}, "spans": [{"traceId": hashlib.md5(now.encode()).hexdigest(),
              "spanId": hashlib.sha1(now.encode()).hexdigest()[:16], "name": "route.measurement", "kind": 1,
              "startTimeUnixNano": now, "endTimeUnixNano": now, "attributes": attrs}]}]}]}


def export_otlp(endpoint: str, report: dict[str, Any]) -> dict[str, Any]:
    if not (endpoint.startswith("https://") or endpoint.startswith("http://127.0.0.1") or endpoint.startswith("http://localhost")):
        raise ValueError("OTLP endpoint must use HTTPS or localhost HTTP")
    request = Request(endpoint.rstrip("/") + "/v1/traces", data=json.dumps(otlp_json(report)).encode(),
                      headers={"Content-Type": "application/json", "User-Agent": "AegisRoute/3"}, method="POST")
    try:
        with urlopen(request, timeout=10) as response:
            return {"sent": True, "status": response.status}
    except OSError as exc:
        return {"sent": False, "error": str(exc)}

"""Evidence, privacy, monitoring, and integration helpers for AegisRoute.

These routines are deliberately dependency-free and never create traffic except
when an explicitly approved provider request is made by the caller.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import statistics
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen


def _hash(value: str) -> str:
    return "anon-" + hashlib.sha256(value.encode()).hexdigest()[:12]


def redact_report(report: dict[str, Any], mode: str) -> dict[str, Any]:
    """Return a copy with identifiers masked; original data is never modified."""
    if mode == "off":
        return report
    # IPv4 values commonly appear in raw traceroute lines. IPv6 values are
    # already available in structured address fields; a broad colon-based regex
    # would incorrectly redact timestamps and other ordinary text.
    ip_pattern = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
    sensitive = {str(report.get("target", "")), str(report.get("destination_ip", ""))}
    for match in ip_pattern.finditer(json.dumps(report)):
        sensitive.add(match.group(0))
    sensitive.discard("")
    replacements = {item: _hash(item) for item in sensitive}
    def walk(value: Any, key: str = "") -> Any:
        if isinstance(value, dict):
            return {name: walk(item, name) for name, item in value.items()}
        if isinstance(value, list):
            return [walk(item, key) for item in value]
        if not isinstance(value, str):
            return value
        # Raw backend lines, graph IDs, and command arrays can include an address
        # outside a structured ``ip`` field, so mask known identifiers everywhere.
        for source in sorted(replacements, key=len, reverse=True):
            value = value.replace(source, replacements[source])
        if key in {"ip", "destination_ip", "target", "rdns", "city", "as_name"}:
            if mode == "strict" or key in {"ip", "destination_ip", "target", "rdns"}:
                return _hash(value)
        return value
    redacted = walk(report)
    redacted["privacy"] = {"mode": mode, "note": "Identifiers were deterministically masked in this exported view."}
    return redacted


def measurement_record(report: dict[str, Any]) -> dict[str, Any]:
    """Stable per-probe observation record suitable for replay and archival."""
    observations: list[dict[str, Any]] = []
    for trace in report.get("traces", []):
        for hop in trace.get("hops", []):
            observations.append({
                "protocol": trace.get("protocol"), "ttl": hop.get("ttl"),
                "responders": [{"ip": r.get("ip"), "rtts_ms": r.get("rtts_ms", []),
                                "annotations": r.get("annotations", [])} for r in hop.get("responders", [])],
                "timeouts": hop.get("timeouts", 0), "stats": hop.get("stats", {}),
            })
    return {"schema": "aegisroute/measurement-record-v1", "captured_at": report.get("finished_at"),
            "target": report.get("target"), "destination_ip": report.get("destination_ip"),
            "settings": {key: report.get("settings", {}).get(key) for key in ("protocol", "strategy", "backend", "probes", "wait")},
            "observations": observations,
            "integrity": {"report_sha256": hashlib.sha256(json.dumps(report, sort_keys=True).encode()).hexdigest()}}


def monitoring_baseline(reports: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute robust recent route statistics without confusing hop loss with service loss."""
    values: list[float] = []
    signatures: list[str] = []
    for report in reports:
        for trace in report.get("traces", []):
            for hop in trace.get("hops", []):
                avg = hop.get("stats", {}).get("avg_ms")
                if isinstance(avg, (int, float)): values.append(float(avg))
        signatures.append(json.dumps([[r.get("ip") for r in h.get("responders", [])] for t in report.get("traces", []) for h in t.get("hops", [])], sort_keys=True))
    if not values:
        return {"sample_count": len(reports), "available": False}
    ordered = sorted(values)
    percentile = lambda q: ordered[min(len(ordered) - 1, round((len(ordered) - 1) * q))]
    return {"sample_count": len(reports), "available": True, "rtt_ms": {"p50": round(percentile(.5), 3), "p95": round(percentile(.95), 3), "p99": round(percentile(.99), 3), "median": round(statistics.median(values), 3)},
            "route_variants": len(set(signatures)),
            "caveat": "Intermediate-hop reply loss is not interpreted as forwarded traffic loss."}


def bgp_security_findings(bgp: dict[str, Any]) -> list[dict[str, Any]]:
    """Conservative BGP alert rules; all findings retain alternate explanations."""
    findings = []
    origins = sorted(set(str(v) for v in bgp.get("origin_asns", []) if v is not None))
    if len(origins) > 1:
        findings.append({"severity": "warning", "type": "bgp_moas_observed", "detail": f"multiple origin ASNs observed: {', '.join(origins)}", "confidence": .72, "evidence": [bgp.get("provider", "BGP source")], "alternative_explanations": ["legitimate multi-origin routing", "collector visibility"]})
    if bgp.get("withdrawals", 0):
        findings.append({"severity": "notice", "type": "bgp_visibility_change", "detail": f"{bgp['withdrawals']} withdrawals observed in the selected window", "confidence": .7, "evidence": [bgp.get("provider", "BGP source")], "alternative_explanations": ["normal traffic engineering", "collector-specific visibility"]})
    return findings


def globalping_request(target: str, args: Any) -> dict[str, Any]:
    """Prepare or submit a single bounded Globalping traceroute measurement."""
    payload = {"type": "traceroute", "target": target, "locations": [{"magic": "World", "limit": args.globalping_probes}],
               "measurementOptions": {"protocol": args.protocol if args.protocol != "all" else "ICMP", "port": args.port}}
    if not args.approve_globalping:
        return {"created": False, "approval_required": True, "provider": "Globalping", "preview": payload}
    request = Request("https://api.globalping.io/v1/measurements", data=json.dumps(payload).encode(),
                      headers={"Content-Type": "application/json", "User-Agent": "AegisRoute/3.2"}, method="POST")
    with urlopen(request, timeout=20) as response:
        return {"created": True, "provider": "Globalping", "status": response.status, "response": json.loads(response.read().decode())}


def import_operator_evidence(path: str, kind: str) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, (dict, list)):
        raise ValueError(f"{kind} evidence must be a JSON object or array")
    count = len(value) if isinstance(value, list) else len(value.get("flows", value.get("records", [])))
    return {"mode": "operator-supplied-import", "kind": kind, "record_count": count, "data": value,
            "warning": "Imported evidence is contextual and is not treated as proof of Internet-path behavior."}


def cyclonedx_sbom(version: str, destination: str) -> dict[str, Any]:
    """Write a small, valid CycloneDX JSON SBOM for the stdlib-only package."""
    document = {"bomFormat": "CycloneDX", "specVersion": "1.5", "serialNumber": "urn:uuid:" + str(uuid.uuid4()), "version": 1,
                "metadata": {"timestamp": datetime.now(timezone.utc).isoformat(), "component": {"type": "application", "name": "aegisroute", "version": version, "licenses": [{"license": {"id": "MIT"}}]}},
                "components": []}
    output = Path(destination).expanduser(); output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    return {"path": str(output), "sha256": hashlib.sha256(output.read_bytes()).hexdigest(), "format": "CycloneDX-1.5"}


def alert_fingerprint(item: dict[str, Any]) -> str:
    stable = {key: item.get(key) for key in ("type", "protocol", "ttl", "detail")}
    return hashlib.sha256(json.dumps(stable, sort_keys=True).encode()).hexdigest()


def suppress_duplicate_alerts(report: dict[str, Any], state_path: str | None, cooldown_seconds: int) -> tuple[dict[str, Any], int]:
    if not state_path:
        return report, 0
    path = Path(state_path).expanduser(); now = int(time.time())
    try: state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError): state = {}
    kept, suppressed = [], 0
    for item in report.get("findings", []):
        fingerprint = alert_fingerprint(item)
        if now - int(state.get(fingerprint, 0)) < cooldown_seconds:
            suppressed += 1; continue
        state[fingerprint] = now; kept.append(item)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, sort_keys=True), encoding="utf-8")
    result = dict(report); result["findings"] = kept
    return result, suppressed

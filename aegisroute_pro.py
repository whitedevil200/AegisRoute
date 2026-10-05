"""AegisRoute 3.0 correlation, diagnostics, quality, reporting, and alert helpers."""

from __future__ import annotations

import hashlib
import html
import ipaddress
import json
import smtplib
import socket
import ssl
import statistics
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from email.message import EmailMessage
from typing import Any
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen


USER_AGENT = "AegisRoute/3.0"


def _json_get(url: str, timeout: float = 10.0) -> Any:
    request = Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    with urlopen(request, timeout=timeout) as response:
        return json.load(response)


def fetch_bgp_events(resources: list[str], hours: int = 24) -> dict[str, Any]:
    """Fetch RIPEstat BGP announcements/withdrawals for observed prefixes."""
    prefixes = []
    for resource in resources:
        try:
            prefixes.append(str(ipaddress.ip_network(resource, strict=False)))
        except ValueError:
            continue
    prefixes = list(dict.fromkeys(prefixes))[:50]
    if not prefixes:
        return {"provider": "RIPEstat", "resources": [], "event_count": 0, "events": [], "error": None}
    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=hours)
    params = {"resource": ",".join(prefixes), "starttime": start.isoformat(),
              "endtime": end.isoformat(), "unix_timestamps": "true", "sourceapp": "aegisroute"}
    url = "https://stat.ripe.net/data/bgp-updates/data.json?" + urlencode(params)
    try:
        payload = _json_get(url)
        data = payload.get("data", {}) if isinstance(payload, dict) else {}
        raw_events = data.get("updates", []) if isinstance(data.get("updates"), list) else []
        events = []
        for event in raw_events[-500:]:
            attrs = event.get("attrs") if isinstance(event.get("attrs"), dict) else {}
            path = attrs.get("path") or event.get("path") or []
            events.append({"type": event.get("type"), "timestamp": event.get("timestamp"),
                           "prefix": event.get("target_prefix"), "source": event.get("source_id"),
                           "path": path, "origin_asn": path[-1] if path else None})
        announcements = sum(event["type"] == "A" for event in events)
        withdrawals = sum(event["type"] == "W" for event in events)
        origins = sorted({str(event["origin_asn"]) for event in events if event["origin_asn"] is not None})
        return {"provider": "RIPEstat", "window_hours": hours, "resources": prefixes,
                "event_count": int(data.get("nr_updates", len(raw_events))),
                "returned_event_count": len(events), "announcements": announcements,
                "withdrawals": withdrawals, "origin_asns": origins, "events": events, "error": None}
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return {"provider": "RIPEstat", "window_hours": hours, "resources": prefixes,
                "event_count": 0, "events": [], "error": str(exc)}


def fetch_bgpstream_events(resources: list[str], hours: int = 24) -> dict[str, Any]:
    """Query a locally installed pybgpstream backend without making it mandatory."""
    prefixes = []
    for resource in resources:
        try:
            prefixes.append(str(ipaddress.ip_network(resource, strict=False)))
        except ValueError:
            continue
    prefixes = list(dict.fromkeys(prefixes))[:20]
    try:
        import pybgpstream  # type: ignore
    except ImportError:
        return {"provider": "BGPStream", "window_hours": hours, "resources": prefixes,
                "event_count": 0, "events": [], "error": "pybgpstream is not installed"}
    start = int((datetime.now(timezone.utc) - timedelta(hours=hours)).timestamp())
    end = int(datetime.now(timezone.utc).timestamp())
    events = []
    try:
        stream = pybgpstream.BGPStream(from_time=start, until_time=end, record_type="updates")
        for prefix in prefixes:
            stream.add_filter("prefix-more", prefix)
        for element in stream:
            fields = element.fields or {}
            as_path = str(fields.get("as-path", "")).split()
            events.append({"type": element.type, "timestamp": element.time,
                           "prefix": fields.get("prefix"), "source": getattr(element, "collector", None),
                           "peer_asn": getattr(element, "peer_asn", None), "path": as_path,
                           "origin_asn": as_path[-1] if as_path else None})
            if len(events) >= 500:
                break
        return {"provider": "BGPStream", "window_hours": hours, "resources": prefixes,
                "event_count": len(events), "returned_event_count": len(events),
                "announcements": sum(item["type"] == "A" for item in events),
                "withdrawals": sum(item["type"] == "W" for item in events),
                "origin_asns": sorted({item["origin_asn"] for item in events if item["origin_asn"]}),
                "events": events, "error": None}
    except Exception as exc:  # pybgpstream exposes backend-specific exception classes
        return {"provider": "BGPStream", "window_hours": hours, "resources": prefixes,
                "event_count": 0, "events": [], "error": str(exc)}


def service_diagnostics(host: str, address: str, port: int, timeout: float, tls_enabled: bool) -> dict[str, Any]:
    """Measure DNS, TCP connect, and optionally TLS without sending application data."""
    result: dict[str, Any] = {"host": host, "address": address, "port": port, "tcp_reachable": False,
                              "tcp_connect_ms": None, "tls": None, "error": None}
    started = time.monotonic()
    sock: socket.socket | None = None
    try:
        family = socket.AF_INET6 if ipaddress.ip_address(address).version == 6 else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((address, port))
        result["tcp_reachable"] = True
        result["tcp_connect_ms"] = round((time.monotonic() - started) * 1000, 3)
        if tls_enabled:
            tls_started = time.monotonic()
            context = ssl.create_default_context()
            server_name = host
            with context.wrap_socket(sock, server_hostname=server_name) as secured:
                sock = None
                certificate = secured.getpeercert()
                result["tls"] = {"handshake_ms": round((time.monotonic() - tls_started) * 1000, 3),
                                 "version": secured.version(), "cipher": secured.cipher()[0] if secured.cipher() else None,
                                 "subject": _cert_name(certificate.get("subject", [])),
                                 "issuer": _cert_name(certificate.get("issuer", [])),
                                 "not_before": certificate.get("notBefore"), "not_after": certificate.get("notAfter")}
    except (OSError, ssl.SSLError, ValueError) as exc:
        result["error"] = str(exc)
    finally:
        if sock is not None:
            sock.close()
    return result


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _cert_name(parts: Any) -> str | None:
    for group in parts:
        for key, value in group:
            if key == "commonName":
                return value
    return None


def parse_interface_extensions(raw: str) -> list[dict[str, Any]]:
    """Parse human-readable RFC 5837 fields emitted by traceroute implementations."""
    import re
    if not re.search(r"(?:interface|ifindex|ifname)", raw, re.IGNORECASE):
        return []
    roles = {"incoming": "incoming", "outgoing": "outgoing", "next-hop": "next-hop",
             "next hop": "next-hop", "sub-ip": "incoming-subinterface"}
    role = next((value for token, value in roles.items() if token in raw.lower()), "unspecified")
    item: dict[str, Any] = {"role": role}
    patterns = {"ifindex": r"(?:ifindex|index)\s*[=:]\s*(\d+)",
                "name": r"(?:ifname|name)\s*[=:]\s*([\w./:-]{1,63})",
                "mtu": r"mtu\s*[=:]\s*(\d+)",
                "address": r"(?:address|addr|ip)\s*[=:]\s*([0-9a-fA-F:.]+)"}
    for key, pattern in patterns.items():
        match = re.search(pattern, raw, re.IGNORECASE)
        if match:
            value: Any = match.group(1)
            if key in {"ifindex", "mtu"}:
                value = int(value)
            item[key] = value
    return [item] if len(item) > 1 else []


def mpls_analysis(report: dict[str, Any]) -> dict[str, Any]:
    observations = []
    labels: dict[int, list[dict[str, Any]]] = {}
    for trace in report.get("traces", []):
        for hop in trace.get("hops", []):
            for entry in hop.get("mpls_labels", []):
                row = {"protocol": trace.get("protocol"), "ttl": hop.get("ttl"), **entry}
                observations.append(row)
                labels.setdefault(int(entry["label"]), []).append(row)
    transitions = []
    ordered = sorted(observations, key=lambda item: (str(item["protocol"]), int(item["ttl"])))
    for left, right in zip(ordered, ordered[1:]):
        if left["protocol"] == right["protocol"] and left["label"] != right["label"]:
            transitions.append({"protocol": left["protocol"], "from_ttl": left["ttl"], "to_ttl": right["ttl"],
                                "from_label": left["label"], "to_label": right["label"]})
    return {"visible": bool(observations), "observations": observations,
            "unique_labels": sorted(labels), "label_transitions": transitions,
            "hidden_tunnel_detection": "requires optional TNT engine; no hidden hops are inferred from absence of labels"}


def historical_findings(previous: dict[str, Any] | None, current: dict[str, Any], latency_delta: float = 25.0) -> list[dict[str, Any]]:
    if not previous:
        return []
    findings = []
    old_traces = {trace.get("protocol"): trace for trace in previous.get("traces", [])}
    for trace in current.get("traces", []):
        old = old_traces.get(trace.get("protocol"))
        if not old:
            continue
        old_hops = {hop.get("ttl"): hop for hop in old.get("hops", [])}
        for hop in trace.get("hops", []):
            prior = old_hops.get(hop.get("ttl"))
            if not prior:
                continue
            ttl = hop.get("ttl")
            old_ips = {r.get("ip") for r in prior.get("responders", [])}
            new_ips = {r.get("ip") for r in hop.get("responders", [])}
            if old_ips != new_ips:
                findings.append(_finding("notice", trace.get("protocol"), ttl, "responder_change",
                                         f"responders changed from {sorted(old_ips)} to {sorted(new_ips)}", .85))
            old_avg, new_avg = prior.get("stats", {}).get("avg_ms"), hop.get("stats", {}).get("avg_ms")
            if old_avg is not None and new_avg is not None and new_avg - old_avg >= latency_delta:
                findings.append(_finding("warning", trace.get("protocol"), ttl, "persistent_latency_change",
                                         f"average RTT increased {new_avg - old_avg:.1f} ms between measurements", .7))
            old_loss = float(prior.get("stats", {}).get("loss_pct", 0))
            new_loss = float(hop.get("stats", {}).get("loss_pct", 0))
            if new_loss - old_loss >= 25:
                findings.append(_finding("warning", trace.get("protocol"), ttl, "loss_increase",
                                         f"diagnostic reply loss increased from {old_loss:.1f}% to {new_loss:.1f}%", .65))
            old_rpki = {r.get("rpki_status") for r in prior.get("responders", []) if r.get("rpki_status")}
            new_rpki = {r.get("rpki_status") for r in hop.get("responders", []) if r.get("rpki_status")}
            if old_rpki != new_rpki and new_rpki:
                findings.append(_finding("warning", trace.get("protocol"), ttl, "rpki_state_change",
                                         f"RPKI state changed from {sorted(old_rpki)} to {sorted(new_rpki)}", .9))
    return findings


def _finding(severity: str, protocol: str | None, ttl: int | None, kind: str, detail: str, confidence: float) -> dict[str, Any]:
    return {"severity": severity, "protocol": protocol or "unknown", "ttl": ttl, "type": kind,
            "detail": detail, "confidence": confidence,
            "evidence": ["Compared normalized consecutive AegisRoute measurements"],
            "alternative_explanations": ["ECMP selection", "diagnostic reply rate limiting", "transient routing change"]}


def quality_score(report: dict[str, Any]) -> dict[str, Any]:
    traces = report.get("traces", [])
    score = 100.0
    deductions = []
    if not traces:
        return {"score": 0, "grade": "F", "deductions": [{"points": 100, "reason": "no traces"}]}
    failed = sum(trace.get("return_code", 1) != 0 for trace in traces)
    if failed:
        points = min(40, failed * 20)
        score -= points; deductions.append({"points": points, "reason": f"{failed} failed trace engines"})
    hops = [hop for trace in traces for hop in trace.get("hops", [])]
    if hops:
        silent_ratio = sum(not hop.get("responders") for hop in hops) / len(hops)
        points = round(min(30, silent_ratio * 30), 1)
        score -= points
        if points:
            deductions.append({"points": points, "reason": f"{silent_ratio:.0%} silent hop observations"})
    destination = report.get("destination_ip")
    reached = any(r.get("ip") == destination for trace in traces for hop in trace.get("hops", []) for r in hop.get("responders", []))
    if not reached:
        score -= 20; deductions.append({"points": 20, "reason": "destination did not reply"})
    if report.get("settings", {}).get("backend") == "windows-tracert-icmp":
        score -= 5; deductions.append({"points": 5, "reason": "Windows backend cannot triangulate TCP/UDP"})
    score = max(0, round(score, 1))
    grade = "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 else "D" if score >= 60 else "F"
    return {"score": score, "grade": grade, "destination_reached": reached, "deductions": deductions}


def merge_reports(base: dict[str, Any], reports: list[dict[str, Any]]) -> dict[str, Any]:
    sources = []
    for index, report in enumerate(reports, 1):
        source = report.get("target", f"source-{index}")
        sources.append({"target": source, "destination_ip": report.get("destination_ip"),
                        "backend": report.get("settings", {}).get("backend")})
        for trace in report.get("traces", []):
            clone = json.loads(json.dumps(trace))
            clone["protocol"] = f"remote-{index}:{clone.get('protocol', 'unknown')}"
            clone.setdefault("metadata", {})["vantage_target"] = source
            base.setdefault("traces", []).append(clone)
        base.setdefault("findings", []).extend(report.get("findings", []))
    base["distributed_measurement"] = {"source_count": 1 + len(reports), "imported_sources": sources}
    return base


def alias_candidates(report: dict[str, Any], limit: int = 5) -> list[dict[str, Any]]:
    """Select bounded, evidence-bearing address pairs for active Ally testing."""
    candidates: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for trace in report.get("traces", []):
        prior = []
        for hop in trace.get("hops", []):
            current = [r for r in hop.get("responders", []) if _is_global(r.get("ip"))]
            pairs = []
            if len(current) > 1:
                pairs.extend((current[0], other, "same TTL multipath") for other in current[1:])
            for left in prior:
                for right in current:
                    if left.get("asn") and left.get("asn") == right.get("asn"):
                        pairs.append((left, right, "adjacent interfaces in the same ASN"))
            for left, right, basis in pairs:
                key = tuple(sorted((left["ip"], right["ip"])))
                if key in seen or key[0] == key[1]:
                    continue
                seen.add(key)
                candidates.append({"addresses": list(key), "basis": basis, "status": "candidate"})
                if len(candidates) >= limit:
                    return candidates
            prior = current
    return candidates


def _is_global(value: Any) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except (ValueError, TypeError):
        return False


def load_report_source(source: str, bearer_token: str | None = None) -> dict[str, Any]:
    parsed = urlparse(source)
    if parsed.scheme in {"https", "http"}:
        headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
        if bearer_token:
            headers["Authorization"] = f"Bearer {bearer_token}"
        with urlopen(Request(source, headers=headers), timeout=15) as response:
            value = json.load(response)
    else:
        with open(Path(source).expanduser(), encoding="utf-8") as handle:
            value = json.load(handle)
    if not isinstance(value, dict) or not isinstance(value.get("traces"), list):
        raise ValueError(f"not a AegisRoute-compatible report: {source}")
    return value


def html_report(report: dict[str, Any]) -> str:
    """Create a standalone, dependency-free investigation report."""
    esc = lambda value: html.escape(str(value))
    hop_rows = []
    for trace in report.get("traces", []):
        for hop in trace.get("hops", []):
            responders = ", ".join(r.get("rdns") or r.get("ip", "") for r in hop.get("responders", [])) or "silent"
            networks = ", ".join(f"AS{r['asn']} {r.get('rpki_status') or ''}" for r in hop.get("responders", []) if r.get("asn"))
            stats = hop.get("stats", {})
            hop_rows.append(f"<tr><td>{esc(trace.get('protocol'))}</td><td>{esc(hop.get('ttl'))}</td>"
                            f"<td>{esc(responders)}</td><td>{esc(networks)}</td><td>{esc(stats.get('avg_ms'))}</td>"
                            f"<td>{esc(stats.get('loss_pct'))}%</td></tr>")
    finding_rows = [f"<tr class='{esc(f.get('severity'))}'><td>{esc(f.get('severity'))}</td><td>{esc(f.get('type'))}</td>"
                    f"<td>{esc(f.get('protocol'))}/{esc(f.get('ttl') or '-')}</td><td>{esc(f.get('confidence', 0))}</td>"
                    f"<td>{esc(f.get('detail'))}</td></tr>" for f in report.get("findings", [])]
    quality = report.get("quality", {})
    embedded = html.escape(json.dumps(report, indent=2))
    return f"""<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width'>
<title>AegisRoute report — {esc(report.get('target'))}</title><style>
body{{font:14px ui-monospace,Consolas,monospace;background:#071018;color:#d7faff;margin:0}}main{{max-width:1200px;margin:auto;padding:28px}}
h1,h2{{color:#45f3ff}}.brand{{color:#bcff38}}.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}}
.card,table,details{{background:#0d1b26;border:1px solid #1d5361;border-radius:8px;padding:14px}}table{{border-collapse:collapse;width:100%;padding:0}}
th,td{{padding:8px;border-bottom:1px solid #193946;text-align:left}}th{{color:#ff61d8}}.warning{{color:#ffbd59}}.notice{{color:#ffe87a}}
pre{{white-space:pre-wrap;overflow-wrap:anywhere}}a{{color:#45f3ff}}</style></head><body><main>
<div class='brand'>{esc(report.get('company', 'Advaitik Intelligence'))} · AegisRoute {esc(report.get('tool_version'))}</div>
<h1>Route Intelligence Report</h1><div class='cards'><div class='card'>Target<br><strong>{esc(report.get('target'))}</strong></div>
<div class='card'>Destination<br><strong>{esc(report.get('destination_ip'))}</strong></div><div class='card'>Quality<br><strong>{esc(quality.get('score','?'))}/100 ({esc(quality.get('grade','?'))})</strong></div>
<div class='card'>Generated<br><strong>{esc(report.get('finished_at'))}</strong></div></div>
<h2>Observed hops</h2><table><thead><tr><th>Source</th><th>TTL</th><th>Responder</th><th>Routing</th><th>Avg RTT</th><th>Loss</th></tr></thead><tbody>{''.join(hop_rows)}</tbody></table>
<h2>Evidence-backed findings</h2><table><thead><tr><th>Severity</th><th>Type</th><th>Location</th><th>Confidence</th><th>Detail</th></tr></thead><tbody>{''.join(finding_rows)}</tbody></table>
<details><summary>Complete machine-readable evidence</summary><pre>{embedded}</pre></details></main></body></html>"""


def send_webhook(url: str, report: dict[str, Any], minimum: str = "warning") -> dict[str, Any]:
    levels = {"info": 0, "notice": 1, "warning": 2, "critical": 3}
    selected = [finding for finding in report.get("findings", [])
                if levels.get(finding.get("severity", "info"), 0) >= levels.get(minimum, 2)]
    if not selected:
        return {"sent": False, "reason": "no findings at or above threshold"}
    summary = f"AegisRoute {report.get('target')}: {len(selected)} finding(s), quality {report.get('quality', {}).get('score', '?')}/100"
    payload = json.dumps({"text": summary, "tool": "AegisRoute", "target": report.get("target"),
                          "quality": report.get("quality"), "findings": selected}).encode()
    request = Request(url, data=payload, headers={"User-Agent": USER_AGENT, "Content-Type": "application/json"}, method="POST")
    try:
        with urlopen(request, timeout=10) as response:
            return {"sent": True, "status": response.status, "finding_count": len(selected)}
    except OSError as exc:
        return {"sent": False, "error": str(exc), "finding_count": len(selected)}


def send_email(host: str, port: int, sender: str, recipient: str, report: dict[str, Any],
               minimum: str = "warning", username: str | None = None,
               password: str | None = None) -> dict[str, Any]:
    levels = {"info": 0, "notice": 1, "warning": 2, "critical": 3}
    selected = [finding for finding in report.get("findings", [])
                if levels.get(finding.get("severity", "info"), 0) >= levels.get(minimum, 2)]
    if not selected:
        return {"sent": False, "reason": "no findings at or above threshold"}
    message = EmailMessage()
    message["Subject"] = f"AegisRoute alert: {report.get('target')}"
    message["From"] = sender
    message["To"] = recipient
    lines = [f"Target: {report.get('target')}", f"Destination: {report.get('destination_ip')}",
             f"Quality: {report.get('quality', {}).get('score', '?')}/100", ""]
    lines.extend(f"[{item.get('severity')}] {item.get('type')}: {item.get('detail')}" for item in selected)
    message.set_content("\n".join(lines))
    try:
        with smtplib.SMTP(host, port, timeout=10) as smtp:
            smtp.starttls(context=ssl.create_default_context())
            if username:
                smtp.login(username, password or "")
            smtp.send_message(message)
        return {"sent": True, "finding_count": len(selected), "recipient": recipient}
    except (OSError, smtplib.SMTPException) as exc:
        return {"sent": False, "error": str(exc), "finding_count": len(selected)}


def report_digest(report: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(report, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

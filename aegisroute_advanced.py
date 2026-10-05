"""Advanced analysis, storage, routing-security, and export helpers for AegisRoute."""

from __future__ import annotations

import asyncio
from contextlib import closing
import hashlib
import ipaddress
import json
import sqlite3
import statistics
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlencode
from urllib.request import Request, urlopen


USER_AGENT = "AegisRoute/3.0"


def _get_json(url: str, timeout: float = 6.0) -> dict[str, Any] | list[Any] | None:
    try:
        request = Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
        with urlopen(request, timeout=timeout) as response:
            return json.load(response)
    except (OSError, ValueError, json.JSONDecodeError):
        return None


def _route_security_sync(ip: str, asn: int | None, prefix: str | None) -> tuple[str, dict[str, Any]]:
    result: dict[str, Any] = {"rpki_status": None, "routing_visibility": None, "announced": None}
    if not asn or not prefix:
        info_url = "https://stat.ripe.net/data/network-info/data.json?" + urlencode({"resource": ip})
        info = _get_json(info_url)
        data = info.get("data", {}) if isinstance(info, dict) else {}
        prefix = prefix or data.get("prefix")
        asns = data.get("asns") or []
        asn = asn or (int(asns[0]) if asns else None)
    result.update({"asn": asn, "prefix": prefix})
    if asn and prefix:
        rpki_url = "https://stat.ripe.net/data/rpki-validation/data.json?" + urlencode(
            {"resource": str(asn), "prefix": prefix}
        )
        rpki = _get_json(rpki_url)
        data = rpki.get("data", {}) if isinstance(rpki, dict) else {}
        result["rpki_status"] = data.get("status")
        status_url = "https://stat.ripe.net/data/routing-status/data.json?" + urlencode({"resource": prefix})
        status = _get_json(status_url)
        route_data = status.get("data", {}) if isinstance(status, dict) else {}
        result["announced"] = bool(route_data.get("origins") or route_data.get("announced_space")) if route_data else None
        result["routing_visibility"] = route_data.get("visibility")
    return ip, result


async def route_security_lookup(items: list[tuple[str, int | None, str | None]], concurrency: int = 6) -> dict[str, dict[str, Any]]:
    semaphore = asyncio.Semaphore(max(1, min(concurrency, 8)))
    loop = asyncio.get_running_loop()

    async def one(item: tuple[str, int | None, str | None]) -> tuple[str, dict[str, Any]]:
        async with semaphore:
            return await loop.run_in_executor(None, _route_security_sync, *item)

    return dict(await asyncio.gather(*(one(item) for item in items)))


def _ixp_sync(ip: str) -> tuple[str, str | None]:
    url = "https://www.peeringdb.com/api/ixpfx?" + urlencode({"prefix__contains": ip, "depth": 2})
    payload = _get_json(url)
    rows = payload.get("data", []) if isinstance(payload, dict) else []
    address = ipaddress.ip_address(ip)
    for row in rows:
        try:
            if address not in ipaddress.ip_network(row.get("prefix", ""), strict=False):
                continue
        except ValueError:
            continue
        ixlan = row.get("ixlan") or {}
        ix = ixlan.get("ix") if isinstance(ixlan, dict) else {}
        name = (ix or {}).get("name") if isinstance(ix, dict) else None
        return ip, name or f"PeeringDB IXP LAN {row.get('ixlan_id', 'unknown')}"
    return ip, None


async def ixp_lookup(ips: list[str], concurrency: int = 4) -> dict[str, str]:
    semaphore = asyncio.Semaphore(max(1, min(concurrency, 4)))
    loop = asyncio.get_running_loop()

    async def one(ip: str) -> tuple[str, str | None]:
        async with semaphore:
            return await loop.run_in_executor(None, _ixp_sync, ip)

    return {ip: value for ip, value in await asyncio.gather(*(one(ip) for ip in ips)) if value}


def parse_mpls_extensions(raw: str) -> list[dict[str, int]]:
    import re
    labels: list[dict[str, int]] = []
    pattern = re.compile(
        r"MPLS(?:(?:\s+Label=)|:?[\s\[]+)(?P<label>\d+).*?"
        r"(?:Exp|TC)=(?P<tc>\d+).*?TTL=(?P<ttl>\d+).*?(?:S|BoS)=(?P<bos>\d+)",
        re.IGNORECASE,
    )
    for match in pattern.finditer(raw):
        labels.append({"label": int(match.group("label")), "traffic_class": int(match.group("tc")),
                       "ttl": int(match.group("ttl")), "bottom_of_stack": int(match.group("bos"))})
    return labels


def build_fusion_graph(report: dict[str, Any]) -> dict[str, Any]:
    node_map: dict[str, dict[str, Any]] = {}
    edge_map: dict[tuple[str, str], dict[str, Any]] = {}
    for trace in report.get("traces", []):
        protocol = trace.get("protocol", "unknown")
        previous: list[str] = ["source"]
        node_map.setdefault("source", {"id": "source", "kind": "source", "ttls": [0], "protocols": []})
        for hop in trace.get("hops", []):
            current = [responder["ip"] for responder in hop.get("responders", [])] or [f"silent:{hop['ttl']}"]
            for responder in hop.get("responders", []):
                node = node_map.setdefault(responder["ip"], {"id": responder["ip"], "kind": "router",
                                                             "ttls": [], "protocols": [], "asn": responder.get("asn")})
                if hop["ttl"] not in node["ttls"]:
                    node["ttls"].append(hop["ttl"])
                if protocol not in node["protocols"]:
                    node["protocols"].append(protocol)
            for node_id in current:
                if node_id.startswith("silent:"):
                    node_map.setdefault(node_id, {"id": node_id, "kind": "silent", "ttls": [hop["ttl"]], "protocols": [protocol]})
            for left in previous:
                for right in current:
                    edge = edge_map.setdefault((left, right), {"source": left, "target": right, "protocols": [], "observations": 0})
                    edge["observations"] += 1
                    if protocol not in edge["protocols"]:
                        edge["protocols"].append(protocol)
            previous = current
    return {"nodes": list(node_map.values()), "edges": list(edge_map.values()),
            "protocol_count": len(report.get("traces", [])), "generated_at": datetime.now(timezone.utc).isoformat()}


def evidence_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    defaults = {
        "silent_hop": (0.35, ["No diagnostic reply was received at this TTL"],
                       ["ICMP rate limiting", "firewall filtering", "router control-plane policy"]),
        "latency_jump": (0.55, ["Average RTT exceeded the configured hop-to-hop threshold"],
                         ["asymmetric return path", "ICMP processing delay", "transient congestion"]),
        "multipath": (0.8, ["Multiple unique responder addresses appeared at one TTL"],
                      ["per-flow ECMP", "per-packet load balancing", "address aliasing"]),
        "possible_loop": (0.45, ["A responder address appeared at multiple TTL values"],
                          ["transparent proxy", "address reuse", "tunnel artifact"]),
        "path_divergence": (0.8, ["Protocol route signatures were not identical"],
                            ["ECMP hashing", "protocol policy", "measurement timing"]),
        "incomplete": (0.7, ["The destination address did not return a terminal response"],
                       ["destination filtering", "hop limit reached", "return-path filtering"]),
        "baseline_change": (0.85, ["Current and saved route signatures differ"],
                            ["normal traffic engineering", "ECMP selection", "routing event"]),
        "rpki_invalid": (0.9, ["RIPEstat returned an invalid RPKI origin validation state"],
                         ["stale public data", "a recently changed ROA", "incorrect origin metadata"]),
        "unannounced_prefix": (0.65, ["RIPEstat did not report the prefix as announced"],
                               ["collector visibility gap", "recent routing change", "incorrect prefix inference"]),
    }
    for finding in findings:
        confidence, evidence, alternatives = defaults.get(
            finding.get("type"), (0.5, [finding.get("detail", "Observed by analyzer")], ["measurement artifact"])
        )
        finding.setdefault("confidence", confidence)
        finding.setdefault("evidence", evidence)
        finding.setdefault("alternative_explanations", alternatives)
    return findings


def route_fingerprint(report: dict[str, Any]) -> str:
    canonical = [[trace.get("protocol"), [[r.get("ip") for r in hop.get("responders", [])]
                                           for hop in trace.get("hops", [])]]
                 for trace in report.get("traces", [])]
    return hashlib.sha256(json.dumps(canonical, separators=(",", ":"), sort_keys=True).encode()).hexdigest()


class MeasurementStore:
    def __init__(self, path: str):
        self.path = str(Path(path).expanduser())

    def _connect(self) -> sqlite3.Connection:
        path = Path(self.path)
        path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(path, timeout=10)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA foreign_keys=ON")
        connection.executescript("""
            CREATE TABLE IF NOT EXISTS measurements (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                recorded_at TEXT NOT NULL,
                target TEXT NOT NULL,
                destination_ip TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                report_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_measurements_target_time
                ON measurements(target, recorded_at DESC);
            CREATE TABLE IF NOT EXISTS findings (
                measurement_id INTEGER NOT NULL REFERENCES measurements(id) ON DELETE CASCADE,
                severity TEXT, type TEXT, protocol TEXT, ttl INTEGER, confidence REAL, detail TEXT
            );
            CREATE TABLE IF NOT EXISTS enrichment_cache (
                module TEXT NOT NULL,
                resource TEXT NOT NULL,
                expires_at REAL NOT NULL,
                value_json TEXT NOT NULL,
                PRIMARY KEY(module, resource)
            );
        """)
        return connection

    def save(self, report: dict[str, Any]) -> int:
        with closing(self._connect()) as connection, connection:
            cursor = connection.execute(
                "INSERT INTO measurements(recorded_at,target,destination_ip,fingerprint,report_json) VALUES(?,?,?,?,?)",
                (report.get("finished_at"), report.get("target"), report.get("destination_ip"),
                 route_fingerprint(report), json.dumps(report, separators=(",", ":"))),
            )
            measurement_id = int(cursor.lastrowid)
            connection.executemany(
                "INSERT INTO findings VALUES(?,?,?,?,?,?,?)",
                [(measurement_id, f.get("severity"), f.get("type"), f.get("protocol"), f.get("ttl"),
                  f.get("confidence"), f.get("detail")) for f in report.get("findings", [])],
            )
            return measurement_id

    def history(self, target: str, limit: int = 20) -> list[dict[str, Any]]:
        with closing(self._connect()) as connection, connection:
            rows = connection.execute(
                "SELECT id,recorded_at,destination_ip,fingerprint,report_json FROM measurements "
                "WHERE target=? ORDER BY id DESC LIMIT ?", (target, max(1, min(limit, 1000))),
            ).fetchall()
        return [{"id": row[0], "recorded_at": row[1], "destination_ip": row[2], "fingerprint": row[3],
                 "report": json.loads(row[4])} for row in rows]

    def cache_get(self, module: str, resources: list[str]) -> dict[str, Any]:
        if not resources:
            return {}
        placeholders = ",".join("?" for _ in resources)
        with closing(self._connect()) as connection, connection:
            rows = connection.execute(
                f"SELECT resource,value_json FROM enrichment_cache WHERE module=? AND expires_at>? "
                f"AND resource IN ({placeholders})", (module, time.time(), *resources),
            ).fetchall()
        result = {}
        for resource, value in rows:
            try:
                result[resource] = json.loads(value)
            except json.JSONDecodeError:
                continue
        return result

    def cache_set(self, module: str, values: dict[str, Any], ttl_seconds: float = 86400) -> None:
        if not values:
            return
        expires = time.time() + ttl_seconds
        with closing(self._connect()) as connection, connection:
            connection.executemany(
                "INSERT INTO enrichment_cache(module,resource,expires_at,value_json) VALUES(?,?,?,?) "
                "ON CONFLICT(module,resource) DO UPDATE SET expires_at=excluded.expires_at,value_json=excluded.value_json",
                [(module, key, expires, json.dumps(value, separators=(",", ":"))) for key, value in values.items()],
            )


def prometheus_text(report: dict[str, Any]) -> str:
    def esc(value: Any) -> str:
        return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")

    target = esc(report.get("target", ""))
    lines = ["# HELP aegisroute_target_reachable Whether the destination replied.",
             "# TYPE aegisroute_target_reachable gauge",
             "# HELP aegisroute_hop_rtt_milliseconds Average hop round-trip time.",
             "# TYPE aegisroute_hop_rtt_milliseconds gauge",
             "# HELP aegisroute_hop_loss_ratio Fraction of probes without a reply.",
             "# TYPE aegisroute_hop_loss_ratio gauge"]
    for trace in report.get("traces", []):
        protocol = esc(trace.get("protocol", ""))
        destination = report.get("destination_ip")
        reached = any(r.get("ip") == destination for h in trace.get("hops", []) for r in h.get("responders", []))
        lines.append(f'aegisroute_target_reachable{{target="{target}",protocol="{protocol}"}} {1 if reached else 0}')
        for hop in trace.get("hops", []):
            stats = hop.get("stats", {})
            labels = f'target="{target}",protocol="{protocol}",ttl="{hop.get("ttl")}"'
            lines.append(f'aegisroute_hop_loss_ratio{{{labels}}} {float(stats.get("loss_pct", 100))/100:.6f}')
            if stats.get("avg_ms") is not None:
                lines.append(f'aegisroute_hop_rtt_milliseconds{{{labels}}} {stats["avg_ms"]}')
    lines.extend(["# HELP aegisroute_findings_total Findings in the latest measurement.",
                  "# TYPE aegisroute_findings_total gauge"])
    counts: dict[tuple[str, str], int] = {}
    for finding in report.get("findings", []):
        key = (finding.get("severity", "unknown"), finding.get("type", "unknown"))
        counts[key] = counts.get(key, 0) + 1
    for (severity, kind), count in counts.items():
        lines.append(f'aegisroute_findings_total{{target="{target}",severity="{esc(severity)}",type="{esc(kind)}"}} {count}')
    if report.get("quality", {}).get("score") is not None:
        lines.extend(["# HELP aegisroute_measurement_quality_score Measurement completeness score from 0 to 100.",
                      "# TYPE aegisroute_measurement_quality_score gauge",
                      f'aegisroute_measurement_quality_score{{target="{target}"}} {report["quality"]["score"]}'])
    service = report.get("service_diagnostics")
    if service:
        lines.extend(["# HELP aegisroute_service_tcp_reachable Whether the configured TCP service connected.",
                      "# TYPE aegisroute_service_tcp_reachable gauge",
                      f'aegisroute_service_tcp_reachable{{target="{target}",port="{service.get("port")}"}} {1 if service.get("tcp_reachable") else 0}'])
        if service.get("tcp_connect_ms") is not None:
            lines.extend(["# HELP aegisroute_service_tcp_connect_milliseconds TCP connection establishment time.",
                          "# TYPE aegisroute_service_tcp_connect_milliseconds gauge"])
            lines.append(f'aegisroute_service_tcp_connect_milliseconds{{target="{target}",port="{service.get("port")}"}} {service["tcp_connect_ms"]}')
    bgp = report.get("bgp_correlation")
    if bgp:
        lines.extend(["# HELP aegisroute_bgp_updates_total BGP updates in the selected correlation window.",
                      "# TYPE aegisroute_bgp_updates_total gauge",
                      f'aegisroute_bgp_updates_total{{target="{target}"}} {bgp.get("event_count", 0)}'])
    return "\n".join(lines) + "\n"


def fetch_atlas_results(measurement_id: int) -> list[dict[str, Any]]:
    url = f"https://atlas.ripe.net/api/v2/measurements/{measurement_id}/results/?format=json"
    data = _get_json(url, timeout=15)
    return data if isinstance(data, list) else []


def normalize_atlas_results(measurement_id: int, results: list[dict[str, Any]], company: str) -> dict[str, Any]:
    """Convert public RIPE Atlas traceroute results to the AegisRoute v3 model."""
    traces: list[dict[str, Any]] = []
    destination = next((row.get("dst_addr") for row in results if row.get("dst_addr")), "unknown")
    timestamps = [row.get("timestamp") for row in results if isinstance(row.get("timestamp"), (int, float))]

    def stats(rtts: list[float], sent: int, timeouts: int) -> dict[str, float | None]:
        return {"loss_pct": round(timeouts / sent * 100, 1) if sent else 100.0,
                "min_ms": round(min(rtts), 3) if rtts else None,
                "avg_ms": round(statistics.fmean(rtts), 3) if rtts else None,
                "max_ms": round(max(rtts), 3) if rtts else None,
                "jitter_ms": round(statistics.pstdev(rtts), 3) if len(rtts) > 1 else 0.0 if rtts else None}

    for row in results:
        hops = []
        if not isinstance(row.get("result"), list):
            continue
        for raw_hop in row["result"]:
            ttl = raw_hop.get("hop")
            if not isinstance(ttl, int):
                continue
            replies = raw_hop.get("result") if isinstance(raw_hop.get("result"), list) else []
            responder_map: dict[str, list[float]] = {}
            timeouts = 0
            for reply in replies:
                if not isinstance(reply, dict) or "x" in reply:
                    timeouts += 1
                    continue
                address = reply.get("from")
                try:
                    address = str(ipaddress.ip_address(address))
                except (ValueError, TypeError):
                    timeouts += 1
                    continue
                responder_map.setdefault(address, [])
                if isinstance(reply.get("rtt"), (int, float)):
                    responder_map[address].append(float(reply["rtt"]))
            sent = max(len(replies), len(responder_map), 1)
            responders = [{"ip": ip, "rtts_ms": values, "annotations": [], "rdns": None,
                           "asn": None, "as_name": None, "prefix": None, "country": None,
                           "city": None, "network_scope": "atlas-observed", "rpki_status": None,
                           "routing_visibility": None, "announced": None, "ixp_name": None}
                          for ip, values in responder_map.items()]
            all_rtts = [value for values in responder_map.values() for value in values]
            hops.append({"ttl": ttl, "sent": sent, "timeouts": max(timeouts, sent - len(all_rtts)),
                         "stats": stats(all_rtts, sent, max(timeouts, sent - len(all_rtts))),
                         "responders": responders, "mpls_labels": [], "raw": ""})
        if hops:
            probe_id = row.get("prb_id", "unknown")
            traces.append({"protocol": f"atlas-{str(row.get('proto', 'trace')).lower()}-probe-{probe_id}",
                           "command": [], "duration_ms": 0.0, "return_code": 0, "stderr": "",
                           "metadata": {"backend": "ripe-atlas", "probe_id": probe_id,
                                        "source_address": row.get("src_addr"), "af": row.get("af"),
                                        "measurement_id": measurement_id}, "hops": hops})
    now = datetime.now(timezone.utc).isoformat()
    started = datetime.fromtimestamp(min(timestamps), timezone.utc).isoformat() if timestamps else now
    report: dict[str, Any] = {"schema": "aegisroute/v3", "tool_version": "3.0.0", "company": company,
                              "theme": "cyber", "started_at": started, "finished_at": now,
                              "target": f"ripe-atlas:{measurement_id}", "destination_ip": destination,
                              "settings": {"backend": "ripe-atlas", "measurement_id": measurement_id,
                                           "result_count": len(results), "actual_protocols": [t["protocol"] for t in traces]},
                              "traces": traces, "findings": []}
    if not traces:
        report["findings"] = evidence_findings([{"severity": "warning", "protocol": "atlas", "ttl": None,
                                                  "type": "incomplete", "detail": "no traceroute results were returned"}])
    report["fusion_graph"] = build_fusion_graph(report)
    return report

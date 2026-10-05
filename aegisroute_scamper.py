"""Optional Scamper JSON adapter for Paris traceroute and genuine MDA discovery."""

from __future__ import annotations

import ipaddress
import json
import os
import tempfile
from pathlib import Path
from typing import Any


def build_scamper_command(binary: str, destination: str, protocol: str, strategy: str,
                          probes: int, first_hop: int, max_hops: int, wait: float,
                          port: int, confidence: int, max_probes: int = 1000) -> tuple[list[str], str]:
    """Return a Scamper invocation and the embedded measurement command."""
    if strategy == "mda":
        methods = {"udp": "udp-dport", "icmp": "icmp-echo", "tcp": "tcp-ack-sport"}
        method = methods.get(protocol, "udp-dport")
        measurement = (f"tracelb -P {method} -c {confidence} -f {first_hop} -q {probes} "
                       f"-Q {max_probes} -w {max(1, round(wait))}")
        if protocol in {"udp", "tcp"}:
            measurement += f" -d {port}"
    else:
        methods = {"udp": "udp-paris", "icmp": "icmp-paris", "tcp": "tcp"}
        method = methods.get(protocol, "udp-paris")
        measurement = f"trace -P {method} -q {probes} -f {first_hop} -m {max_hops} -w {max(1, round(wait))}"
        if protocol in {"udp", "tcp"}:
            measurement += f" -d {port}"
    measurement += f" {destination}"
    return [binary, "-O", "json", "-o", "{output}", "-I", measurement], measurement


def _rtt_ms(value: Any) -> float | None:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.rstrip(" ms"))
        except ValueError:
            return None
    if isinstance(value, dict):
        if "usec" in value or "sec" in value:
            return float(value.get("sec", 0)) * 1000 + float(value.get("usec", 0)) / 1000
        if "ms" in value:
            return _rtt_ms(value["ms"])
    return None


def _valid_ip(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def _walk(value: Any):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk(child)


def normalize_scamper_json(payload: dict[str, Any], probes: int) -> list[dict[str, Any]]:
    """Normalize trace/tracelb JSON across Scamper schema generations."""
    observations: dict[int, dict[str, list[float]]] = {}

    def add(ttl: Any, reply: Any) -> None:
        if not isinstance(reply, dict) or not isinstance(ttl, int):
            return
        address = _valid_ip(reply.get("from") or reply.get("addr") or reply.get("src"))
        if not address:
            return
        rtt = _rtt_ms(reply.get("rtt"))
        observations.setdefault(ttl, {}).setdefault(address, [])
        if rtt is not None:
            observations[ttl][address].append(rtt)

    explicit_hops = payload.get("hops") if isinstance(payload.get("hops"), list) else []
    for hop in explicit_hops:
        ttl = hop.get("probe_ttl") or hop.get("ttl") or hop.get("hop")
        replies = hop.get("replies") or hop.get("result") or []
        add(ttl, hop)
        if not isinstance(replies, list):
            replies = [replies]
        for reply in replies:
            add(ttl, reply)
    # tracelb stores replies under nodes -> links -> probes; a probe's TTL
    # applies to each reply below it.
    for node in payload.get("nodes", []) if isinstance(payload.get("nodes"), list) else []:
        for item in _walk(node.get("links", [])):
            candidate_probes = item.get("probes")
            if not isinstance(candidate_probes, list):
                continue
            for probe in candidate_probes:
                if not isinstance(probe, dict):
                    continue
                ttl = probe.get("ttl") or probe.get("probe_ttl")
                replies = probe.get("replies") or probe.get("reply") or []
                if not isinstance(replies, list):
                    replies = [replies]
                for reply in replies:
                    add(ttl, reply)
    if not observations:
        for item in _walk(payload):
            ttl = item.get("probe_ttl") or item.get("ttl") or item.get("hop")
            address = _valid_ip(item.get("from") or item.get("addr"))
            if not address or not isinstance(ttl, int) or ttl < 1:
                continue
            rtt = _rtt_ms(item.get("rtt"))
            observations.setdefault(ttl, {}).setdefault(address, [])
            if rtt is not None:
                observations[ttl][address].append(rtt)
    result = []
    for ttl in sorted(observations):
        responders = [{"ip": ip, "rtts_ms": rtts} for ip, rtts in observations[ttl].items()]
        replies = sum(max(1, len(item["rtts_ms"])) for item in responders)
        sent = max(probes, replies)
        result.append({"ttl": ttl, "sent": sent, "timeouts": max(0, sent - replies),
                       "responders": responders})
    return result


def load_json_records(path: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with open(path, encoding="utf-8", errors="replace") as handle:
        for line in handle:
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                records.append(value)
    return records


def output_path() -> str:
    fd, path = tempfile.mkstemp(prefix="aegisroute-scamper-", suffix=".json")
    os.close(fd)
    return str(Path(path))


def build_ally_command(binary: str, left: str, right: str, output: str) -> list[str]:
    """Build a bounded Scamper Ally alias-resolution measurement."""
    measurement = ("dealias -m ally -f 200 -q 5 "
                   f"-p '-P icmp-echo -i {left}' -p '-P icmp-echo -i {right}'")
    return [binary, "-O", "json", "-o", output, "-I", measurement]


def ally_result(records: list[dict[str, Any]], left: str, right: str) -> str:
    """Return confirmed, rejected, or inconclusive without upgrading weak evidence."""
    for record in records:
        aliases = record.get("aliases")
        if isinstance(aliases, list):
            flattened = {str(item) for item in aliases}
            if {left, right}.issubset(flattened):
                return "confirmed"
        for item in _walk(record):
            result = str(item.get("result", "")).lower()
            if result in {"aliases", "alias"}:
                return "confirmed"
            if result in {"not aliases", "not-aliases", "not_aliases"}:
                return "rejected"
    return "inconclusive"

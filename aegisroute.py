#!/usr/bin/env python3
"""AegisRoute - fast, multi-protocol Linux route intelligence."""

from __future__ import annotations

import argparse
import asyncio
import csv
import ipaddress
import json
import math
import os
import re
import shutil
import signal
import socket
import statistics
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from aegisroute_advanced import (MeasurementStore, build_fusion_graph, evidence_findings,
                                fetch_atlas_results, ixp_lookup, parse_mpls_extensions,
                                prometheus_text, route_security_lookup, normalize_atlas_results)
from aegisroute_scamper import (ally_result, build_ally_command, build_scamper_command,
                               load_json_records, normalize_scamper_json, output_path)
from aegisroute_pro import (alias_candidates, fetch_bgp_events, fetch_bgpstream_events,
                           historical_findings, html_report,
                           load_report_source, merge_reports, mpls_analysis,
                           parse_interface_extensions, quality_score,
                           send_email, send_webhook, service_diagnostics)

VERSION = "3.0.0"
DEFAULT_COMPANY = "Advaitik Intelligence"
CGNAT_NETWORK = ipaddress.ip_network("100.64.0.0/10")
IP_RE = re.compile(r"(?<![\w:])(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]{2,})(?![\w:])")
HOP_RE = re.compile(r"^\s*(\d+)\s+(.*)$")
RTT_RE = re.compile(r"(?P<rtt>\d+(?:\.\d+)?)\s*ms\b")
ANSI = {"reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m", "red": "\033[31m",
        "green": "\033[32m", "yellow": "\033[33m", "cyan": "\033[36m", "magenta": "\033[35m"}
THEMES = {
    "cyber": {"primary": "\033[38;5;51m", "secondary": "\033[38;5;201m", "accent": "\033[38;5;118m", "warn": "\033[38;5;214m"},
    "ocean": {"primary": "\033[38;5;39m", "secondary": "\033[38;5;45m", "accent": "\033[38;5;87m", "warn": "\033[38;5;221m"},
    "amber": {"primary": "\033[38;5;220m", "secondary": "\033[38;5;208m", "accent": "\033[38;5;228m", "warn": "\033[38;5;196m"},
    "mono": {"primary": "\033[1m", "secondary": "\033[2m", "accent": "\033[1m", "warn": "\033[1m"},
}
_ENRICHMENT_CACHE: dict[str, dict[str, tuple[float, Any]]] = {}
CACHE_TTL_SECONDS = 3600.0
BANNER = (
    "██████╗  █████╗ ████████╗██╗  ██╗███████╗ ██████╗ ██████╗ ██████╗ ███████╗",
    "██╔══██╗██╔══██╗╚══██╔══╝██║  ██║██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝",
    "██████╔╝███████║   ██║   ███████║███████╗██║     ██║   ██║██████╔╝█████╗  ",
    "██╔═══╝ ██╔══██║   ██║   ██╔══██║╚════██║██║     ██║   ██║██╔═══╝ ██╔══╝  ",
    "██║     ██║  ██║   ██║   ██║  ██║███████║╚██████╗╚██████╔╝██║     ███████╗",
    "╚═╝     ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚══════╝",
)


class HelpFormatter(argparse.RawDescriptionHelpFormatter, argparse.ArgumentDefaultsHelpFormatter):
    """Preserve examples while still showing defaults beside every option."""


HELP_DESCRIPTION = """\
AegisRoute performs TTL-limited route measurement and turns router replies into
human-readable route intelligence. It can launch UDP, TCP, and ICMP traces in
parallel, correlate different paths, enrich public hop addresses, and detect
conditions such as silent hops, latency jumps, loops, and ECMP multipath.

HOW IT WORKS
  1. The target is resolved to IPv4 or IPv6.
  2. The native backend sends probes with increasing TTL/hop-limit values
     (Linux traceroute for full mode; Windows tracert for ICMP compatibility).
  3. Routers return TTL-expired messages; AegisRoute parses their addresses/RTTs.
  4. Optional DNS, ASN/prefix, geo, RPKI, and IXP lookups annotate public hops.
  5. The analysis engine produces evidence-backed findings and table, JSON,
     JSONL, CSV, or Prometheus output.
  6. A fusion graph correlates protocols; optional SQLite retains route history.

Run with no target in an interactive terminal to open the guided selection menu.
Use --demo to exercise the complete interface without sending network packets.
Windows real-target mode automatically uses ICMP tracert; full TCP/UDP and
advanced flow controls require Linux.
"""


HELP_EPILOG = """\
KEY DEFINITIONS
  TTL/hop limit       Maximum number of routers a probe can cross.
  RTT                 Round-trip time from this system to a responding hop.
  Jitter              Variation (population standard deviation) among hop RTTs.
  Loss                Probes at a TTL that did not produce a reply. Intermediate
                      loss can be ICMP rate limiting and is not proof of data loss.
  ECMP/multipath      More than one router responded at the same TTL.
  ASN                 Autonomous System Number identifying a routed network.
  Flow consistency    Pins ports where supported to reduce load-balancer variance.
  Paris traceroute    Holds flow identifiers stable to reduce ECMP path mixing.
  MDA                 Multipath Detection Algorithm; discovers per-flow branches
                      to a selected statistical confidence using Scamper tracelb.
  BGP correlation     Compares observed prefixes with control-plane announcements
                      and withdrawals; it does not prove causation by itself.
  Alias resolution    Tests whether two IP interfaces belong to one router. Only
                      a positive Scamper Ally result is labeled confirmed.
  Quality score       Measurement completeness score, not a network health score.

COMMON EXAMPLES
  aegisroute                         Guided interactive mode
  aegisroute --demo                  Safe interface preview; sends no packets
  aegisroute example.com             UDP + TCP + ICMP trace with DNS/ASN context
  aegisroute 1.1.1.1 -P tcp -p 443  Trace the HTTPS path only
  aegisroute example.com --no-enrich Keep all hop addresses away from lookup services
  aegisroute example.com --format json -o trace.json
  aegisroute example.com --watch 30 --format jsonl -o history.jsonl
  aegisroute example.com --enrich rdns,asn,rpki,ixp --store routes.db
  aegisroute example.com --format prometheus -o aegisroute.prom
  aegisroute example.com --store routes.db --history 20
  aegisroute --atlas-id 12345678     Import an existing RIPE Atlas measurement
  aegisroute --atlas-ids 123,456     Fuse multiple Atlas measurement vantages
  aegisroute example.com --bgp-events --service-check --tls-check
  aegisroute example.com --format html -o investigation.html
  aegisroute example.com --watch 30 --tui --store routes.db
  aegisroute example.com --merge-report remote.json --format json
  aegisroute --doctor                Check Linux runtime and traceroute dependency

PRIVACY
  rdns performs PTR DNS queries. asn sends public hop IPs to Team Cymru bulk WHOIS.
  geo sends public hop IPs to ipwho.is; rpki sends prefix/ASN data to RIPEstat;
  ixp queries PeeringDB. --no-enrich disables all enrichment traffic.
  --bgp-events queries RIPEstat. --remote-report fetches the supplied HTTPS URL.
  Alerts transmit findings only when explicitly configured.

EXIT STATUS
  0 success (at least one probe engine succeeded); 2 configuration/dependency or
  total probe failure; 130 interrupted by Ctrl+C. An incomplete route can still
  exit 0 because routers commonly suppress diagnostic replies.

More documentation: man aegisroute, or the installed README.
"""


@dataclass
class Responder:
    ip: str
    rtts_ms: list[float] = field(default_factory=list)
    annotations: list[str] = field(default_factory=list)
    rdns: str | None = None
    asn: int | None = None
    as_name: str | None = None
    prefix: str | None = None
    country: str | None = None
    city: str | None = None
    network_scope: str | None = None
    rpki_status: str | None = None
    routing_visibility: Any = None
    announced: bool | None = None
    ixp_name: str | None = None


@dataclass
class Hop:
    ttl: int
    sent: int
    timeouts: int
    responders: list[Responder]
    raw: str = ""
    mpls_labels: list[dict[str, int]] = field(default_factory=list)
    interface_extensions: list[dict[str, Any]] = field(default_factory=list)

    def all_rtts(self) -> list[float]:
        return [rtt for responder in self.responders for rtt in responder.rtts_ms]

    def stats(self) -> dict[str, float | None]:
        values = self.all_rtts()
        loss = (self.timeouts / self.sent * 100.0) if self.sent else 100.0
        return {
            "loss_pct": round(loss, 1),
            "min_ms": round(min(values), 3) if values else None,
            "avg_ms": round(statistics.fmean(values), 3) if values else None,
            "max_ms": round(max(values), 3) if values else None,
            "jitter_ms": round(statistics.pstdev(values), 3) if len(values) > 1 else 0.0 if values else None,
        }


@dataclass
class Trace:
    protocol: str
    command: list[str]
    hops: list[Hop]
    duration_ms: float
    return_code: int
    stderr: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def color(text: str, name: str, enabled: bool) -> str:
    return f"{ANSI[name]}{text}{ANSI['reset']}" if enabled else text


def themed(text: str, role: str, theme: str, enabled: bool, bold: bool = False) -> str:
    if not enabled:
        return text
    weight = ANSI["bold"] if bold else ""
    return f"{weight}{THEMES[theme][role]}{text}{ANSI['reset']}"


def render_banner(company: str, theme: str, enabled: bool) -> str:
    rows = []
    roles = ("primary", "primary", "secondary", "secondary", "accent", "accent")
    for row, role in zip(BANNER, roles):
        rows.append(themed(row, role, theme, enabled, bold=True))
    subtitle = f"{company}  •  Route Intelligence Console  •  v{VERSION}"
    rows.extend([themed("━" * min(78, max(36, len(subtitle))), "secondary", theme, enabled),
                 themed(subtitle, "accent", theme, enabled, bold=True)])
    return "\n".join(rows)


def select_option(title: str, options: list[tuple[str, str]], default: int = 1) -> str:
    print(f"\n{title}", file=sys.stderr)
    for number, (_, label) in enumerate(options, 1):
        marker = "›" if number == default else " "
        print(f"  {marker} {number}. {label}", file=sys.stderr)
    while True:
        answer = prompt_input(f"Select [{default}]: ")
        if not answer:
            return options[default - 1][0]
        if answer.isdigit() and 1 <= int(answer) <= len(options):
            return options[int(answer) - 1][0]
        print(f"Enter a number from 1 to {len(options)}.", file=sys.stderr)


def prompt_input(prompt: str) -> str:
    print(prompt, end="", file=sys.stderr, flush=True)
    line = sys.stdin.readline()
    if not line:
        raise ValueError("interactive input ended before setup was complete")
    return line.strip()


def interactive_setup(args: argparse.Namespace) -> None:
    interactive_color = not args.no_color and sys.stderr.isatty()
    print(render_banner(args.company, args.theme, interactive_color), file=sys.stderr)
    print(themed("\nGuided trace setup", "primary", args.theme, interactive_color, bold=True), file=sys.stderr)
    while not args.target:
        args.target = prompt_input("Target hostname or IP: ")
    args.protocol = select_option("Probe strategy", [
        ("all", "Triangulate with UDP + TCP + ICMP (recommended)"),
        ("tcp", "TCP service path"), ("udp", "UDP fixed-flow path"), ("icmp", "ICMP classic path")])
    if shutil.which(args.scamper_binary):
        args.strategy = select_option("Measurement algorithm", [
            ("classic", "Classic native traceroute (fast)"),
            ("paris", "Scamper Paris trace (flow-stable)"),
            ("mda", "Scamper MDA branch discovery (research-grade, more probes)")])
    else:
        args.strategy = "classic"
        print("  Scamper not found: using the classic native algorithm.", file=sys.stderr)
    if args.strategy == "mda" and args.protocol == "all":
        args.protocol = "udp"
        print("  MDA uses one UDP discovery run to keep probe volume bounded.", file=sys.stderr)
    if args.protocol in {"all", "tcp", "udp"}:
        answer = prompt_input(f"Destination port [{args.port}]: ")
        if answer:
            args.port = int(answer)
    enrichment = select_option("Hop intelligence", [
        ("rdns,asn", "Standard: reverse DNS + ASN/prefix"),
        ("rdns,asn,geo,rpki,ixp", "Research: add geo, RPKI, visibility, and IXP context"),
        ("", "Private: no external enrichment")])
    args.enrich = enrichment
    args.no_enrich = not bool(enrichment)
    args.format = select_option("Report format", [
        ("table", "Designer terminal dashboard"), ("json", "Structured JSON"),
        ("csv", "Spreadsheet-ready CSV"), ("prometheus", "Prometheus text metrics")])
    args.flow_consistent = select_option("Pin flow identifiers?", [
        ("yes", "Yes, improve ECMP consistency"), ("no", "No, use native defaults")]) == "yes"
    print(themed("\n✓ Configuration ready. Starting trace…\n", "accent", args.theme, interactive_color, bold=True), file=sys.stderr)


def valid_ip(token: str) -> str | None:
    token = token.strip("()[],:;")
    try:
        return str(ipaddress.ip_address(token))
    except ValueError:
        return None


def classify_ip(ip: str) -> str:
    obj = ipaddress.ip_address(ip)
    if obj.is_loopback:
        return "loopback"
    if obj.is_link_local:
        return "link-local"
    if obj in CGNAT_NETWORK:
        return "carrier-nat"
    if obj.is_private:
        return "private"
    if obj.is_multicast:
        return "multicast"
    if obj.is_reserved:
        return "reserved"
    if obj.is_unspecified:
        return "unspecified"
    return "global"


def parse_hop(line: str, probes: int) -> Hop | None:
    match = HOP_RE.match(line)
    if not match:
        return None
    ttl, body = int(match.group(1)), match.group(2)
    responders: dict[str, Responder] = {}
    current_ip: str | None = None
    timeouts = len(re.findall(r"(?:^|\s)\*(?=\s|$)", body))

    tokens = body.replace("(", " ").replace(")", " ").split()
    idx = 0
    while idx < len(tokens):
        maybe_ip = valid_ip(tokens[idx])
        if maybe_ip:
            current_ip = maybe_ip
            responders.setdefault(current_ip, Responder(ip=current_ip, network_scope=classify_ip(current_ip)))
            idx += 1
            continue
        if idx + 1 < len(tokens) and tokens[idx + 1] == "ms":
            try:
                rtt = float(tokens[idx])
            except ValueError:
                idx += 1
                continue
            if current_ip:
                responders[current_ip].rtts_ms.append(rtt)
            idx += 2
            continue
        if tokens[idx].startswith("!") and current_ip:
            responders[current_ip].annotations.append(tokens[idx])
        idx += 1

    observed = sum(len(r.rtts_ms) for r in responders.values()) + timeouts
    sent = max(probes, observed)
    return Hop(ttl=ttl, sent=sent, timeouts=max(timeouts, sent - sum(len(r.rtts_ms) for r in responders.values())),
               responders=list(responders.values()), raw=line.rstrip(), mpls_labels=parse_mpls_extensions(body),
               interface_extensions=parse_interface_extensions(body))


def parse_traceroute(output: str, probes: int) -> list[Hop]:
    return [hop for line in output.splitlines() if (hop := parse_hop(line, probes)) is not None]


def parse_tracert(output: str) -> list[Hop]:
    """Parse Windows tracert output, where RTT values precede the hop address."""
    hops: list[Hop] = []
    for line in output.splitlines():
        match = HOP_RE.match(line)
        if not match:
            continue
        ttl, body = int(match.group(1)), match.group(2)
        timeouts = len(re.findall(r"(?:^|\s)\*(?=\s|$)", body))
        rtts = []
        for timing in re.finditer(r"(?P<less><)?\s*(?P<value>\d+(?:\.\d+)?)\s*ms\b", body, re.IGNORECASE):
            value = float(timing.group("value"))
            rtts.append(value / 2 if timing.group("less") else value)
        addresses = [ip for token in body.replace("[", " ").replace("]", " ").split()
                     if (ip := valid_ip(token)) is not None]
        responders = []
        if addresses:
            ip = addresses[-1]
            responders = [Responder(ip=ip, rtts_ms=rtts, network_scope=classify_ip(ip))]
        sent = max(3, len(rtts) + timeouts)
        hops.append(Hop(ttl=ttl, sent=sent, timeouts=max(timeouts, sent - len(rtts)),
                        responders=responders, raw=line.rstrip()))
    return hops


def load_tnt_trace(path: str, probes: int) -> Trace:
    raw_tnt = Path(path).expanduser().read_text(encoding="utf-8", errors="replace")
    indicators = [line.strip() for line in raw_tnt.splitlines()
                  if re.search(r"(?:MPLS|INVISIBLE|OPAQUE|TUNNEL|BRPR|DPR)", line, re.IGNORECASE)]
    return Trace("tnt", ["import", str(Path(path).expanduser())], parse_traceroute(raw_tnt, probes),
                 0.0, 0, "", {"backend": "tnt-import", "tunnel_indicators": indicators[:100],
                                "note": "Imported from an external TNT capture; AegisRoute did not generate these revelations"})


def is_windows_backend(binary: str) -> bool:
    return Path(binary).name.lower() in {"tracert", "tracert.exe"}


def traceroute_capabilities(binary: str) -> str:
    try:
        help_arg = "/?" if is_windows_backend(binary) else "--help"
        result = subprocess.run([binary, help_arg], capture_output=True, text=True, timeout=3)
        return result.stdout + result.stderr
    except (OSError, subprocess.SubprocessError):
        return ""


def build_command(args: argparse.Namespace, protocol: str, destination: str, help_text: str) -> list[str]:
    if is_windows_backend(args.binary):
        cmd = [args.binary, "-d", "-h", str(args.max_hops), "-w", str(max(1, round(args.wait * 1000))),
               "-6" if args.ipv6 else "-4"]
        if args.ipv6 and args.source:
            cmd.extend(["-S", args.source])
        cmd.append(destination)
        return cmd
    cmd = [args.binary, "-n", "-q", str(args.probes), "-m", str(args.max_hops), "-f", str(args.first_hop),
           "-w", str(args.wait)]
    cmd.append("-6" if args.ipv6 else "-4")
    if protocol == "icmp":
        cmd.append("-I")
    elif protocol == "tcp":
        cmd.extend(["-T", "-p", str(args.port)])
    else:
        cmd.extend(["-U", "-p", str(args.port)])
    if args.flow_consistent and "--sport" in help_text:
        cmd.extend(["--sport", str(args.source_port)])
    if args.mtu and "--mtu" in help_text:
        cmd.append("--mtu")
    if "--extensions" in help_text or " -e" in help_text:
        cmd.append("-e")
    if args.interface:
        cmd.extend(["-i", args.interface])
    if args.source:
        cmd.extend(["-s", args.source])
    cmd.append(destination)
    return cmd


def windows_compatibility_note(args: argparse.Namespace) -> str:
    details = ["Windows tracert compatibility backend: actual probe protocol is ICMP with three probes per TTL"]
    if args.protocol != "icmp":
        details.append(f"requested {args.protocol.upper()} mode was mapped to ICMP because tracert has no TCP/UDP hop mode")
    if args.probes != 3:
        details.append(f"requested --probes {args.probes} cannot change tracert's fixed sample count")
    if args.first_hop > 1:
        details.append(f"results below TTL {args.first_hop} were filtered after measurement")
    if args.interface:
        details.append(f"interface binding ({args.interface}) is unavailable in tracert")
    if args.source and not args.ipv6:
        details.append("IPv4 source binding is unavailable in tracert")
    if args.flow_consistent:
        details.append("flow consistency/source-port control is unavailable in tracert")
    if args.mtu:
        details.append("MTU discovery is unavailable in tracert")
    return "; ".join(details)


async def run_trace(args: argparse.Namespace, protocol: str, destination: str, help_text: str) -> Trace:
    cmd = build_command(args, protocol, destination, help_text)
    started = time.monotonic()
    timeout = min(600.0, max(15.0, args.max_hops * args.wait * args.probes + 10.0))
    try:
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE,
                                                    stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        text = stdout.decode(errors="replace")
        err = stderr.decode(errors="replace").strip()
        windows = is_windows_backend(args.binary)
        notes = []
        if windows:
            notes.append(windows_compatibility_note(args))
        if err:
            notes.append(err)
        hops = parse_tracert(text) if windows else parse_traceroute(text, args.probes)
        if windows and args.first_hop > 1:
            hops = [hop for hop in hops if hop.ttl >= args.first_hop]
        effective_code = 0 if windows and hops else proc.returncode or 0
        return Trace(protocol, cmd, hops, round((time.monotonic() - started) * 1000, 2),
                     effective_code, "; ".join(notes))
    except asyncio.TimeoutError:
        try:
            proc.kill()
            await proc.wait()
        except ProcessLookupError:
            pass
        return Trace(protocol, cmd, [], round((time.monotonic() - started) * 1000, 2), 124,
                     f"probe timed out after {timeout:.1f}s")
    except OSError as exc:
        return Trace(protocol, cmd, [], round((time.monotonic() - started) * 1000, 2), 127, str(exc))


async def run_scamper_trace(args: argparse.Namespace, protocol: str, destination: str) -> Trace:
    template, measurement = build_scamper_command(
        args.scamper_binary, destination, protocol, args.strategy, args.probes,
        args.first_hop, args.max_hops, args.wait, args.port, args.mda_confidence,
        args.mda_max_probes,
    )
    result_path = output_path()
    cmd = [result_path if token == "{output}" else token for token in template]
    started = time.monotonic()
    timeout = min(900.0, max(30.0, args.max_hops * args.wait * args.probes * 2 + 20.0))
    try:
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE,
                                                    stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        records = load_json_records(result_path)
        normalized = []
        measurement_types = []
        for record in records:
            measurement_types.append(str(record.get("type", "unknown")))
            normalized.extend(normalize_scamper_json(record, args.probes))
        merged: dict[int, Hop] = {}
        for item in normalized:
            hop = merged.setdefault(item["ttl"], Hop(item["ttl"], item["sent"], item["timeouts"], []))
            hop.sent = max(hop.sent, item["sent"])
            hop.timeouts = min(hop.timeouts, item["timeouts"])
            by_ip = {responder.ip: responder for responder in hop.responders}
            for raw_responder in item["responders"]:
                responder = by_ip.get(raw_responder["ip"])
                if responder is None:
                    responder = Responder(raw_responder["ip"], network_scope=classify_ip(raw_responder["ip"]))
                    hop.responders.append(responder)
                    by_ip[responder.ip] = responder
                responder.rtts_ms.extend(raw_responder["rtts_ms"])
        note_parts = [stderr.decode(errors="replace").strip(), stdout.decode(errors="replace").strip()]
        note = "; ".join(part for part in note_parts if part)
        return Trace(protocol, cmd, [merged[key] for key in sorted(merged)],
                     round((time.monotonic() - started) * 1000, 2), proc.returncode or 0, note,
                     {"backend": "scamper", "strategy": args.strategy, "measurement": measurement,
                      "record_types": sorted(set(measurement_types)), "record_count": len(records)})
    except asyncio.TimeoutError:
        try:
            proc.kill()
            await proc.wait()
        except ProcessLookupError:
            pass
        return Trace(protocol, cmd, [], round((time.monotonic() - started) * 1000, 2), 124,
                     f"Scamper measurement timed out after {timeout:.1f}s",
                     {"backend": "scamper", "strategy": args.strategy})
    except OSError as exc:
        return Trace(protocol, cmd, [], round((time.monotonic() - started) * 1000, 2), 127, str(exc),
                     {"backend": "scamper", "strategy": args.strategy})
    finally:
        try:
            os.unlink(result_path)
        except OSError:
            pass


async def resolve_target(target: str, family: int) -> tuple[str, str]:
    loop = asyncio.get_running_loop()
    infos = await loop.run_in_executor(None, lambda: socket.getaddrinfo(target, None, family, socket.SOCK_DGRAM))
    if not infos:
        raise ValueError(f"could not resolve {target}")
    return target, infos[0][4][0]


def unique_public_ips(traces: Iterable[Trace]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for trace in traces:
        for hop in trace.hops:
            for responder in hop.responders:
                if responder.ip not in seen and classify_ip(responder.ip) == "global":
                    seen.add(responder.ip)
                    result.append(responder.ip)
    return result


async def reverse_dns(ips: list[str], concurrency: int) -> dict[str, str]:
    semaphore = asyncio.Semaphore(concurrency)
    loop = asyncio.get_running_loop()

    async def one(ip: str) -> tuple[str, str | None]:
        async with semaphore:
            try:
                name = await asyncio.wait_for(loop.run_in_executor(None, lambda: socket.gethostbyaddr(ip)[0]), 2.0)
                return ip, name
            except (OSError, asyncio.TimeoutError):
                return ip, None

    return {ip: name for ip, name in await asyncio.gather(*(one(ip) for ip in ips)) if name}


def cymru_lookup_sync(ips: list[str], timeout: float = 5.0) -> dict[str, dict[str, Any]]:
    if not ips:
        return {}
    query = "begin\nverbose\n" + "\n".join(ips) + "\nend\n"
    result: dict[str, dict[str, Any]] = {}
    try:
        with socket.create_connection(("whois.cymru.com", 43), timeout=timeout) as sock:
            sock.sendall(query.encode())
            chunks: list[bytes] = []
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
        for line in b"".join(chunks).decode(errors="replace").splitlines():
            parts = [p.strip() for p in line.split("|")]
            if len(parts) < 7 or parts[0].upper().startswith("AS"):
                continue
            try:
                ip = str(ipaddress.ip_address(parts[1]))
                asn = int(parts[0]) if parts[0].isdigit() else None
            except ValueError:
                continue
            result[ip] = {"asn": asn, "prefix": parts[2] or None, "country": parts[3] or None,
                          "as_name": parts[6] or None}
    except OSError:
        pass
    return result


async def cymru_lookup(ips: list[str]) -> dict[str, dict[str, Any]]:
    return await asyncio.get_running_loop().run_in_executor(None, cymru_lookup_sync, ips)


def fetch_geo_sync(ip: str) -> tuple[str, dict[str, Any] | None]:
    req = Request(f"https://ipwho.is/{ip}?fields=success,country_code,city", headers={"User-Agent": f"AegisRoute/{VERSION}"})
    try:
        with urlopen(req, timeout=4) as response:
            data = json.load(response)
        if data.get("success"):
            return ip, {"country": data.get("country_code"), "city": data.get("city")}
    except (OSError, HTTPError, URLError, ValueError, json.JSONDecodeError):
        pass
    return ip, None


async def geo_lookup(ips: list[str], concurrency: int) -> dict[str, dict[str, Any]]:
    semaphore = asyncio.Semaphore(min(concurrency, 6))
    loop = asyncio.get_running_loop()

    async def one(ip: str) -> tuple[str, dict[str, Any] | None]:
        async with semaphore:
            return await loop.run_in_executor(None, fetch_geo_sync, ip)

    return {ip: data for ip, data in await asyncio.gather(*(one(ip) for ip in ips)) if data}


async def enrich(traces: list[Trace], kinds: set[str], concurrency: int, cache_database: str | None = None) -> None:
    ips = list(dict.fromkeys(r.ip for t in traces for h in t.hops for r in h.responders))
    public = [ip for ip in ips if classify_ip(ip) == "global"]
    now = time.monotonic()

    def cached(module: str, keys: list[str]) -> tuple[dict[str, Any], list[str]]:
        bucket = _ENRICHMENT_CACHE.get(module, {})
        hits = {key: bucket[key][1] for key in keys if key in bucket and now - bucket[key][0] < CACHE_TTL_SECONDS}
        if cache_database:
            persistent = MeasurementStore(cache_database).cache_get(module, [key for key in keys if key not in hits])
            hits.update(persistent)
        return hits, [key for key in keys if key not in hits]

    def remember(module: str, values: dict[str, Any]) -> None:
        bucket = _ENRICHMENT_CACHE.setdefault(module, {})
        for key, value in values.items():
            bucket[key] = (time.monotonic(), value)
        if cache_database:
            MeasurementStore(cache_database).cache_set(module, values)

    tasks: dict[str, asyncio.Task[Any]] = {}
    values: dict[str, dict[str, Any]] = {}
    if "rdns" in kinds:
        values["rdns"], missing = cached("rdns", ips)
        tasks["rdns"] = asyncio.create_task(reverse_dns(missing, concurrency))
    if "asn" in kinds:
        values["asn"], missing = cached("asn", public)
        tasks["asn"] = asyncio.create_task(cymru_lookup(missing))
    if "geo" in kinds:
        values["geo"], missing = cached("geo", public)
        tasks["geo"] = asyncio.create_task(geo_lookup(missing, concurrency))
    for name, task in tasks.items():
        fetched = await task
        values[name].update(fetched)
        remember(name, fetched)
    if "rpki" in kinds:
        values["rpki"], missing = cached("rpki", public)
        items = []
        for ip in missing:
            meta = values.get("asn", {}).get(ip, {})
            items.append((ip, meta.get("asn"), meta.get("prefix")))
        fetched = await route_security_lookup(items, concurrency)
        values["rpki"].update(fetched)
        remember("rpki", fetched)
    if "ixp" in kinds:
        values["ixp"], missing = cached("ixp", public)
        fetched = await ixp_lookup(missing, concurrency)
        values["ixp"].update(fetched)
        remember("ixp", fetched)
    for trace in traces:
        for hop in trace.hops:
            for responder in hop.responders:
                responder.rdns = values.get("rdns", {}).get(responder.ip)
                meta = values.get("asn", {}).get(responder.ip, {})
                responder.asn, responder.as_name = meta.get("asn"), meta.get("as_name")
                responder.prefix = meta.get("prefix")
                responder.country = meta.get("country")
                geo = values.get("geo", {}).get(responder.ip, {})
                responder.country = geo.get("country") or responder.country
                responder.city = geo.get("city")
                security = values.get("rpki", {}).get(responder.ip, {})
                responder.asn = responder.asn or security.get("asn")
                responder.prefix = responder.prefix or security.get("prefix")
                responder.rpki_status = security.get("rpki_status")
                responder.routing_visibility = security.get("routing_visibility")
                responder.announced = security.get("announced")
                responder.ixp_name = values.get("ixp", {}).get(responder.ip)


def route_signature(trace: Trace) -> list[list[str]]:
    return [[r.ip for r in hop.responders] for hop in trace.hops]


def analyze(traces: list[Trace], destination_ip: str, spike_ms: float) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for trace in traces:
        previous_avg: float | None = None
        seen: dict[str, int] = {}
        for hop in trace.hops:
            stats = hop.stats()
            avg = stats["avg_ms"]
            if avg is not None and previous_avg is not None and avg - previous_avg >= spike_ms:
                findings.append({"severity": "notice", "protocol": trace.protocol, "ttl": hop.ttl,
                                 "type": "latency_jump", "detail": f"+{avg - previous_avg:.1f} ms vs previous responding hop"})
            if avg is not None:
                previous_avg = avg
            if hop.timeouts == hop.sent:
                findings.append({"severity": "info", "protocol": trace.protocol, "ttl": hop.ttl,
                                 "type": "silent_hop", "detail": "no TTL-expired reply (filtering or rate limiting possible)"})
            if len(hop.responders) > 1:
                findings.append({"severity": "info", "protocol": trace.protocol, "ttl": hop.ttl,
                                 "type": "multipath", "detail": f"{len(hop.responders)} responders observed at this TTL"})
            for responder in hop.responders:
                if responder.ip in seen and seen[responder.ip] != hop.ttl:
                    findings.append({"severity": "warning", "protocol": trace.protocol, "ttl": hop.ttl,
                                     "type": "possible_loop", "detail": f"{responder.ip} also appeared at TTL {seen[responder.ip]}"})
                seen[responder.ip] = hop.ttl
                if any("!" in item for item in responder.annotations):
                    findings.append({"severity": "warning", "protocol": trace.protocol, "ttl": hop.ttl,
                                     "type": "icmp_annotation", "detail": " ".join(responder.annotations)})
                if responder.rpki_status and responder.rpki_status.lower() == "invalid":
                    findings.append({"severity": "warning", "protocol": trace.protocol, "ttl": hop.ttl,
                                     "type": "rpki_invalid", "detail": f"{responder.prefix or responder.ip} via AS{responder.asn or '?'} is RPKI invalid"})
                if responder.announced is False:
                    findings.append({"severity": "warning", "protocol": trace.protocol, "ttl": hop.ttl,
                                     "type": "unannounced_prefix", "detail": f"{responder.prefix or responder.ip} was not visible as announced in RIPEstat"})
        reached = any(r.ip == destination_ip for h in trace.hops for r in h.responders)
        if not reached:
            findings.append({"severity": "warning", "protocol": trace.protocol, "ttl": None,
                             "type": "incomplete", "detail": "destination did not reply before trace ended"})
    if len(traces) > 1:
        signatures = {t.protocol: route_signature(t) for t in traces}
        if len({json.dumps(v, sort_keys=True) for v in signatures.values()}) > 1:
            findings.append({"severity": "notice", "protocol": "cross-protocol", "ttl": None,
                             "type": "path_divergence", "detail": "probe protocols observed different route signatures"})
    return findings


def trace_to_dict(trace: Trace) -> dict[str, Any]:
    return {"protocol": trace.protocol, "command": trace.command, "duration_ms": trace.duration_ms,
            "return_code": trace.return_code, "stderr": trace.stderr, "metadata": trace.metadata,
            "hops": [{"ttl": h.ttl, "sent": h.sent, "timeouts": h.timeouts, "stats": h.stats(),
                      "responders": [asdict(r) for r in h.responders], "mpls_labels": h.mpls_labels,
                      "interface_extensions": h.interface_extensions,
                      "raw": h.raw} for h in trace.hops]}


def make_report(target: str, destination_ip: str, args: argparse.Namespace, traces: list[Trace], started: str) -> dict[str, Any]:
    report = {"schema": "aegisroute/v3", "tool_version": VERSION, "company": args.company, "theme": args.theme,
            "started_at": started, "finished_at": utc_now(),
            "target": target, "destination_ip": destination_ip,
            "settings": {"protocol": args.protocol, "port": args.port, "probes": args.probes,
                         "max_hops": args.max_hops, "wait_seconds": args.wait,
                         "flow_consistent": args.flow_consistent, "mtu_discovery": args.mtu,
                         "enrichment": sorted(args.enrich),
                         "backend": "demo" if args.demo else "scamper" if getattr(args, "active_backend", None) == "scamper" else "windows-tracert-icmp" if is_windows_backend(args.binary) else "linux-traceroute",
                         "strategy": args.strategy,
                         "actual_protocols": [trace.protocol for trace in traces]},
            "traces": [trace_to_dict(t) for t in traces],
            "findings": evidence_findings(analyze(traces, destination_ip, args.spike_threshold))}
    report["fusion_graph"] = build_fusion_graph(report)
    report["mpls_analysis"] = mpls_analysis(report)
    report["quality"] = quality_score(report)
    return report


def load_baseline(path: str | None) -> dict[str, Any] | None:
    if not path:
        return None
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def compare_baseline(report: dict[str, Any], baseline: dict[str, Any] | None) -> None:
    if not baseline:
        return
    old = {t["protocol"]: [[r["ip"] for r in h["responders"]] for h in t["hops"]] for t in baseline.get("traces", [])}
    for trace in report["traces"]:
        current = [[r["ip"] for r in h["responders"]] for h in trace["hops"]]
        prior = old.get(trace["protocol"])
        if prior is None:
            continue
        max_len = max(len(prior), len(current))
        changed = [ttl + 1 for ttl in range(max_len)
                   if (prior[ttl] if ttl < len(prior) else []) != (current[ttl] if ttl < len(current) else [])]
        if changed:
            report["findings"].append({"severity": "notice", "protocol": trace["protocol"], "ttl": None,
                                       "type": "baseline_change", "detail": f"route changed at TTLs {changed}"})


def render_table(report: dict[str, Any], use_color: bool) -> str:
    theme = report.get("theme", "cyber")
    lines = [render_banner(report.get("company", DEFAULT_COMPANY), theme, use_color), "",
             themed("╭─ TRACE SESSION", "primary", theme, use_color, bold=True),
             f"│ Target    {report['target']}  →  {report['destination_ip']}",
             f"│ Started   {report['started_at']}",
             f"│ Engines   {', '.join(t['protocol'].upper() for t in report['traces'])}",
             f"│ Quality   {report.get('quality', {}).get('score', '?')}/100  grade {report.get('quality', {}).get('grade', '?')}",
             themed("╰" + "─" * 76, "primary", theme, use_color)]
    for trace in report["traces"]:
        status = "ok" if trace["return_code"] == 0 else f"exit {trace['return_code']}"
        status_icon = "●" if trace["return_code"] == 0 else "◆"
        heading = f"{status_icon} {trace['protocol'].upper():<5}  {status:<8}  engine {trace['duration_ms']:.0f} ms"
        lines.extend(["", themed(heading, "accent" if trace["return_code"] == 0 else "warn", theme, use_color, bold=True),
                      themed(" TTL  LOSS     RTT MIN/AVG/MAX/JIT       NETWORK                    RESPONDER", "secondary", theme, use_color),
                      themed(" ───  ──────   ───────────────────────   ─────────────────────────  ─────────────────────────", "secondary", theme, use_color)])
        for hop in trace["hops"]:
            stats = hop["stats"]
            timing = "*" if stats["avg_ms"] is None else f"{stats['min_ms']:.1f}/{stats['avg_ms']:.1f}/{stats['max_ms']:.1f}/{stats['jitter_ms']:.1f}"
            if not hop["responders"]:
                lines.append(themed(f" {hop['ttl']:>3}  {stats['loss_pct']:>5.1f}%   {'*':<25} {'silent':<26}  · · ·", "warn", theme, use_color))
            for index, responder in enumerate(hop["responders"]):
                network = f"AS{responder['asn']}" if responder.get("asn") else responder.get("network_scope", "")
                if responder.get("country"):
                    network += f"/{responder['country']}"
                if responder.get("rpki_status"):
                    network += f"/{responder['rpki_status']}"
                label = responder.get("rdns") or responder["ip"]
                if responder.get("rdns"):
                    label += f" ({responder['ip']})"
                prefix = f" {hop['ttl']:>3}  {stats['loss_pct']:>5.1f}%   {timing:<25} {network[:25]:<26}" if index == 0 else " " * 69
                lines.append(prefix + " " + label)
                if responder.get("ixp_name"):
                    lines.append(" " * 69 + f" IXP: {responder['ixp_name']}")
            for mpls in hop.get("mpls_labels", []):
                lines.append(" " * 69 + f" MPLS label={mpls['label']} tc={mpls['traffic_class']} ttl={mpls['ttl']} bos={mpls['bottom_of_stack']}")
        if trace.get("stderr"):
            lines.append(color(f"note: {trace['stderr']}", "yellow", use_color))
    if (report.get("service_diagnostics") or report.get("bgp_correlation") or report.get("alias_resolution")
            or report.get("distributed_measurement") or report.get("mpls_analysis", {}).get("visible")):
        lines.extend(["", themed("╭─ ADVANCED CORRELATION", "primary", theme, use_color, bold=True)])
        service = report.get("service_diagnostics")
        if service:
            tls = service.get("tls") or {}
            lines.append(f"│ Service   TCP/{service.get('port')} {'reachable' if service.get('tcp_reachable') else 'unreachable'}  connect={service.get('tcp_connect_ms')} ms")
            if tls:
                lines.append(f"│ TLS       {tls.get('version')} / {tls.get('cipher')}  handshake={tls.get('handshake_ms')} ms  cert={tls.get('subject')}")
        bgp = report.get("bgp_correlation")
        if bgp:
            lines.append(f"│ BGP       {bgp.get('event_count', 0)} events / {bgp.get('window_hours')}h  announcements={bgp.get('announcements', 0)} withdrawals={bgp.get('withdrawals', 0)} origins={','.join(bgp.get('origin_asns', [])) or '-'}")
        aliases = report.get("alias_resolution")
        if aliases:
            lines.append(f"│ Aliases   {len(aliases.get('confirmed_pairs', []))} confirmed / {aliases.get('tested_pairs', 0)} tested with Scamper Ally")
        mpls = report.get("mpls_analysis", {})
        if mpls.get("visible"):
            lines.append(f"│ MPLS      labels={','.join(str(item) for item in mpls.get('unique_labels', []))} transitions={len(mpls.get('label_transitions', []))}")
        distributed = report.get("distributed_measurement")
        if distributed:
            lines.append(f"│ Vantages  {distributed.get('source_count')} correlated measurement sources")
        lines.append(themed("╰" + "─" * 76, "primary", theme, use_color))
    if report["findings"]:
        lines.extend(["", themed("╭─ INTELLIGENCE FINDINGS", "secondary", theme, use_color, bold=True)])
        for finding in report["findings"]:
            where = f"/{finding['protocol']}" + (f"/ttl-{finding['ttl']}" if finding.get("ttl") else "")
            icon = "!" if finding["severity"] == "warning" else "◆" if finding["severity"] == "notice" else "·"
            role = "warn" if finding["severity"] in {"warning", "notice"} else "secondary"
            confidence = f" [{finding.get('confidence', 0):.0%}]" if finding.get("confidence") is not None else ""
            lines.append(themed(f"│ {icon} {finding['severity'].upper():<7} {where}{confidence}: {finding['detail']}", role, theme, use_color))
        lines.append(themed("╰" + "─" * 76, "secondary", theme, use_color))
    lines.extend(["", themed(f"Generated by {report.get('company', DEFAULT_COMPANY)} • AegisRoute v{VERSION}",
                              "accent", theme, use_color)])
    return "\n".join(lines)


def demo_trace() -> list[Trace]:
    """Deterministic UI/data-pipeline preview that sends no packets."""
    samples = {
        "udp": """ 1  192.168.1.1  0.420 ms  0.510 ms  0.460 ms
 2  10.10.0.1  3.200 ms  3.410 ms  3.330 ms
 3  100.64.0.1  8.100 ms  *  8.700 ms
 4  198.51.100.14  14.200 ms  198.51.100.18  15.100 ms  14.800 ms
 5  * * *
 6  203.0.113.80  54.100 ms  53.800 ms  54.400 ms""",
        "tcp": """ 1  192.168.1.1  0.390 ms  0.450 ms  0.410 ms
 2  10.10.0.1  3.100 ms  3.220 ms  3.180 ms
 3  100.64.0.1  7.900 ms  8.200 ms  8.000 ms
 4  198.51.100.22  15.300 ms  15.100 ms  15.500 ms
 5  203.0.113.80  52.900 ms  53.200 ms  53.000 ms""",
        "icmp": """ 1  192.168.1.1  0.400 ms  0.430 ms  0.420 ms
 2  10.10.0.1  3.000 ms  3.100 ms  3.050 ms
 3  * * *
 4  198.51.100.14  14.900 ms  15.000 ms  14.700 ms
 5  203.0.113.80  53.500 ms  53.100 ms  53.300 ms""",
    }
    traces = [Trace(mode, ["traceroute", f"--{mode}", "demo.aegisroute.local"], parse_traceroute(text, 3),
                    118.0 + index * 17.0, 0) for index, (mode, text) in enumerate(samples.items())]
    names = {"192.168.1.1": "gateway.lan", "203.0.113.80": "edge.demo.example"}
    for trace in traces:
        for hop in trace.hops:
            for responder in hop.responders:
                responder.rdns = names.get(responder.ip)
                if responder.ip.startswith("198.51.100."):
                    responder.asn, responder.as_name, responder.country = 64520, "DEMO-TRANSIT", "US"
                elif responder.ip == "203.0.113.80":
                    responder.asn, responder.as_name, responder.country, responder.city = 64530, "DEMO-EDGE", "IN", "Mumbai"
    return traces


def csv_text(report: dict[str, Any]) -> str:
    import io
    stream = io.StringIO()
    writer = csv.writer(stream)
    writer.writerow(["target", "destination_ip", "protocol", "ttl", "loss_pct", "min_ms", "avg_ms", "max_ms",
                     "jitter_ms", "ip", "rdns", "asn", "as_name", "prefix", "country", "city", "scope",
                     "rpki_status", "announced", "routing_visibility", "ixp_name", "mpls_labels"])
    for trace in report["traces"]:
        for hop in trace["hops"]:
            rows = hop["responders"] or [{}]
            for responder in rows:
                s = hop["stats"]
                writer.writerow([report["target"], report["destination_ip"], trace["protocol"], hop["ttl"],
                                 s["loss_pct"], s["min_ms"], s["avg_ms"], s["max_ms"], s["jitter_ms"],
                                 responder.get("ip"), responder.get("rdns"), responder.get("asn"),
                                 responder.get("as_name"), responder.get("prefix"), responder.get("country"),
                                 responder.get("city"), responder.get("network_scope"), responder.get("rpki_status"),
                                 responder.get("announced"), responder.get("routing_visibility"), responder.get("ixp_name"),
                                 json.dumps(hop.get("mpls_labels", []), separators=(",", ":"))])
    return stream.getvalue()


def atomic_write(path: str, content: str) -> None:
    destination = Path(path).expanduser()
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_path = tempfile.mkstemp(prefix=f".{destination.name}.", dir=str(destination.parent), text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            handle.write(content)
        os.replace(temp_path, destination)
    except BaseException:
        try:
            os.unlink(temp_path)
        except OSError:
            pass
        raise


def protocols(value: str) -> list[str]:
    return ["udp", "tcp", "icmp"] if value == "all" else [value]


def backend_protocols(requested: str, binary: str) -> list[str]:
    if not is_windows_backend(binary):
        return protocols(requested)
    return ["icmp"]


async def one_cycle(args: argparse.Namespace, target: str, destination_ip: str, help_text: str,
                    baseline: dict[str, Any] | None, modes: list[str]) -> dict[str, Any]:
    started = utc_now()
    runner = run_scamper_trace if args.active_backend == "scamper" else run_trace
    traces = list(await asyncio.gather(*(runner(args, mode, destination_ip) if runner is run_scamper_trace
                                        else runner(args, mode, destination_ip, help_text) for mode in modes)))
    if args.tnt_output:
        traces.append(load_tnt_trace(args.tnt_output, args.probes))
    if args.enrich:
        await enrich(traces, args.enrich, args.concurrency, args.store)
    report = make_report(target, destination_ip, args, traces, started)
    compare_baseline(report, baseline)
    return report


async def augment_report(args: argparse.Namespace, report: dict[str, Any], previous: dict[str, Any] | None) -> None:
    loop = asyncio.get_running_loop()
    report["findings"].extend(historical_findings(previous, report, args.history_latency_delta))
    sources = list(args.merge_report or []) + list(args.remote_report or [])
    if sources:
        imported = []
        for source in sources:
            imported.append(await loop.run_in_executor(None, load_report_source, source, args.remote_token))
        merge_reports(report, imported)
    if args.bgp_events:
        prefixes = list(dict.fromkeys(
            responder.get("prefix") for trace in report.get("traces", []) for hop in trace.get("hops", [])
            for responder in hop.get("responders", []) if responder.get("prefix")
        ))
        bgp_function = fetch_bgpstream_events if args.bgp_provider == "bgpstream" else fetch_bgp_events
        report["bgp_correlation"] = await loop.run_in_executor(None, bgp_function, prefixes, args.bgp_window)
        bgp = report["bgp_correlation"]
        if bgp.get("withdrawals"):
            report["findings"].append({"severity": "notice", "protocol": "control-plane", "ttl": None,
                                       "type": "bgp_withdrawals", "detail": f"{bgp['withdrawals']} BGP withdrawals observed in the correlation window",
                                       "confidence": .8, "evidence": [f"{bgp.get('provider')} BGP update stream"],
                                       "alternative_explanations": ["normal traffic engineering", "collector-specific visibility"]})
        if len(bgp.get("origin_asns", [])) > 1:
            report["findings"].append({"severity": "warning", "protocol": "control-plane", "ttl": None,
                                       "type": "multiple_bgp_origins", "detail": f"multiple origins appeared: {bgp['origin_asns']}",
                                       "confidence": .75, "evidence": [f"Origins in {bgp.get('provider')} update paths"],
                                       "alternative_explanations": ["legitimate MOAS", "route-server artifact"]})
    if args.service_check or args.tls_check:
        report["service_diagnostics"] = await loop.run_in_executor(
            None, service_diagnostics, report["target"], report["destination_ip"], args.port,
            min(10.0, max(1.0, args.wait * 3)), args.tls_check,
        )
        if not report["service_diagnostics"].get("tcp_reachable"):
            report["findings"].append({"severity": "warning", "protocol": "service", "ttl": None,
                                       "type": "service_unreachable", "detail": report["service_diagnostics"].get("error") or "TCP connection failed",
                                       "confidence": .9, "evidence": ["Direct TCP connection attempt"],
                                       "alternative_explanations": ["service filtering", "service not listening", "transient failure"]})
    if args.alias_resolve:
        scamper = shutil.which(args.scamper_binary)
        if not scamper:
            raise RuntimeError("--alias-resolve requires Scamper; install the 'scamper' package")
        candidates = alias_candidates(report, args.alias_max_pairs)
        for candidate in candidates:
            output = output_path()
            left, right = candidate["addresses"]
            command = build_ally_command(scamper, left, right, output)
            try:
                proc = await asyncio.create_subprocess_exec(*command, stdout=asyncio.subprocess.PIPE,
                                                            stderr=asyncio.subprocess.PIPE)
                _, stderr = await asyncio.wait_for(proc.communicate(), timeout=90)
                candidate["status"] = ally_result(load_json_records(output), left, right)
                candidate["return_code"] = proc.returncode
                candidate["error"] = stderr.decode(errors="replace").strip() or None
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                candidate["status"] = "inconclusive"
                candidate["error"] = "Ally measurement timed out"
            finally:
                try:
                    os.unlink(output)
                except OSError:
                    pass
        report["alias_resolution"] = {"engine": "scamper-ally", "tested_pairs": len(candidates),
                                      "pairs": candidates,
                                      "confirmed_pairs": [item["addresses"] for item in candidates if item["status"] == "confirmed"]}
    report["fusion_graph"] = build_fusion_graph(report)
    report["mpls_analysis"] = mpls_analysis(report)
    report["quality"] = quality_score(report)
    report["findings"] = evidence_findings(report["findings"])


async def deliver_alerts(args: argparse.Namespace, report: dict[str, Any]) -> None:
    loop = asyncio.get_running_loop()
    deliveries: dict[str, Any] = {}
    alert_report = report
    if args.alert_mode == "changes":
        actionable = {"baseline_change", "responder_change", "persistent_latency_change", "loss_increase",
                      "rpki_state_change", "bgp_withdrawals", "multiple_bgp_origins", "rpki_invalid",
                      "unannounced_prefix", "service_unreachable"}
        alert_report = dict(report)
        alert_report["findings"] = [item for item in report.get("findings", []) if item.get("type") in actionable]
    if args.webhook:
        deliveries["webhook"] = await loop.run_in_executor(
            None, send_webhook, args.webhook, alert_report, args.alert_severity)
    if args.email_to:
        deliveries["email"] = await loop.run_in_executor(
            None, send_email, args.smtp_host, args.smtp_port, args.email_from, args.email_to,
            alert_report, args.alert_severity, args.smtp_user, os.environ.get("AEGISROUTE_SMTP_PASSWORD"))
    if deliveries:
        report["alert_delivery"] = deliveries


def output_report(report: dict[str, Any], args: argparse.Namespace, append: bool = False) -> None:
    if args.format == "json":
        content = json.dumps(report, indent=2, sort_keys=False) + "\n"
    elif args.format == "jsonl":
        content = json.dumps(report, separators=(",", ":")) + "\n"
    elif args.format == "csv":
        content = csv_text(report)
    elif args.format == "prometheus":
        content = prometheus_text(report)
    elif args.format == "html":
        content = html_report(report)
    else:
        view = report
        tab_label = "all"
        if args.tui:
            tabs = ["all"] + [trace.get("protocol", "unknown") for trace in report.get("traces", [])]
            args.tui_tab_index = getattr(args, "tui_tab_index", 0) % len(tabs)
            tab_label = tabs[args.tui_tab_index]
            if tab_label != "all":
                view = dict(report)
                view["traces"] = [trace for trace in report.get("traces", []) if trace.get("protocol") == tab_label]
        content = render_table(view, args.color) + "\n"
        if args.tui and not args.output:
            content = "\033[2J\033[H" + content + f"\nTUI tab: {tab_label}  [Tab] next view  [r] refresh  [q] quit\n"
    if args.output:
        if append:
            destination = Path(args.output).expanduser()
            destination.parent.mkdir(parents=True, exist_ok=True)
            with destination.open("a", encoding="utf-8", newline="") as handle:
                handle.write(content)
        else:
            atomic_write(args.output, content)
    else:
        sys.stdout.write(content)
        sys.stdout.flush()


def read_tui_key() -> str | None:
    if os.name == "nt":
        try:
            import msvcrt
            if msvcrt.kbhit():
                value = msvcrt.getwch()
                return "tab" if value == "\t" else value.lower()
        except (ImportError, OSError):
            return None
    else:
        try:
            import select
            ready, _, _ = select.select([sys.stdin], [], [], 0)
            if ready:
                value = sys.stdin.read(1)
                return "tab" if value == "\t" else value.lower()
        except (OSError, ValueError):
            return None
    return None


async def tui_wait(report: dict[str, Any], args: argparse.Namespace, seconds: float) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        key = read_tui_key()
        if key == "q":
            return False
        if key == "r":
            return True
        if key == "tab":
            args.tui_tab_index = getattr(args, "tui_tab_index", 0) + 1
            output_report(report, args)
        await asyncio.sleep(0.1)
    return True


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="aegisroute", description=HELP_DESCRIPTION, epilog=HELP_EPILOG,
                                formatter_class=HelpFormatter)
    p.add_argument("target", nargs="?", help="hostname or IPv4/IPv6 address; omit for guided mode in a terminal")
    p.add_argument("-P", "--protocol", choices=["udp", "tcp", "icmp", "all"], default="all",
                   help="probe engine: UDP fixed destination port, TCP SYN to --port, ICMP echo, or all three concurrently")
    p.add_argument("--backend", choices=["auto", "native", "scamper"], default="auto",
                   help="measurement backend; auto selects Scamper for Paris/MDA and native traceroute otherwise")
    p.add_argument("--strategy", choices=["classic", "paris", "mda"], default="classic",
                   help="classic traceroute, Scamper Paris flow-stable trace, or genuine Scamper MDA tracelb")
    p.add_argument("--mda-confidence", type=int, choices=[95, 99], default=95,
                   help="MDA completeness confidence; 99 sends more probes than 95")
    p.add_argument("--mda-max-probes", type=int, default=1000, metavar="N",
                   help="hard safety cap on packets sent by one Scamper MDA measurement")
    p.add_argument("--scamper-binary", default=os.environ.get("AEGISROUTE_SCAMPER", "scamper"), metavar="PATH",
                   help="Scamper executable used by --strategy paris/mda")
    p.add_argument("-p", "--port", type=int, default=443,
                   help="destination service port used by TCP/UDP probes; ignored by ICMP")
    p.add_argument("-q", "--probes", type=int, default=3,
                   help="number of samples sent for each TTL; more samples improve statistics but increase traffic/time")
    p.add_argument("-m", "--max-hops", type=int, default=30,
                   help="highest TTL/hop limit to probe before declaring the path incomplete")
    p.add_argument("-f", "--first-hop", type=int, default=1,
                   help="lowest TTL to probe; increase only when intentionally skipping known local hops")
    p.add_argument("-w", "--wait", type=float, default=1.0,
                   help="maximum seconds to wait for an individual reply before recording a timeout")
    family = p.add_mutually_exclusive_group()
    family.add_argument("-4", dest="ipv6", action="store_false", help="resolve and probe only IPv4 addresses")
    family.add_argument("-6", dest="ipv6", action="store_true", help="resolve and probe only IPv6 addresses")
    p.set_defaults(ipv6=False)
    p.add_argument("-i", "--interface", metavar="NAME",
                   help="bind probes to a Linux network interface such as eth0, ens3, or wg0")
    p.add_argument("-s", "--source", metavar="ADDRESS",
                   help="bind probes to a local source IPv4/IPv6 address configured on this system")
    p.add_argument("--flow-consistent", action="store_true",
                   help="pin source/destination ports where the backend supports --sport; Paris-inspired ECMP stability")
    p.add_argument("--source-port", type=int, default=33434,
                   help="source port used with --flow-consistent; choose an unused port from 1-65535")
    p.add_argument("--mtu", action="store_true",
                   help="ask Linux traceroute to discover path MTU changes; applied only when backend supports --mtu")
    p.add_argument("--enrich", default="rdns,asn",
                   help="modules: rdns,asn,geo,rpki (RIPEstat routing security),ixp (PeeringDB exchange detection)")
    p.add_argument("--no-enrich", action="store_true",
                   help="disable DNS, ASN, and geolocation lookups; best option for private/offline assessments")
    p.add_argument("--concurrency", type=int, default=16,
                   help="maximum simultaneous DNS/geo lookups; ASN lookup remains one efficient bulk request")
    p.add_argument("--spike-threshold", type=float, default=35.0, metavar="MS",
                   help="create a latency-jump finding when average RTT increases by at least this many milliseconds")
    p.add_argument("--format", choices=["table", "json", "jsonl", "csv", "prometheus", "html"], default="table",
                   help="report encoding: terminal, JSON, JSONL, CSV, Prometheus, or standalone HTML")
    p.add_argument("-o", "--output", metavar="FILE",
                   help="write the report to FILE atomically; watch mode appends subsequent JSONL/table cycles")
    p.add_argument("--compare", metavar="REPORT.json",
                   help="compare each protocol route against an earlier AegisRoute JSON report and flag changed TTLs")
    p.add_argument("--watch", type=float, metavar="SECONDS",
                   help="repeat the complete trace after this interval and compare each cycle with the previous one")
    p.add_argument("--cycles", type=int, default=0, metavar="N",
                   help="with --watch, stop after N cycles; zero continues until Ctrl+C")
    p.add_argument("--store", metavar="DATABASE",
                   help="save every completed report and finding to a WAL-mode SQLite database")
    p.add_argument("--history", type=int, metavar="N",
                   help="show the latest N stored measurements for TARGET from --store, then exit")
    p.add_argument("--atlas-id", type=int, metavar="ID",
                   help="fetch public results for an existing RIPE Atlas measurement ID, then exit as JSON")
    p.add_argument("--atlas-ids", metavar="ID,ID",
                   help="fetch and fuse multiple existing RIPE Atlas measurements")
    p.add_argument("--merge-report", action="append", metavar="FILE",
                   help="merge another AegisRoute JSON report as a measurement vantage; repeatable")
    p.add_argument("--remote-report", action="append", metavar="URL",
                   help="fetch and merge a remote AegisRoute JSON report over HTTP(S); repeatable")
    p.add_argument("--remote-token", default=os.environ.get("AEGISROUTE_REMOTE_TOKEN"), metavar="TOKEN",
                   help="Bearer token for remote agents; AEGISROUTE_REMOTE_TOKEN avoids shell history")
    p.add_argument("--bgp-events", action="store_true",
                   help="correlate observed prefixes with RIPEstat BGP announcements and withdrawals")
    p.add_argument("--bgp-window", type=int, default=24, metavar="HOURS",
                   help="BGP event lookback window, from 1 through 168 hours")
    p.add_argument("--bgp-provider", choices=["ripestat", "bgpstream"], default="ripestat",
                   help="control-plane source; BGPStream requires the optional pybgpstream package")
    p.add_argument("--service-check", action="store_true",
                   help="measure direct TCP service reachability and connection time on --port")
    p.add_argument("--tls-check", action="store_true",
                   help="perform a verified TLS handshake and report version, cipher, certificate, and timing")
    p.add_argument("--alias-resolve", action="store_true",
                   help="actively test bounded router-address pairs with Scamper Ally")
    p.add_argument("--alias-max-pairs", type=int, default=5, metavar="N",
                   help="maximum Ally address pairs tested per measurement, from 1 through 20")
    p.add_argument("--tnt-output", metavar="FILE",
                   help="import external TNT text output for hidden-MPLS correlation without claiming local revelation")
    p.add_argument("--history-latency-delta", type=float, default=25.0, metavar="MS",
                   help="historical average-RTT increase that creates a persistent degradation finding")
    p.add_argument("--webhook", metavar="HTTPS_URL",
                   help="POST an alert JSON only when findings meet --alert-severity")
    p.add_argument("--alert-severity", choices=["info", "notice", "warning", "critical"], default="warning",
                   help="minimum finding severity sent to --webhook")
    p.add_argument("--alert-mode", choices=["changes", "all"], default="changes",
                   help="send actionable route/security changes only, or all threshold-matched findings")
    p.add_argument("--email-to", metavar="ADDRESS",
                   help="send threshold-matched findings by SMTP email")
    p.add_argument("--email-from", metavar="ADDRESS",
                   help="SMTP sender address required with --email-to")
    p.add_argument("--smtp-host", metavar="HOST",
                   help="STARTTLS SMTP server required with --email-to")
    p.add_argument("--smtp-port", type=int, default=587, metavar="PORT",
                   help="STARTTLS SMTP port")
    p.add_argument("--smtp-user", metavar="USER",
                   help="optional SMTP username; password comes from AEGISROUTE_SMTP_PASSWORD")
    p.add_argument("--tui", action="store_true",
                   help="clear and redraw the table each watch cycle as a live full-screen console")
    native_backend = "tracert" if os.name == "nt" else "traceroute"
    p.add_argument("--binary", default=os.environ.get("AEGISROUTE_TRACEROUTE", native_backend), metavar="PATH",
                   help="alternate traceroute executable; defaults to tracert on Windows and traceroute elsewhere")
    p.add_argument("--dry-run", action="store_true",
                   help="resolve the target and print exact backend commands without sending probes")
    p.add_argument("--interactive", action="store_true",
                   help="force the guided selection menu even when a target could be supplied directly")
    p.add_argument("--demo", action="store_true",
                   help="render deterministic sample routes through the full analysis/UI pipeline; sends no packets")
    p.add_argument("--doctor", action="store_true",
                   help="print platform, Python, traceroute backend, and capability diagnostics, then exit")
    p.add_argument("--company", default=os.environ.get("AEGISROUTE_COMPANY", DEFAULT_COMPANY),
                   help="company name shown in banners/reports; AEGISROUTE_COMPANY provides the environment default")
    p.add_argument("--theme", choices=sorted(THEMES), default=os.environ.get("AEGISROUTE_THEME", "cyber"),
                   help="terminal color palette; AEGISROUTE_THEME provides the environment default")
    p.add_argument("--no-color", action="store_true",
                   help="suppress ANSI color sequences for logs, basic terminals, and accessibility tools")
    p.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    return p


def validate_args(args: argparse.Namespace) -> None:
    if args.atlas_id is not None:
        if args.atlas_id <= 0:
            raise ValueError("atlas measurement ID must be positive")
        args.enrich = set()
        args.color = False
        return
    if args.atlas_ids:
        try:
            args.atlas_id_list = [int(item.strip()) for item in args.atlas_ids.split(",") if item.strip()]
        except ValueError as exc:
            raise ValueError("--atlas-ids must be comma-separated positive integers") from exc
        if not args.atlas_id_list or any(item <= 0 for item in args.atlas_id_list):
            raise ValueError("--atlas-ids must contain positive integers")
        args.enrich = set()
        args.color = False
        return
    args.atlas_id_list = []
    if not args.target and args.demo:
        args.target = "demo.aegisroute.local"
    if not args.target:
        raise ValueError("target is required outside interactive or demo mode")
    if len(args.company) > 80 or any(ord(ch) < 32 or ord(ch) == 127 for ch in args.company):
        raise ValueError("company name must be 1-80 printable characters")
    if not args.company.strip():
        raise ValueError("company name cannot be empty")
    if args.target.startswith("-") or any(ch.isspace() for ch in args.target):
        raise ValueError("target must be a hostname or address, not an option or whitespace-containing string")
    for name, value, low, high in [("port", args.port, 1, 65535), ("source port", args.source_port, 1, 65535),
                                   ("probes", args.probes, 1, 10), ("max hops", args.max_hops, 1, 255),
                                   ("first hop", args.first_hop, 1, args.max_hops), ("concurrency", args.concurrency, 1, 128)]:
        if not low <= value <= high:
            raise ValueError(f"{name} must be between {low} and {high}")
    if not 100 <= args.mda_max_probes <= 10000:
        raise ValueError("MDA max probes must be between 100 and 10000")
    if not 0.05 <= args.wait <= 60:
        raise ValueError("wait must be between 0.05 and 60 seconds")
    allowed = {"rdns", "asn", "geo", "rpki", "ixp"}
    args.enrich = set() if args.no_enrich else {item.strip().lower() for item in args.enrich.split(",") if item.strip()}
    unknown = args.enrich - allowed
    if unknown:
        raise ValueError(f"unknown enrichment: {', '.join(sorted(unknown))}")
    args.color = not args.no_color and sys.stdout.isatty() and args.format == "table"
    if args.watch is not None and args.watch < 1:
        raise ValueError("watch interval must be at least 1 second")
    if args.cycles < 0:
        raise ValueError("cycles cannot be negative")
    if args.history is not None and args.history <= 0:
        raise ValueError("history count must be positive")
    if args.history is not None and not args.store:
        raise ValueError("--history requires --store DATABASE")
    if args.backend == "native" and args.strategy != "classic":
        raise ValueError("Paris and MDA strategies require --backend scamper or auto")
    if args.spike_threshold <= 0:
        raise ValueError("spike threshold must be greater than zero")
    if not 1 <= args.bgp_window <= 168:
        raise ValueError("BGP window must be between 1 and 168 hours")
    if args.history_latency_delta <= 0:
        raise ValueError("history latency delta must be greater than zero")
    if not 1 <= args.alias_max_pairs <= 20:
        raise ValueError("alias max pairs must be between 1 and 20")
    if args.tnt_output and not Path(args.tnt_output).expanduser().is_file():
        raise ValueError("--tnt-output must name a readable TNT text capture")
    if args.webhook and urlparse(args.webhook).scheme != "https":
        raise ValueError("--webhook requires an HTTPS URL")
    if args.email_to and (not args.email_from or not args.smtp_host):
        raise ValueError("--email-to requires --email-from and --smtp-host")
    if not 1 <= args.smtp_port <= 65535:
        raise ValueError("SMTP port must be between 1 and 65535")
    for remote in args.remote_report or []:
        if urlparse(remote).scheme != "https":
            raise ValueError("--remote-report requires an HTTPS URL")
    if args.format == "html" and not args.output:
        raise ValueError("HTML format requires --output FILE")
    if args.tui and args.format != "table":
        raise ValueError("--tui requires --format table")
    if args.tui and (args.output or not sys.stdout.isatty()):
        raise ValueError("--tui requires an interactive terminal and cannot use --output")
    if args.watch and args.format == "json":
        args.format = "jsonl"


def run_doctor(args: argparse.Namespace) -> int:
    is_linux = sys.platform.startswith("linux")
    is_windows = os.name == "nt"
    python_ok = sys.version_info >= (3, 10)
    binary = shutil.which(args.binary)
    print(render_banner(args.company, args.theme, not args.no_color and sys.stdout.isatty()))
    print("\nAegisRoute runtime diagnostics")
    platform_status = "full Linux backend" if is_linux else "ICMP tracert fallback" if is_windows else "unsupported"
    print(f"  Platform       {sys.platform:<12} {platform_status}")
    print(f"  Python         {sys.version.split()[0]:<12} {'OK' if python_ok else 'Python 3.10+ required'}")
    print(f"  traceroute     {(binary or 'not found')}")
    if binary:
        help_text = traceroute_capabilities(binary)
        windows_backend = is_windows_backend(binary)
        print(f"  TCP probes     {'unavailable in Windows fallback' if windows_backend else 'supported' if '-T' in help_text else 'not advertised by backend'}")
        print(f"  ICMP probes    {'supported' if windows_backend or '-I' in help_text else 'not advertised by backend'}")
        print(f"  Flow pinning   {'unavailable in Windows fallback' if windows_backend else 'supported' if '--sport' in help_text else 'not advertised by backend'}")
        print(f"  MTU discovery  {'unavailable in Windows fallback' if windows_backend else 'supported' if '--mtu' in help_text else 'not advertised by backend'}")
    print(f"  SQLite history built in")
    scamper = shutil.which(args.scamper_binary)
    print(f"  Scamper        {scamper or 'optional backend not installed (Paris/MDA unavailable)'}")
    try:
        import pybgpstream  # type: ignore  # noqa: F401
        bgpstream_status = "available"
    except ImportError:
        bgpstream_status = "optional pybgpstream module not installed"
    print(f"  BGPStream      {bgpstream_status}")
    if is_linux and hasattr(os, "geteuid"):
        print(f"  Effective UID  {os.geteuid()} ({'root' if os.geteuid() == 0 else 'unprivileged; TCP/ICMP may need sudo'})")
    if not binary:
        print("\nFix: install the distribution 'traceroute' package or run ./install.sh")
    print("\nDemo check: aegisroute --demo")
    return 0 if (is_linux or is_windows) and python_ok and binary else 2


async def async_main(args: argparse.Namespace) -> int:
    if getattr(args, "atlas_id_list", None):
        loop = asyncio.get_running_loop()
        batches = await asyncio.gather(*(loop.run_in_executor(None, fetch_atlas_results, item)
                                         for item in args.atlas_id_list))
        reports = [normalize_atlas_results(item, rows, args.company)
                   for item, rows in zip(args.atlas_id_list, batches)]
        report = reports[0]
        merge_reports(report, reports[1:])
        report["target"] = "ripe-atlas:" + ",".join(str(item) for item in args.atlas_id_list)
        report["fusion_graph"] = build_fusion_graph(report)
        report["quality"] = quality_score(report)
        if args.store and report.get("traces"):
            report["measurement_id"] = MeasurementStore(args.store).save(report)
        print(json.dumps(report, indent=2))
        return 0 if any(batches) else 2
    if args.atlas_id is not None:
        results = await asyncio.get_running_loop().run_in_executor(None, fetch_atlas_results, args.atlas_id)
        report = normalize_atlas_results(args.atlas_id, results, args.company)
        report["quality"] = quality_score(report)
        report["mpls_analysis"] = mpls_analysis(report)
        if args.store and report.get("traces"):
            report["measurement_id"] = MeasurementStore(args.store).save(report)
        print(json.dumps(report, indent=2))
        return 0 if results else 2
    if args.history is not None:
        rows = MeasurementStore(args.store).history(args.target, args.history)
        print(json.dumps({"schema": "aegisroute/history-v1", "target": args.target, "count": len(rows),
                          "measurements": [{k: v for k, v in row.items() if k != "report"} for row in rows]}, indent=2))
        return 0
    if args.demo:
        args.target = args.target or "demo.aegisroute.local"
        traces = [trace for trace in demo_trace() if args.protocol == "all" or trace.protocol == args.protocol]
        if args.tnt_output:
            traces.append(load_tnt_trace(args.tnt_output, args.probes))
        report = make_report(args.target, "203.0.113.80", args, traces, utc_now())
        await augment_report(args, report, None)
        await deliver_alerts(args, report)
        if args.store:
            report["measurement_id"] = MeasurementStore(args.store).save(report)
        output_report(report, args)
        return 0
    family = socket.AF_INET6 if args.ipv6 else socket.AF_INET
    resolve_started = time.monotonic()
    target, destination_ip = await resolve_target(args.target, family)
    resolution_ms = round((time.monotonic() - resolve_started) * 1000, 3)
    args.active_backend = "scamper" if args.backend == "scamper" or (args.backend == "auto" and args.strategy != "classic") else "native"
    if args.active_backend == "scamper":
        scamper = shutil.which(args.scamper_binary)
        if not scamper:
            raise RuntimeError("Scamper is required for Paris/MDA; install the 'scamper' package or use --strategy classic")
        args.scamper_binary = scamper
        binary = scamper
    else:
        binary = shutil.which(args.binary)
    if not binary:
        expected = "Windows tracert" if os.name == "nt" else "Linux traceroute"
        raise RuntimeError(f"'{args.binary}' not found; install/enable {expected} or run ./install.sh on Linux")
    if args.active_backend == "native":
        args.binary = binary
    help_text = traceroute_capabilities(binary) if args.active_backend == "native" else ""
    modes = backend_protocols(args.protocol, binary) if args.active_backend == "native" else protocols(args.protocol)
    if args.strategy == "mda" and args.protocol == "all":
        modes = ["udp"]
    if args.dry_run:
        for mode in modes:
            if args.active_backend == "scamper":
                command, _ = build_scamper_command(args.scamper_binary, destination_ip, mode, args.strategy,
                                                   args.probes, args.first_hop, args.max_hops, args.wait,
                                                   args.port, args.mda_confidence, args.mda_max_probes)
                print(" ".join(command))
            else:
                print(" ".join(build_command(args, mode, destination_ip, help_text)))
        return 0
    baseline = load_baseline(args.compare)
    if baseline is None and args.store:
        rows = MeasurementStore(args.store).history(target, 1)
        baseline = rows[0]["report"] if rows else None
    cycle = 0
    while True:
        cycle += 1
        report = await one_cycle(args, target, destination_ip, help_text, baseline, modes)
        report["resolution"] = {"address": destination_ip, "family": "IPv6" if args.ipv6 else "IPv4",
                                "duration_ms": resolution_ms}
        await augment_report(args, report, baseline)
        await deliver_alerts(args, report)
        if args.store:
            report["measurement_id"] = MeasurementStore(args.store).save(report)
        output_report(report, args, append=bool(args.watch and args.output and cycle > 1))
        if not args.watch or (args.cycles and cycle >= args.cycles):
            failed = all(t["return_code"] != 0 for t in report["traces"])
            return 2 if failed else 0
        baseline = report
        if args.tui:
            if not await tui_wait(report, args, args.watch):
                return 0
        else:
            await asyncio.sleep(args.watch)


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except OSError:
                pass
    args = parser().parse_args()
    try:
        if args.doctor:
            return run_doctor(args)
        wants_interactive = args.interactive or (not args.target and not args.demo and args.atlas_id is None
                                                  and not args.atlas_ids and sys.stdin.isatty())
        if wants_interactive:
            interactive_setup(args)
        validate_args(args)
        return asyncio.run(async_main(args))
    except KeyboardInterrupt:
        return 130
    except (ValueError, RuntimeError, OSError, json.JSONDecodeError) as exc:
        print(f"aegisroute: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

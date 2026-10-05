import importlib.util
import json
import pathlib
import sys
import tempfile
import unittest


MODULE_PATH = pathlib.Path(__file__).parents[1] / "aegisroute.py"
sys.path.insert(0, str(MODULE_PATH.parent))
SPEC = importlib.util.spec_from_file_location("aegisroute", MODULE_PATH)
aegisroute = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
sys.modules[SPEC.name] = aegisroute
SPEC.loader.exec_module(aegisroute)
from aegisroute_advanced import MeasurementStore, normalize_atlas_results
from aegisroute_scamper import build_scamper_command, normalize_scamper_json
from aegisroute_pro import historical_findings, html_report, merge_reports, parse_interface_extensions, quality_score


class ParserTests(unittest.TestCase):
    def test_single_path_and_timeout(self):
        text = """traceroute to example.net (203.0.113.9), 30 hops max
 1  192.168.1.1  0.501 ms  0.420 ms  0.399 ms
 2  198.51.100.1  8.100 ms  *  9.300 ms
 3  * * *
"""
        hops = aegisroute.parse_traceroute(text, 3)
        self.assertEqual(len(hops), 3)
        self.assertEqual(hops[0].responders[0].ip, "192.168.1.1")
        self.assertEqual(hops[1].timeouts, 1)
        self.assertAlmostEqual(hops[1].stats()["avg_ms"], 8.7)
        self.assertEqual(hops[2].stats()["loss_pct"], 100.0)

    def test_windows_tracert_parser(self):
        text = """Tracing route to 127.0.0.1 over a maximum of 3 hops

  1    <1 ms    <1 ms    <1 ms  127.0.0.1
  2     *        *        *     Request timed out.
"""
        hops = aegisroute.parse_tracert(text)
        self.assertEqual(len(hops), 2)
        self.assertEqual(hops[0].responders[0].ip, "127.0.0.1")
        self.assertEqual(hops[0].responders[0].rtts_ms, [0.5, 0.5, 0.5])
        self.assertEqual(hops[1].stats()["loss_pct"], 100.0)

    def test_windows_all_protocol_choices_degrade_without_error(self):
        for requested in ("all", "icmp", "tcp", "udp"):
            self.assertEqual(aegisroute.backend_protocols(requested, "C:/Windows/System32/tracert.exe"), ["icmp"])

    def test_mpls_extension_parser(self):
        parsed = aegisroute.parse_mpls_extensions("MPLS Label=16002 Exp=0 TTL=1 S=1")
        self.assertEqual(parsed[0]["label"], 16002)
        self.assertEqual(parsed[0]["bottom_of_stack"], 1)

    def test_evidence_and_fusion_are_in_v3_report(self):
        args = aegisroute.parser().parse_args(["--demo", "--no-enrich"])
        aegisroute.validate_args(args)
        report = aegisroute.make_report("demo", "203.0.113.80", args, aegisroute.demo_trace(), aegisroute.utc_now())
        self.assertEqual(report["schema"], "aegisroute/v3")
        self.assertTrue(report["fusion_graph"]["nodes"])
        self.assertTrue(all("confidence" in finding for finding in report["findings"]))

    def test_prometheus_export(self):
        args = aegisroute.parser().parse_args(["--demo", "--no-enrich"])
        aegisroute.validate_args(args)
        report = aegisroute.make_report("demo", "203.0.113.80", args, aegisroute.demo_trace(), aegisroute.utc_now())
        output = aegisroute.prometheus_text(report)
        self.assertIn("aegisroute_target_reachable", output)
        self.assertIn("aegisroute_hop_rtt_milliseconds", output)

    def test_ecmp_multiple_responders(self):
        hop = aegisroute.parse_hop(
            " 5  192.0.2.1  12.0 ms  192.0.2.2  13.0 ms  192.0.2.1  12.5 ms", 3
        )
        self.assertIsNotNone(hop)
        self.assertEqual(len(hop.responders), 2)
        self.assertEqual(hop.responders[0].rtts_ms, [12.0, 12.5])

    def test_icmp_annotation(self):
        hop = aegisroute.parse_hop(" 7  203.0.113.1  20.2 ms !H  * *", 3)
        self.assertEqual(hop.responders[0].annotations, ["!H"])

    def test_ip_classification(self):
        self.assertEqual(aegisroute.classify_ip("127.0.0.1"), "loopback")
        self.assertEqual(aegisroute.classify_ip("192.168.1.1"), "private")
        self.assertEqual(aegisroute.classify_ip("100.64.1.1"), "carrier-nat")
        self.assertEqual(aegisroute.classify_ip("8.8.8.8"), "global")

    def test_demo_exercises_three_protocols(self):
        traces = aegisroute.demo_trace()
        self.assertEqual([trace.protocol for trace in traces], ["udp", "tcp", "icmp"])
        self.assertTrue(all(trace.hops for trace in traces))

    def test_default_company_brand(self):
        args = aegisroute.parser().parse_args(["--demo"])
        self.assertEqual(args.company, "Advaitik Intelligence")

    def test_help_documents_all_options_and_concepts(self):
        help_text = aegisroute.parser().format_help()
        for option in ("--protocol", "--probes", "--flow-consistent", "--enrich", "--compare",
                       "--watch", "--doctor", "--company", "--theme", "--no-color", "--strategy",
                       "--store", "--atlas-id"):
            self.assertIn(option, help_text)
        for concept in ("TTL/hop limit", "Jitter", "ECMP/multipath", "EXIT STATUS", "PRIVACY"):
            self.assertIn(concept, help_text)

    def test_scamper_paris_and_mda_are_real_commands(self):
        command, measurement = build_scamper_command("scamper", "1.1.1.1", "udp", "paris", 3, 1, 30, 1, 443, 95)
        self.assertIn("udp-paris", measurement)
        self.assertIn("json", command)
        _, mda = build_scamper_command("scamper", "1.1.1.1", "udp", "mda", 3, 1, 30, 1, 443, 99)
        self.assertIn("tracelb", mda)
        self.assertIn("-c 99", mda)
        self.assertIn("-Q 1000", mda)

    def test_scamper_json_normalization(self):
        payload = {"type": "trace", "hops": [{"probe_ttl": 1, "replies": [
            {"from": "192.0.2.1", "rtt": 1.25}, {"from": "192.0.2.2", "rtt": {"usec": 2500}}
        ]}]}
        hops = normalize_scamper_json(payload, 3)
        self.assertEqual(hops[0]["ttl"], 1)
        self.assertEqual(len(hops[0]["responders"]), 2)
        self.assertEqual(hops[0]["responders"][1]["rtts_ms"], [2.5])
        tracelb = {"type": "tracelb", "nodes": [{"addr": "192.0.2.1", "links": [[{
            "addr": "192.0.2.2", "probes": [{"ttl": 4, "replies": [{"from": "192.0.2.2", "rtt": 8.2}]}]
        }]]}]}
        mda_hops = normalize_scamper_json(tracelb, 3)
        self.assertEqual(mda_hops[0]["ttl"], 4)
        self.assertEqual(mda_hops[0]["responders"][0]["ip"], "192.0.2.2")

    def test_atlas_normalization_uses_v3_fusion_model(self):
        sample = [{"prb_id": 7, "dst_addr": "1.1.1.1", "proto": "ICMP", "timestamp": 1,
                   "result": [{"hop": 1, "result": [{"from": "192.0.2.1", "rtt": 1.5}, {"x": "*"}]}]}]
        report = normalize_atlas_results(42, sample, "Advaitik Intelligence")
        self.assertEqual(report["schema"], "aegisroute/v3")
        self.assertEqual(report["settings"]["backend"], "ripe-atlas")
        self.assertTrue(report["fusion_graph"]["nodes"])

    def test_rfc5837_interface_extension_parser(self):
        values = parse_interface_extensions("Interface outgoing ifIndex=7 name=xe-0/0/0 MTU=1500 address=192.0.2.8")
        self.assertEqual(values[0]["role"], "outgoing")
        self.assertEqual(values[0]["ifindex"], 7)
        self.assertEqual(values[0]["mtu"], 1500)

    def test_quality_history_merge_and_html(self):
        args = aegisroute.parser().parse_args(["--demo", "--no-enrich"])
        aegisroute.validate_args(args)
        old = aegisroute.make_report("demo", "203.0.113.80", args, aegisroute.demo_trace(), aegisroute.utc_now())
        current = json.loads(json.dumps(old))
        current["traces"][0]["hops"][0]["stats"]["avg_ms"] += 50
        findings = historical_findings(old, current, 25)
        self.assertTrue(any(item["type"] == "persistent_latency_change" for item in findings))
        self.assertGreater(quality_score(old)["score"], 0)
        merged = merge_reports(current, [old])
        self.assertEqual(merged["distributed_measurement"]["source_count"], 2)
        self.assertIn("Route Intelligence Report", html_report(merged))

    def test_persistent_enrichment_cache(self):
        with tempfile.TemporaryDirectory() as folder:
            store = MeasurementStore(str(pathlib.Path(folder) / "history.db"))
            store.cache_set("asn", {"8.8.8.8": {"asn": 15169}}, 60)
            self.assertEqual(store.cache_get("asn", ["8.8.8.8"])["8.8.8.8"]["asn"], 15169)


if __name__ == "__main__":
    unittest.main()

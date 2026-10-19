#!/usr/bin/env python3
"""Tests for the scenario-C generator and validator (unittest, stdlib)."""

import datetime
import json
import os
import re
import sys
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "lab"))

import generate as g  # noqa: E402
import run as r  # noqa: E402
import validate as v  # noqa: E402

# The fields allowed on an sdp-lab event (the data contract).
ALLOWED_FIELDS = {
    "@timestamp", "event.kind", "event.dataset", "event.code", "event.action",
    "lab.run_id", "lab.mode", "lab.variant", "host.name", "process.pid",
    "process.name", "process.executable", "process.hash.sha256",
    "process.parent.name", "registry.path", "file.path",
    "destination.ip", "destination.port",
}
# Keyword fields whose values must never contain a space (SA rule).
KEYWORD_FIELDS = ALLOWED_FIELDS - {"process.pid", "lab.variant", "destination.port"}

START = datetime.datetime(2026, 10, 18, 9, 0, 0, tzinfo=datetime.timezone.utc)


def gen(copies=4):
    return g.generate(copies, ["ws1.lab.local", "ws2.lab.local"],
                      "198.51.100.10", 8080, START, "lab-20261018T090000Z-abc123", "generated")


class GeneratorTest(unittest.TestCase):
    def test_copy1_hash_is_deterministic(self):
        self.assertEqual(g.copy1_sha256(), g.copy1_sha256())
        self.assertRegex(g.copy1_sha256(), r"^[0-9a-f]{64}$")
        c1 = g.build_copies(4, ["ws1.lab.local", "ws2.lab.local"])[0]
        self.assertEqual(c1["sha256"], g.copy1_sha256())
        self.assertEqual(c1["name"], "update-helper.exe")

    def test_copies_2_to_n_are_unique(self):
        copies = g.build_copies(4, ["ws1.lab.local", "ws2.lab.local"])
        hashes = [c["sha256"] for c in copies]
        names = [c["name"] for c in copies]
        self.assertEqual(len(set(hashes)), 4, "hashes must be unique")
        self.assertEqual(len(set(names)), 4, "names must be unique")
        for c in copies[1:]:
            self.assertRegex(c["name"], r"^svc-[0-9a-f]{8}\.exe$")

    def test_events_conform_to_contract(self):
        events, _ = gen()
        self.assertTrue(events)
        for e in events:
            self.assertIn(e["event.code"], {"1", "3", "13"})
            for key in e:
                self.assertIn(key, ALLOWED_FIELDS, f"unexpected field {key}")
            for key in KEYWORD_FIELDS:
                if key in e:
                    self.assertNotIn(" ", str(e[key]), f"{key} has a space")

    def test_ndjson_is_nested(self):
        import tempfile
        with tempfile.TemporaryDirectory() as out:
            g.main(["--out", out, "--start", "2026-10-18T09:00:00Z"])
            with open(os.path.join(out, "events.ndjson"), encoding="utf-8") as fh:
                docs = [json.loads(line) for line in fh]
        self.assertTrue(docs)
        for d in docs:
            self.assertIn("@timestamp", d)
            for key in d:
                self.assertTrue(key == "@timestamp" or "." not in key, f"flat key {key}")
            self.assertIn(d["event"]["code"], {"1", "3", "13"})
            self.assertEqual(d["event"]["dataset"], "lab")
        first = docs[0]
        self.assertEqual(first["process"]["hash"]["sha256"], g.copy1_sha256())
        self.assertEqual(first["process"]["parent"]["name"], "explorer.exe")
        reg = next(d for d in docs if d["event"]["code"] == "13")
        self.assertIn("\\CurrentVersion\\Run\\", reg["registry"]["path"])
        self.assertIn("\\AppData\\Local\\Temp\\", reg["process"]["executable"])
        net = next(d for d in docs if d["event"]["code"] == "3")
        self.assertEqual(net["destination"], {"ip": "198.51.100.10", "port": 8080})

    def test_beacon_logic_is_satisfiable(self):
        events, _ = gen()
        code3 = [e for e in events if e["event.code"] == "3" and e["lab.variant"] == 1]
        self.assertGreaterEqual(len(code3), 5, "need 5+ beacons within 10 min per copy")
        times = [v._parse(e["@timestamp"]) for e in code3]
        span = (max(times) - min(times)).total_seconds()
        self.assertLessEqual(span, 600)

    def test_run_json_is_clean_and_small(self):
        _, run_doc = gen()
        self.assertFalse(run_doc["sample"])
        self.assertEqual(run_doc["beacon"], "lab beacon :8080")
        for variant in run_doc["variants"]:
            self.assertIn(variant["host"], {"ws1", "ws2"})
            self.assertEqual(variant["findings"], [])
        blob = json.dumps(run_doc, indent=2)
        self.assertLessEqual(len(blob.encode("utf-8")), 64 * 1024)
        self.assertNotIn(".lab.local", blob)
        self.assertEqual(re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", blob), [])


class ValidatorTest(unittest.TestCase):
    def _run_doc(self):
        return gen()[1]

    def test_hash_catches_one_incident_at_two(self):
        run_doc = self._run_doc()
        # Hash fires only on copy 1; run-key on all; beacon monitor opens the
        # incident at copy 2 (two distinct hashes to one beacon address).
        detections = [
            {"rule": "ioc-update-helper-sha256", "variant": 1, "at": "2026-10-18T09:00:58Z"},
            {"rule": "run-key-from-temp", "variant": 1, "at": "2026-10-18T09:01:03Z"},
            {"rule": "run-key-from-temp", "variant": 2, "at": "2026-10-18T09:10:04Z"},
            {"rule": "run-key-from-temp", "variant": 3, "at": "2026-10-18T09:19:02Z"},
            {"rule": "run-key-from-temp", "variant": 4, "at": "2026-10-18T09:28:02Z"},
            {"rule": "lab-beaconing", "variant": 2, "at": "2026-10-18T09:14:05Z"},
        ]
        incident = {"variant": 2, "at": "2026-10-18T09:11:00Z"}
        final = v.validate(run_doc, {"detections": detections, "incident": incident})

        caught = [x["n"] for x in final["variants"] if x["caught_by_hash"]]
        self.assertEqual(caught, [1], "hash must catch exactly copy 1")
        self.assertEqual(final["incident"]["opened_at_variant"], 2)
        self.assertEqual(final["incident"]["key"], "beacon")
        self.assertEqual(final["incident"]["delay_s"], 120)

        v1 = next(x for x in final["variants"] if x["n"] == 1)
        hashf = next(f for f in v1["findings"] if f["rule"] == "ioc-update-helper-sha256")
        self.assertEqual(hashf["delay_s"], 58)
        self.assertIn("T1204.002", final["techniques"]["detected"])
        self.assertIn("T1027", final["techniques"]["expected"])

    def test_no_incident_when_none(self):
        run_doc = self._run_doc()
        final = v.validate(run_doc, {"detections": [], "incident": None})
        self.assertIsNone(final["incident"]["opened_at_variant"])
        self.assertIsNone(final["incident"]["delay_s"])
        self.assertEqual(final["techniques"]["detected"], [])


FIXTURES = os.path.join(HERE, "fixtures")
# The run the saved raw responses were captured from (run_id and start reconstructed
# from the findings' embedded documents).
RAW_RUN_ID = "lab-20261018T135746Z-1b7a3b"
RAW_START = datetime.datetime(2026, 10, 18, 13, 24, 46, tzinfo=datetime.timezone.utc)


class SAParserTest(unittest.TestCase):
    """The parser turns real OpenSearch Security Analytics findings and Alerting
    alerts (saved from a live siem01 run) into the final run document."""

    def _raw(self):
        with open(os.path.join(FIXTURES, "raw_findings.json"), encoding="utf-8") as fh:
            raw_findings = json.load(fh)
        with open(os.path.join(FIXTURES, "raw_alerts.json"), encoding="utf-8") as fh:
            raw_alerts = json.load(fh)
        return raw_findings, raw_alerts

    def _final(self):
        _, run_doc = g.generate(4, ["ws1.lab.local", "ws2.lab.local"],
                                "198.51.100.10", 8080, RAW_START, RAW_RUN_ID, "generated")
        raw_findings, raw_alerts = self._raw()
        findings = v.parse_sa(raw_findings, raw_alerts, run_doc)
        return run_doc, v.validate(run_doc, findings)

    def test_hash_caught_one_of_four(self):
        _, final = self._final()
        caught = [x["n"] for x in final["variants"] if x["caught_by_hash"]]
        self.assertEqual(caught, [1], "the known-hash rule catches copy 1 only")

    def test_run_key_fires_on_all_four_hash_only_on_one(self):
        _, final = self._final()
        run_key = [x["n"] for x in final["variants"]
                   if any(f["rule"] == "run-key-from-temp" for f in x["findings"])]
        hash_hits = [x["n"] for x in final["variants"]
                     if any(f["rule"] == "ioc-update-helper-sha256" for f in x["findings"])]
        self.assertEqual(run_key, [1, 2, 3, 4])
        self.assertEqual(hash_hits, [1])

    def test_incident_opens_at_copy_two(self):
        _, final = self._final()
        self.assertEqual(final["incident"]["opened_at_variant"], 2)
        self.assertEqual(final["incident"]["key"], "beacon")
        # Independent expected delay: the alert start_time against copy 2's first event.
        alert_at = datetime.datetime.fromtimestamp(1792331906207 / 1000, tz=datetime.timezone.utc)
        expected = round((alert_at - datetime.datetime(2026, 10, 18, 13, 33, 46,
                                                        tzinfo=datetime.timezone.utc)).total_seconds())
        self.assertEqual(final["incident"]["delay_s"], expected)

    def test_techniques_expected_vs_detected(self):
        _, final = self._final()
        self.assertEqual(final["techniques"]["detected"],
                         ["T1071.001", "T1204.002", "T1547.001"])
        self.assertEqual(final["techniques"]["expected"],
                         ["T1027", "T1071.001", "T1204.002", "T1547.001"])

    def test_isolated_vm_finding_is_ignored(self):
        # The saved findings include an isolated-VM copy (variant 11, T1543.002); it
        # is not a variant of this generated run, so it never appears.
        _, final = self._final()
        self.assertTrue(all(x["n"] in {1, 2, 3, 4} for x in final["variants"]))
        all_rules = {f["rule"] for x in final["variants"] for f in x["findings"]}
        self.assertNotIn("lab-persistence-user-unit-from-tmp", all_rules)

    def test_final_doc_shape_and_caps(self):
        run_doc, final = self._final()
        self.assertFalse(final["sample"])
        self.assertEqual(final["run"]["mode"], "generated")
        self.assertEqual(final["run"]["id"], RAW_RUN_ID)
        for x in final["variants"]:
            self.assertIsInstance(x["caught_by_hash"], bool)
            self.assertIsInstance(x["findings"], list)
            for f in x["findings"]:
                self.assertIsInstance(f["delay_s"], int)
        out_bytes = json.dumps(final, indent=2).encode("utf-8")
        self.assertLessEqual(len(out_bytes), 64 * 1024)
        v._assert_no_leak(out_bytes)  # raises on a real host/address leak
        self.assertNotIn(".lab.local", out_bytes.decode("utf-8"))

    def test_findings_filtered_by_run_id(self):
        # Security Analytics findings carry the matched document's lab.run_id; a run
        # document for a different run gets none of them. (Bucket-level alerts carry
        # no run_id; run.py polls them by the current monitor window, so the parser
        # trusts the alerts it is handed.)
        _, other = g.generate(4, ["ws1.lab.local", "ws2.lab.local"],
                              "198.51.100.10", 8080, RAW_START, "lab-20260101T000000Z-000000", "generated")
        raw_findings, _ = self._raw()
        self.assertEqual(v.parse_sa_findings(raw_findings, other), [])


# The exact environment contract run.py consumes. Its authoritative counterpart
# is cluster/infra/lab/cronjob.yaml in the self-defending-portfolio repository (a
# different repo, which cannot be imported here), so this test freezes the set:
# renaming or adding an env name in run.py breaks it, forcing the CronJob to be
# kept in step. The CronJob supplies the required four plus LAB_MODE; the rest are
# defaulted so they are never required.
REQUIRED_ENV = {"SIEM_URL", "SIEM_CLIENT_CERT", "SIEM_CLIENT_KEY", "SIEM_CA_CERT"}
OPTIONAL_ENV = {"LAB_MODE", "LAB_STREAM", "LAB_RUNS_INDEX",
                "LAB_DETECTOR_NAME", "LAB_MONITOR_NAME"}
CRONJOB_ENV = {
    "SIEM_URL": "https://10.4.2.10:9200",
    "SIEM_CLIENT_CERT": "/etc/lab-runner/siem/tls.crt",
    "SIEM_CLIENT_KEY": "/etc/lab-runner/siem/tls.key",
    "SIEM_CA_CERT": "/etc/lab-runner/siem/ca.crt",
    "LAB_MODE": "generated",
}


class RunEnvContractTest(unittest.TestCase):
    """Freeze the CronJob env contract so run.py and the SDP CronJob can't drift."""

    def test_source_references_exactly_the_contract_env(self):
        with open(os.path.join(HERE, "..", "lab", "run.py"), encoding="utf-8") as fh:
            src = fh.read()
        found = set(re.findall(r"\b(?:SIEM|LAB)_[A-Z_]+\b", src))
        self.assertEqual(found, REQUIRED_ENV | OPTIONAL_ENV,
                         "run.py references an env var outside the frozen contract "
                         "(update cluster/infra/lab/cronjob.yaml in SDP to match)")

    def test_cronjob_env_only_parses_and_satisfies_required(self):
        # `python3 /app/lab/run.py` with ONLY the CronJob's env (no args) must parse
        # and pass the required-argument check.
        with mock.patch.dict(os.environ, CRONJOB_ENV, clear=True):
            args = r.parse_args([])
            r._require(args, ["endpoint", "client-cert", "client-key", "cacert"])
        self.assertEqual(args.endpoint, "https://10.4.2.10:9200")
        self.assertEqual(args.client_cert, "/etc/lab-runner/siem/tls.crt")
        self.assertEqual(args.client_key, "/etc/lab-runner/siem/tls.key")
        self.assertEqual(args.cacert, "/etc/lab-runner/siem/ca.crt")
        self.assertEqual(args.mode, "generated")

    def test_optional_env_have_working_defaults(self):
        with mock.patch.dict(os.environ, CRONJOB_ENV, clear=True):
            args = r.parse_args([])
        self.assertEqual(args.stream, "sdp-lab")
        self.assertEqual(args.runs_index, "lab-runs")
        self.assertEqual(args.detector_name, "sdp-lab-rules")
        self.assertEqual(args.monitor_name, "sdp-git: lab-polymorphic-beacon")

    def test_required_env_missing_fails_clearly(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            args = r.parse_args([])
            with self.assertRaises(SystemExit) as ctx:
                r._require(args, ["endpoint", "client-cert", "client-key", "cacert"])
        self.assertIn("missing required argument(s)", str(ctx.exception))

    def test_help_exits_zero(self):
        with self.assertRaises(SystemExit) as ctx:
            r.parse_args(["--help"])
        self.assertEqual(ctx.exception.code, 0)


class RunDiscoveryTest(unittest.TestCase):
    """The detector/monitor ids are OpenSearch-generated and dynamic, so run.py
    resolves them by name at runtime. The discovery request construction and the
    exact-name resolution are unit-tested against a fake HTTP (no siem01)."""

    ENDPOINT = "https://siem.example:9200"

    def _fake_https(self, by_path):
        calls = []

        def fake(method, endpoint, path, ctx, body=None, headers=None):
            calls.append({"method": method, "endpoint": endpoint, "path": path,
                          "body": body, "headers": headers})
            status, payload = by_path[path.split("?")[0]]
            return status, json.dumps(payload).encode("utf-8")

        return fake, calls

    def test_discover_detector_builds_request_and_resolves_id(self):
        resp = {"hits": {"hits": [
            {"_id": "det-xyz", "_source": {"name": "sdp-lab-rules", "detector_type": "sdp_lab"}},
            {"_id": "det-other", "_source": {"name": "some-other-detector"}},
        ]}}
        fake, calls = self._fake_https({r.DETECTORS_SEARCH_PATH: (200, resp)})
        with mock.patch.object(r, "https", fake):
            det_id = r.discover_detector_id(self.ENDPOINT, None, "sdp-lab-rules")
        self.assertEqual(det_id, "det-xyz")
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["method"], "POST")
        self.assertEqual(calls[0]["path"], r.DETECTORS_SEARCH_PATH)
        self.assertEqual(calls[0]["headers"], {"Content-Type": "application/json"})
        sent = json.loads(calls[0]["body"])
        self.assertEqual(sent["query"]["match_phrase"]["name"], "sdp-lab-rules")

    def test_discover_monitor_builds_request_and_resolves_id(self):
        name = "sdp-git: lab-polymorphic-beacon"
        resp = {"hits": {"hits": [
            {"_id": "mon-123", "_source": {"name": name, "enabled": True}},
            {"_id": "wf-1", "_source": {"name": name, "type": "workflow"}},
        ]}}
        fake, calls = self._fake_https({r.MONITORS_SEARCH_PATH: (200, resp)})
        with mock.patch.object(r, "https", fake):
            mon_id = r.discover_monitor_id(self.ENDPOINT, None, name)
        # The workflow hit with the same name is ignored; one real monitor resolves.
        self.assertEqual(mon_id, "mon-123")
        self.assertEqual(calls[0]["path"], r.MONITORS_SEARCH_PATH)
        sent = json.loads(calls[0]["body"])
        self.assertEqual(sent["query"]["match_phrase"]["name"], name)

    def test_discover_fails_when_name_absent(self):
        resp = {"hits": {"hits": [{"_id": "x", "_source": {"name": "unrelated"}}]}}
        fake, _ = self._fake_https({r.DETECTORS_SEARCH_PATH: (200, resp)})
        with mock.patch.object(r, "https", fake):
            with self.assertRaises(SystemExit) as ctx:
                r.discover_detector_id(self.ENDPOINT, None, "sdp-lab-rules")
        self.assertIn("no detector named", str(ctx.exception))

    def test_discover_fails_when_name_ambiguous(self):
        resp = {"hits": {"hits": [
            {"_id": "a", "_source": {"name": "sdp-lab-rules"}},
            {"_id": "b", "_source": {"name": "sdp-lab-rules"}},
        ]}}
        fake, _ = self._fake_https({r.DETECTORS_SEARCH_PATH: (200, resp)})
        with mock.patch.object(r, "https", fake):
            with self.assertRaises(SystemExit) as ctx:
                r.discover_detector_id(self.ENDPOINT, None, "sdp-lab-rules")
        self.assertIn("cannot resolve a single id", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()

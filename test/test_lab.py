#!/usr/bin/env python3
"""Tests for the scenario-C generator and validator (unittest, stdlib)."""

import datetime
import json
import os
import re
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "lab"))

import generate as g  # noqa: E402
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


if __name__ == "__main__":
    unittest.main()

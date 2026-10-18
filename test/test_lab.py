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


if __name__ == "__main__":
    unittest.main()

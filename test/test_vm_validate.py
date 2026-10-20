#!/usr/bin/env python3
"""Variant B validator (lab/vm_validate.py, run.py --mode isolated-vm) against a real run.

The fixtures are siem01's own answers for run lab-20261019T191309Z-4e396b (the second real run on
the isolated VM, before copy 1's hash was pinned): its 39 sdp-lab documents, the Security Analytics
findings of that run plus one of a variant A run (which must be ignored), and every alert of the
lab monitor (only the one inside the run's window may count).
"""

import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "lab"))

import run  # noqa: E402
import validate  # noqa: E402
import vm_validate as vv  # noqa: E402


def fixture(name):
    with open(os.path.join(HERE, "fixtures", name), encoding="utf-8") as fh:
        return json.load(fh)


RUN = fixture("vm_run_docs.json")
RUN_ID = RUN["run_id"]


def build():
    doc = vv.build_run_doc(RUN_ID, RUN["docs"])
    alerts = run._run_window_alerts(fixture("vm_raw_alerts.json"), doc)
    return vv.finish(doc, fixture("vm_raw_findings.json"), alerts), alerts


class BuildTest(unittest.TestCase):
    def test_run_and_lifecycle(self):
        d = vv.build_run_doc(RUN_ID, RUN["docs"])
        self.assertEqual(d["run"]["mode"], "isolated-vm")
        self.assertEqual(d["run"]["started_at"], "2026-10-19T19:12:45.000Z")  # the rollback marker
        self.assertEqual(d["run"]["duration_s"], 190)
        marks = [m["marker"] for m in d["lifecycle"]]
        self.assertEqual(marks[0], "rollback")
        self.assertEqual(marks[-1], "poweroff_requested")
        self.assertEqual(len(marks), 8)
        offs = [m["offset_s"] for m in d["lifecycle"]]
        self.assertEqual(offs, sorted(offs), "lifecycle is in time order")

    def test_copies(self):
        d = vv.build_run_doc(RUN_ID, RUN["docs"])
        self.assertEqual([v["n"] for v in d["variants"]], [1, 2, 3, 4])
        v1 = d["variants"][0]
        self.assertEqual(v1["renamed"], "update-helper")
        self.assertEqual(v1["sha256"], "f876f3ff0694f1dad661d2e63d4c65709dde4499f2f4c5cd3068990127f3e332")
        self.assertEqual(len({v["sha256"] for v in d["variants"]}), 4)
        for v in d["variants"]:
            self.assertIn("pid", v)
            self.assertIn("ppid", v)
            self.assertEqual(v["host"], "lab-vm")
            self.assertEqual(v["events"][0]["event.code"], "1")
            self.assertEqual(v["ground_truth"]["variant_sha256"], v["sha256"])
            self.assertEqual("T1027" in v["ground_truth"]["techniques"], v["n"] > 1)

    def test_beacon_address_masked(self):
        d = vv.build_run_doc(RUN_ID, RUN["docs"])
        beacons = [e for v in d["variants"] for e in v["events"] if e["event.code"] == "3"]
        self.assertTrue(beacons)
        self.assertTrue(all(e["destination.ip"] == "lab beacon :8080" for e in beacons))
        validate._assert_no_leak(json.dumps(d).encode())

    def test_no_events_refused(self):
        markers_only = [x for x in RUN["docs"] if x.get("event", {}).get("action") == "lifecycle"]
        with self.assertRaises(SystemExit):
            vv.build_run_doc(RUN_ID, markers_only)

    def test_without_rollback_offsets_stay_non_negative(self):
        docs = [x for x in RUN["docs"] if x.get("lab", {}).get("marker") not in ("rollback", "start")]
        d = vv.build_run_doc(RUN_ID, docs)
        self.assertNotIn("rollback", [m["marker"] for m in d["lifecycle"]])
        self.assertTrue(all(e["offset_s"] >= 0 for v in d["variants"] for e in v["events"]))


class FinishTest(unittest.TestCase):
    def test_only_this_runs_alert_counts(self):
        _, alerts = build()
        self.assertEqual(len(alerts["alerts"]), 1)

    def test_findings_incident_counters(self):
        final, _ = build()
        # The hash was pinned after this run: the known-hash rule caught none of the 4 copies.
        self.assertEqual([v["caught_by_hash"] for v in final["variants"]], [False] * 4)
        for v in final["variants"]:
            rules = [f["rule"] for f in v["findings"]]
            self.assertIn("lab-persistence-user-unit-from-tmp", rules)
            for f in v["findings"]:
                self.assertEqual(f["at_offset_s"], v["events"][0]["offset_s"] + f["delay_s"])
        self.assertEqual(final["incident"]["opened_at_variant"], 2)
        self.assertEqual(final["incident"]["key"], "beacon")
        self.assertIn("at_offset_s", final["incident"])
        c = final["counters"]
        self.assertEqual(c["events"], sum(len(v["events"]) for v in final["variants"]))
        self.assertEqual(c["events"], 31)
        self.assertEqual(c["findings"], 5)
        self.assertEqual((c["processes"], c["unique_hashes"], c["incidents"]), (4, 4, 1))
        self.assertEqual(final["techniques"]["detected"], ["T1071.001", "T1543.002"])

    def test_a_finding_of_another_run_is_ignored(self):
        final, _ = build()
        self.assertEqual(sum(len(v["findings"]) for v in final["variants"]), 5)

    def test_fits_the_cap_and_does_not_leak(self):
        final, _ = build()
        out = json.dumps(final, separators=(",", ":")).encode()
        self.assertLess(len(out), 64 * 1024)
        validate._assert_no_leak(out)


class PinnedHashTest(unittest.TestCase):
    """The control run after copy 1's hash was pinned (lab-20261020T065649Z-6f5f9b): its real
    findings, fetched the way main_vm does (detectorType + the run's time range)."""

    def test_hash_rule_catches_exactly_copy_1(self):
        r3 = fixture("vm_run3_docs.json")
        doc = vv.build_run_doc(r3["run_id"], r3["docs"])
        final = vv.finish(doc, fixture("vm_run3_findings.json"), {"alerts": []})
        self.assertEqual([v["caught_by_hash"] for v in final["variants"]], [True, False, False, False])
        self.assertEqual(final["variants"][0]["sha256"],
                         "f876f3ff0694f1dad661d2e63d4c65709dde4499f2f4c5cd3068990127f3e332")
        self.assertIn("T1204.002", final["techniques"]["detected"])
        # No alert handed in: no incident, and the counters say so.
        self.assertIsNone(final["incident"]["opened_at_variant"])
        self.assertEqual(final["counters"]["incidents"], 0)

    def test_findings_query_is_scoped_to_the_run(self):
        doc = vv.build_run_doc(RUN_ID, RUN["docs"])
        path = run.vm_findings_path(doc)
        self.assertIn("detectorType=sdp_lab", path)
        t0 = int(validate._parse(doc["run"]["started_at"]).timestamp() * 1000)
        self.assertIn(f"startTime={t0}", path)
        self.assertNotIn("size=10000", path)


class PublishTest(unittest.TestCase):
    def test_bulk_action_carries_the_run_id(self):
        sent = {}

        def fake_https(method, endpoint, path, ctx, body=None, headers=None):
            sent["body"] = body
            return 200, b'{"errors":false,"items":[{}]}'
        orig = run.https
        run.https = fake_https
        try:
            run.publish_run_doc("https://x:9200", "lab-runs", {"run": {"id": RUN_ID}}, None, doc_id=RUN_ID)
        finally:
            run.https = orig
        action = json.loads(sent["body"].decode().splitlines()[0])
        self.assertEqual(action, {"index": {"_index": "lab-runs", "_id": RUN_ID}})

    def test_mode_parses(self):
        args = run.parse_args(["--mode", "isolated-vm", "--dry-run", "--endpoint", "https://x:9200",
                               "--client-cert", "c", "--client-key", "k", "--cacert", "a"])
        self.assertEqual(args.mode, "isolated-vm")
        self.assertTrue(args.dry_run)


if __name__ == "__main__":
    unittest.main()

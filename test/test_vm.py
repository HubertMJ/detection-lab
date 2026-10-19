#!/usr/bin/env python3
"""Tests for the variant B scenario builder (unittest, stdlib). The pure builder logic is tested
against a synthetic base image so no compiler is needed; if the real compiled canary is present
(dist/lab-canary) it is checked too."""

import hashlib
import os
import re
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "vm"))

import run_scenario as rs  # noqa: E402

# A synthetic "base": some bytes, the magic, 32 zero marker bytes, more bytes. Enough for the
# builder's byte-patching logic without compiling anything.
SYNTH_BASE = b"\x7fELF" + b"\x00" * 100 + rs.MAGIC + bytes(rs.MARKER_LEN) + b"tail" * 50
REAL = os.path.join(HERE, "..", "vm", "dist", "lab-canary")


class BuilderTest(unittest.TestCase):
    def test_marker_offset_found_once(self):
        off = rs._marker_offset(SYNTH_BASE)
        self.assertEqual(SYNTH_BASE[off - len(rs.MAGIC):off], rs.MAGIC)
        self.assertEqual(SYNTH_BASE[off:off + rs.MARKER_LEN], bytes(rs.MARKER_LEN))

    def test_marker_missing_is_fatal(self):
        with self.assertRaises(SystemExit):
            rs._marker_offset(b"no magic here")

    def test_marker_duplicate_is_fatal(self):
        with self.assertRaises(SystemExit):
            rs._marker_offset(SYNTH_BASE + rs.MAGIC + bytes(rs.MARKER_LEN))

    def test_four_distinct_hashes_copy1_is_base(self):
        copies = rs.build_variants(SYNTH_BASE, 4)
        self.assertEqual(len(copies), 4)
        hashes = [c["sha256"] for c in copies]
        self.assertEqual(len(set(hashes)), 4, "every copy must have a distinct hash")
        # Copy 1 is byte-for-byte the base (marker already zero), so it hashes to the base.
        self.assertEqual(copies[0]["sha256"], hashlib.sha256(SYNTH_BASE).hexdigest())
        self.assertEqual(copies[0]["image"], SYNTH_BASE)

    def test_copy1_deterministic_across_builds(self):
        a = rs.build_variants(SYNTH_BASE, 4)[0]
        b = rs.build_variants(SYNTH_BASE, 4)[0]
        self.assertEqual(a["sha256"], b["sha256"])

    def test_names(self):
        copies = rs.build_variants(SYNTH_BASE, 4)
        self.assertEqual(copies[0]["name"], rs.COPY1_NAME)
        self.assertEqual(len({c["name"] for c in copies}), 4)
        for c in copies[1:]:
            self.assertRegex(c["name"], r"^svc-[0-9a-f]{8}$")

    def test_only_the_marker_changes(self):
        off = rs._marker_offset(SYNTH_BASE)
        img = rs.build_variants(SYNTH_BASE, 2)[1]["image"]
        self.assertEqual(img[:off], SYNTH_BASE[:off])
        self.assertEqual(img[off + rs.MARKER_LEN:], SYNTH_BASE[off + rs.MARKER_LEN:])
        self.assertNotEqual(img[off:off + rs.MARKER_LEN], SYNTH_BASE[off:off + rs.MARKER_LEN])

    def test_run_id_format(self):
        import datetime
        rid = rs.run_id(datetime.datetime(2026, 10, 19, 7, 36, 10, tzinfo=datetime.timezone.utc))
        self.assertRegex(rid, r"^lab-20261019T073610Z-[0-9a-f]{6}$")

    def test_persistence_path(self):
        os.environ["HOME"] = "/home/labuser"
        self.assertEqual(rs._persistence_path("update-helper"),
                         "/home/labuser/.config/systemd/user/update-helper.service")

    def test_namemap_written_for_the_lua_mapper(self):
        import tempfile
        copies = rs.build_variants(SYNTH_BASE, 4)
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "namemap")
            rs.write_namemap(path, "lab-20261019T073610Z-abc123", copies)
            with open(path, encoding="utf-8") as fh:
                lines = fh.read().splitlines()
        self.assertEqual(lines[0], "run_id lab-20261019T073610Z-abc123")
        self.assertEqual(lines[1], f"{copies[0]['name']} 1")
        self.assertEqual(len(lines), 5)  # run_id + 4 copies
        # every data line is "<name> <variant>"
        for ln in lines[1:]:
            self.assertRegex(ln, r"^\S+ [1-4]$")

    @unittest.skipUnless(os.path.exists(REAL), "compiled canary not built")
    def test_real_binary_has_exactly_one_marker_and_stable_copy1(self):
        with open(REAL, "rb") as fh:
            base = fh.read()
        self.assertEqual(base.count(rs.MAGIC), 1, "exactly one marker slot in the real binary")
        copies = rs.build_variants(base, 4)
        self.assertEqual(copies[0]["sha256"], hashlib.sha256(base).hexdigest())
        self.assertEqual(len({c["sha256"] for c in copies}), 4)


if __name__ == "__main__":
    unittest.main()

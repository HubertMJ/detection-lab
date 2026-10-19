#!/usr/bin/env python3
"""Variant B scenario runner: build the polymorphic copies and really run them on the lab VM.

Unlike variant A (lab/generate.py synthesises Sysmon-shaped events), this does the real thing: it
makes four copies of the compiled lab canary, each with a different 32-byte marker so each has a new
SHA-256 and a new name, drops them under a work dir (``/tmp`` on the VM) and executes them. Running
each copy makes the real kernel actions Sysmon for Linux reports:

  * the exec itself            -> process-create     (event 1)
  * the copy writes a user     -> file-create        (event 11)
    systemd persistence unit
  * the copy beacons N times   -> network-connection (event 3)

Copy 1 keeps the marker all-zero, so it is byte-for-byte the compiled base image and hashes to the
pinned known-hash value. Copies 2..N get a fresh random marker.

The runner does not ship or detect anything. It writes a ground-truth manifest (run id, and per copy
the real name, SHA-256, pid, start time and the persistence path) that Fluent Bit uses to tag the
shipped events with the run id and variant, and that the siem01 validator later lines up against the
real findings. Standard library only.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import secrets
import stat
import subprocess
import time

MAGIC = b"LABCANARYMARK01:"
MARKER_LEN = 32
COPY1_NAME = "update-helper"
HOST = "lab-vm"


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _iso(t: datetime.datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"


def run_id(now: datetime.datetime) -> str:
    return "lab-" + now.strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(3)


def _marker_offset(blob: bytes) -> int:
    """Byte offset of the 32 marker bytes (right after the magic). Fatal if absent or ambiguous."""
    first = blob.find(MAGIC)
    if first < 0:
        raise SystemExit("marker magic not found in the base image; wrong or unbuilt binary")
    if blob.find(MAGIC, first + 1) >= 0:
        raise SystemExit("marker magic found more than once; cannot patch unambiguously")
    return first + len(MAGIC)


def build_variants(base: bytes, count: int):
    """The per-copy facts and bytes: copy 1 keeps the zero marker, copies 2..N get a fresh one."""
    off = _marker_offset(base)
    copies = []
    for n in range(1, count + 1):
        marker = bytes(MARKER_LEN) if n == 1 else secrets.token_bytes(MARKER_LEN)
        img = bytearray(base)
        img[off:off + MARKER_LEN] = marker
        img = bytes(img)
        name = COPY1_NAME if n == 1 else "svc-" + secrets.token_hex(4)
        copies.append({
            "n": n,
            "name": name,
            "sha256": hashlib.sha256(img).hexdigest(),
            "image": img,
        })
    return copies


def _persistence_path(name: str) -> str:
    home = os.environ.get("HOME") or "/root"
    return f"{home}/.config/systemd/user/{name}.service"


def run(base_path: str, workdir: str, sink_ip: str, sink_port: int, beacons: int,
        interval_ms: int, gap_s: int, count: int, rid: str, namemap: str | None = None) -> dict:
    with open(base_path, "rb") as fh:
        base = fh.read()
    copies = build_variants(base, count)
    # Write the name map BEFORE running anything, so Fluent Bit can tag the very first event.
    if namemap:
        write_namemap(namemap, rid, copies)
    os.makedirs(workdir, exist_ok=True)
    variants = []
    for i, c in enumerate(copies):
        path = os.path.join(workdir, c["name"])
        with open(path, "wb") as fh:
            fh.write(c["image"])
        os.chmod(path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
        started = _now()
        proc = subprocess.Popen([path, sink_ip, str(sink_port), str(beacons), str(interval_ms)],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        variants.append({
            "n": c["n"],
            "host": HOST,
            "sha256": c["sha256"],
            "renamed": c["name"],
            "executable": path,
            "pid": proc.pid,
            "started_at": _iso(started),
            "persistence_path": _persistence_path(c["name"]),
            "_proc": proc,
        })
        if i + 1 < len(copies):
            time.sleep(gap_s)
    finished = _now()
    for v in variants:
        v.pop("_proc").wait(timeout=60)
    return {
        "run_id": rid,
        "mode": "isolated-vm",
        "host": HOST,
        "started_at": variants[0]["started_at"] if variants else _iso(finished),
        "finished_at": _iso(_now()),
        "sink": {"ip": sink_ip, "port": sink_port, "beacons": beacons, "interval_ms": interval_ms},
        "variants": variants,
    }


def parse_args(argv=None):
    p = argparse.ArgumentParser(description="run the variant B scenario on the lab VM")
    p.add_argument("--base", default="/opt/lab/lab-canary", help="compiled base image (copy 1)")
    p.add_argument("--workdir", default="/tmp", help="where the copies are written and run")
    p.add_argument("--sink-ip", required=True, help="lab beacon sink address (siem01)")
    p.add_argument("--sink-port", type=int, default=8080)
    p.add_argument("--beacons", type=int, default=6, help="beacons per copy (>=5 for the rule)")
    p.add_argument("--interval-ms", type=int, default=20000, help="ms between beacons")
    p.add_argument("--gap-s", type=int, default=15, help="seconds between copies")
    p.add_argument("--copies", type=int, default=4)
    p.add_argument("--run-id", default=None)
    p.add_argument("--manifest", default="/run/lab/manifest.json",
                   help="ground-truth manifest for the validator")
    p.add_argument("--namemap", default="/run/lab/pidmap",
                   help="run_id + name->variant lines Fluent Bit's mapper reads to tag and filter")
    return p.parse_args(argv)


def write_namemap(path: str, rid: str, copies) -> None:
    """The run id and one ``name variant sha256`` line per copy, for the Fluent Bit Lua mapper (no
    JSON in Lua). Keyed by the copy's file name (not pid) and written BEFORE the copies run, so no
    early event (the exec itself, the file-create) is dropped for want of a pid that is not known
    yet. Only these names' events are shipped, tagged with this run id and variant; the hash goes on
    the network events, which Linux Sysmon logs without one."""
    lines = ["run_id " + rid]
    for c in copies:
        lines.append(f"{c['name']} {c['n']} {c['sha256']}")
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def main(argv=None):
    args = parse_args(argv)
    if args.copies < 1:
        raise SystemExit("--copies must be >= 1")
    rid = args.run_id or run_id(_now())
    doc = run(args.base, args.workdir, args.sink_ip, args.sink_port, args.beacons,
              args.interval_ms, args.gap_s, args.copies, rid, namemap=args.namemap)
    os.makedirs(os.path.dirname(args.manifest) or ".", exist_ok=True)
    with open(args.manifest, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, separators=(",", ":"), sort_keys=True)
    print(f"run {rid}: ran {len(doc['variants'])} copies on {HOST} -> {args.manifest}", flush=True)


if __name__ == "__main__":
    main()

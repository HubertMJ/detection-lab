#!/usr/bin/env python3
"""Generate one run of scenario C as event data plus ground truth (variant A).

Variant A executes nothing. This CLI only writes synthetic, Sysmon-shaped JSON:
a benign marker artefact is "copied" N times so that every copy has a new
SHA-256 and a new file name (polymorphism), and the events each copy would
produce are emitted. Copy 1 is deterministic (a fixed byte blob, constant
SHA-256) so a hash IOC rule can be pinned to it; copies 2..N each get a fresh
random 16-byte marker, hence a new hash and a new randomised name.

Outputs (into --out):
  events.ndjson  one event per line, in the sdp-lab field contract as nested
                 objects (Security Analytics rules match nested documents, not
                 flat dotted keys), ready to bulk-index into OpenSearch.
  run.json       the ground-truth / run document in the LabReplay shape the
                 site consumes, with lab labels only (no real host/user/address)
                 and findings left empty for the validator to fill.

Standard library only (runs on siem01 / Debian, no pip).
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import secrets

SCHEMA = 1

# The fixed base bytes of the harmless marker artefact. Copy 1 appends a zero
# marker (deterministic); copies 2..N append a fresh random 16-byte marker.
BASE_BLOB = b"detection-lab/scenario-c harmless marker artefact v1\n"
COPY1_MARKER = bytes(16)

# A synthetic lab user; never a real account name.
LAB_USER = "labuser"
TEMP_DIR = f"C:\\Users\\{LAB_USER}\\AppData\\Local\\Temp"
RUN_KEY = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
PARENT = "explorer.exe"
COPY1_NAME = "update-helper.exe"

# Beacon offsets (seconds from a copy's first event): 6 connections inside a
# ~5-minute window, so the 5+/10-min beaconing logic is satisfiable.
BEACON_OFFSETS = (5, 65, 125, 185, 245, 305)

# Seconds between one copy's first event and the next copy's. Two copies share a
# host (copy n and copy n+2), so GAP_S must leave two same-host copies apart by
# 2*GAP_S > the per-copy span (max BEACON_OFFSETS), or their beacons would overlap
# on one host. 180 keeps same-host copies 360 s apart (> 305 s span) while packing
# the whole run into a recent window instead of spreading it over half an hour.
GAP_S = 180

SCENARIO = {
    "id": "C",
    "title": "A new hash and a new name for every copy",
    "summary": (
        "A harmless test program, rebuilt and renamed four times so each copy "
        "has a new SHA-256 and a new file name, is run on two lab workstations. "
        "It only writes a Run key and calls a lab-internal address every 60 s."
    ),
}

ARTEFACT = {"name": COPY1_NAME, "path": f"{TEMP_DIR}\\{COPY1_NAME}"}

RISK_THRESHOLD = 100

RULES = [
    {"id": "ioc-update-helper-sha256", "title": "Known-bad hash", "kind": "sigma",
     "technique": "T1204.002", "score": 50,
     "logic": "process.hash.sha256 is the hash from the first sighting"},
    {"id": "run-key-from-temp", "title": "Run key written from a Temp folder", "kind": "sigma",
     "technique": "T1547.001", "score": 20,
     "logic": "a registry Run value set by a process under \\AppData\\Local\\Temp\\"},
    {"id": "same-name-new-hash", "title": "Same name, new hash", "kind": "monitor",
     "technique": "T1027", "score": 30,
     "logic": "one process.name, a SHA-256 not seen for it in 30 days (first-seen per name)"},
    {"id": "lab-beaconing", "title": "Beaconing", "kind": "monitor",
     "technique": "T1071.001", "score": 10,
     "logic": "5+ connections from one process to one address at a steady interval within 10 min"},
]


def copy1_sha256() -> str:
    return hashlib.sha256(BASE_BLOB + COPY1_MARKER).hexdigest()


def _ts(base: datetime.datetime, offset_s: float) -> str:
    t = base + datetime.timedelta(seconds=offset_s)
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"


def _run_id(now: datetime.datetime) -> str:
    return "lab-" + now.strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(3)


def timeline_span_s(count: int) -> int:
    """Seconds from the first copy's first event to the last copy's last event:
    (count-1) gaps plus one copy's own span. Used to anchor the default timeline so
    it ends at generation time, never in the future."""
    return max(0, count - 1) * GAP_S + max(BEACON_OFFSETS)


def _random_name() -> str:
    return "svc-" + secrets.token_hex(4) + ".exe"


def _value_name(proc_name: str) -> str:
    return proc_name[:-4] if proc_name.endswith(".exe") else proc_name


def build_copies(count: int, hosts: list[str]):
    """Return the per-copy facts (ground truth): hash, name, host, variant n."""
    copies = []
    for n in range(1, count + 1):
        if n == 1:
            blob = BASE_BLOB + COPY1_MARKER
            name = COPY1_NAME
        else:
            blob = BASE_BLOB + secrets.token_bytes(16)
            name = _random_name()
        copies.append({
            "n": n,
            "host": hosts[(n - 1) % len(hosts)],
            "name": name,
            "sha256": hashlib.sha256(blob).hexdigest(),
            "pid": 1000 + n * 7,
        })
    return copies


def copy_events(copy, start: datetime.datetime, run_id: str, mode: str,
                beacon_ip: str, beacon_port: int):
    """The sdp-lab events for one copy (process-create, registry-value-set, beacons)."""
    name = copy["name"]
    exe = f"{TEMP_DIR}\\{name}"
    sha = copy["sha256"]
    host = copy["host"]
    pid = copy["pid"]
    common = {
        "event.kind": "event",
        "event.dataset": "lab",
        "lab.run_id": run_id,
        "lab.mode": mode,
        "lab.variant": copy["n"],
        "host.name": host,
        "process.pid": pid,
        "process.name": name,
    }
    events = []
    events.append({
        "@timestamp": _ts(start, 0), "event.code": "1", "event.action": "process-create",
        **common, "process.executable": exe, "process.hash.sha256": sha,
        "process.parent.name": PARENT,
    })
    events.append({
        "@timestamp": _ts(start, 2), "event.code": "13", "event.action": "registry-value-set",
        **common, "process.executable": exe,
        "registry.path": f"{RUN_KEY}\\{_value_name(name)}",
    })
    for off in BEACON_OFFSETS:
        events.append({
            "@timestamp": _ts(start, off), "event.code": "3", "event.action": "network-connection",
            **common, "process.hash.sha256": sha,
            "destination.ip": beacon_ip, "destination.port": beacon_port,
        })
    return events


def run_variant(copy, events, beacon_label: str):
    """A LabReplay variant (lab labels only, findings empty) for run.json."""
    host_label = "ws1" if copy["host"].startswith("ws1") else "ws2"
    first_ts = events[0]["@timestamp"]
    techniques = ["T1204.002", "T1547.001", "T1071.001"]
    if copy["n"] > 1:
        techniques.append("T1027")
    san = []
    for e in events:
        ev = {"@timestamp": e["@timestamp"], "event.code": e["event.code"],
              "event.action": e["event.action"], "host.name": host_label,
              "process.name": e["process.name"]}
        if "process.executable" in e:
            ev["process.executable"] = e["process.executable"]
        if "process.hash.sha256" in e:
            ev["process.hash.sha256"] = e["process.hash.sha256"]
        if "process.parent.name" in e:
            ev["process.parent.name"] = e["process.parent.name"]
        if "registry.path" in e:
            ev["registry.path"] = e["registry.path"]
        if "destination.port" in e:
            ev["destination.ip"] = beacon_label
            ev["destination.port"] = e["destination.port"]
        san.append(ev)
    return {
        "n": copy["n"],
        "host": host_label,
        "sha256": copy["sha256"],
        "renamed": copy["name"],
        "events": san,
        "ground_truth": {"@timestamp": first_ts, "host": host_label,
                         "techniques": techniques, "variant_sha256": copy["sha256"]},
        "findings": [],
        "caught_by_hash": False,
    }


def generate(count, hosts, beacon_ip, beacon_port, start, run_id, mode):
    copies = build_copies(count, hosts)
    beacon_label = f"lab beacon :{beacon_port}"
    all_events = []
    variants = []
    for i, copy in enumerate(copies):
        c_start = start + datetime.timedelta(seconds=i * GAP_S)
        events = copy_events(copy, c_start, run_id, mode, beacon_ip, beacon_port)
        all_events.extend(events)
        variants.append(run_variant(copy, events, beacon_label))
    all_events.sort(key=lambda e: e["@timestamp"])
    started_at = all_events[0]["@timestamp"]
    finished_at = all_events[-1]["@timestamp"]
    run_doc = {
        "schema": SCHEMA,
        "sample": False,
        "run": {"id": run_id, "mode": mode, "started_at": started_at, "finished_at": finished_at},
        "scenario": SCENARIO,
        "artefact": ARTEFACT,
        "beacon": beacon_label,
        "risk_threshold": RISK_THRESHOLD,
        "rules": RULES,
        "variants": variants,
    }
    return all_events, run_doc


def nest(event):
    """Flat dotted keys -> nested objects (Security Analytics only matches nested docs).

    "@timestamp" stays a top-level key.
    """
    out = {}
    for key, value in event.items():
        if key == "@timestamp":
            out[key] = value
            continue
        node = out
        parts = key.split(".")
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        node[parts[-1]] = value
    return out


def parse_args(argv):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--copies", type=int, default=4)
    p.add_argument("--hosts", default="ws1.lab.local,ws2.lab.local")
    p.add_argument("--beacon-ip", default="198.51.100.10",
                   help="synthetic lab beacon address (RFC 5737 TEST-NET-2)")
    p.add_argument("--beacon-port", type=int, default=8080)
    p.add_argument("--start", default=None, help="ISO-8601 UTC start timestamp (default: now)")
    p.add_argument("--out", required=True, help="output directory")
    p.add_argument("--run-id", default=None)
    p.add_argument("--mode", default="generated", choices=["generated"])
    p.add_argument("--copy1-hash-out", default=None,
                   help="also write copy 1's SHA-256 (one hex line) to this path")
    return p.parse_args(argv)


def main(argv):
    args = parse_args(argv)
    if args.copies < 1:
        raise SystemExit("--copies must be >= 1")
    hosts = [h.strip() for h in args.hosts.split(",") if h.strip()]
    if not hosts:
        raise SystemExit("--hosts must list at least one host")
    now = datetime.datetime.now(datetime.timezone.utc)
    if args.start:
        start = datetime.datetime.fromisoformat(args.start.replace("Z", "+00:00"))
        if start.tzinfo is None:
            start = start.replace(tzinfo=datetime.timezone.utc)
    else:
        # Anchor the run to END at `now`, not start at it: the four copies are
        # indexed moments after they are generated and the detector runs later
        # still, so a timeline that began at `now` would leave later copies dated
        # in the future and every finding/incident delay (detection time minus
        # event time) negative. Starting span seconds in the past puts the last
        # event at `now`, so all events are in the recent past and all delays >= 0.
        start = now.replace(microsecond=0) - datetime.timedelta(
            seconds=timeline_span_s(args.copies))
    run_id = args.run_id or _run_id(now)
    events, run_doc = generate(args.copies, hosts, args.beacon_ip, args.beacon_port,
                               start, run_id, args.mode)

    os.makedirs(args.out, exist_ok=True)
    nd_path = os.path.join(args.out, "events.ndjson")
    with open(nd_path, "w", encoding="utf-8") as fh:
        for e in events:
            fh.write(json.dumps(nest(e), separators=(",", ":"), sort_keys=True))
            fh.write("\n")
    run_path = os.path.join(args.out, "run.json")
    run_bytes = json.dumps(run_doc, indent=2).encode("utf-8")
    if len(run_bytes) > 64 * 1024:
        raise SystemExit(f"run.json is {len(run_bytes)} bytes, over the 64 KiB cap")
    with open(run_path, "wb") as fh:
        fh.write(run_bytes)

    if args.copy1_hash_out:
        with open(args.copy1_hash_out, "w", encoding="utf-8") as fh:
            fh.write(copy1_sha256() + "\n")

    print(f"run_id {run_id}")
    print(f"copy1_sha256 {copy1_sha256()}")
    print(f"events {len(events)} -> {nd_path}")
    print(f"run.json {len(run_bytes)} bytes -> {run_path}")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main(sys.argv[1:]))

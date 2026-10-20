#!/usr/bin/env python3
"""Turn one real isolated-VM run (variant B) into its run document.

Variant A's runner generates the events, so it already holds the run document; variant B's events
were made by a real VM and shipped by its Fluent Bit, so this module rebuilds the document from
what siem01 holds: the run's sdp-lab documents (Sysmon events per copy and the lifecycle markers),
the Security Analytics findings of sdp-lab-rules and the alerts of the lab monitor. It then reuses
validate.validate (delays, caught_by_hash, incident, ATT&CK coverage) and adds what only B has:
the lifecycle timeline, run-level counters, per-copy pid/ppid and every offset from the rollback.

Never emits a real address: destination.ip becomes the lab label "lab beacon :<port>", as variant
A's run document does, and the result passes validate._assert_no_leak before it is published.

The pure part (build_run_doc) takes no I/O and is tested offline; run.py --mode isolated-vm drives
the I/O (fetch, wait, publish). Standard library only.
"""

from __future__ import annotations

import datetime
import json

import validate

SCHEMA = 1
HOST = "lab-vm"
SCENARIO = {
    "id": "C",
    "title": "A new hash and a new name for every copy",
    "summary": ("A harmless test program, rebuilt so each copy has a new SHA-256 and renamed four "
                "times, runs on a real isolated VM. Each copy writes a systemd user persistence unit "
                "from /tmp and beacons to a lab-internal address."),
}
ARTEFACT = {"name": "update-helper", "path": "/tmp/update-helper"}
RISK_THRESHOLD = 100
# The rules that can see a variant B run, as siem/ in self-defending-portfolio defines them. The
# technique is how a Security Analytics finding maps back to its rule (its first attack.tNNNN tag).
RULES = [
    {"id": "ioc-lab-known-hash", "title": "Known-bad hash", "kind": "sigma",
     "technique": "T1204.002", "score": 50,
     "logic": "process.hash.sha256 is a hash on the indicator list (copy 1)"},
    {"id": "lab-persistence-user-unit-from-tmp", "title": "Persistence unit from /tmp", "kind": "sigma",
     "technique": "T1543.002", "score": 20,
     "logic": "a systemd user unit or crontab written by a process under /tmp"},
    {"id": "lab-polymorphic-beacon", "title": "One beacon, many binaries", "kind": "monitor",
     "technique": "T1071.001", "score": 30,
     "logic": "two or more distinct SHA-256 calling one address within 15 min"},
]
LIFECYCLE_LABELS = {
    "rollback": "Reverted to clean snapshot",
    "start": "VM started",
    "booted": "Booted",
    "sysmon_up": "Sysmon started",
    "shipper_up": "Fluent Bit started",
    "run_start": "Scenario started",
    "drained": "All events shipped to siem01",
    "poweroff_requested": "Powered off",
}
LIFECYCLE_ORDER = list(LIFECYCLE_LABELS)
# The flat event keys a run document keeps (the sdp-lab fields the page shows, nothing else).
EVENT_KEYS = ("@timestamp", "event.code", "event.action", "host.name", "process.name",
              "process.executable", "process.hash.sha256", "process.pid", "process.parent.pid",
              "process.parent.name", "file.path", "destination.port")


def flatten(doc: dict, prefix: str = "") -> dict:
    """Nested sdp-lab _source -> flat dotted keys ("@timestamp" stays as is)."""
    out: dict = {}
    for key, value in doc.items():
        name = f"{prefix}{key}"
        if isinstance(value, dict):
            out.update(flatten(value, name + "."))
        else:
            out[name] = value
    return out


def _parse(ts: str) -> datetime.datetime:
    return validate._parse(ts)


def _iso(t: datetime.datetime) -> str:
    return t.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + \
        f"{t.microsecond // 1000:03d}Z"


def _offset(t0: datetime.datetime, ts: str) -> int:
    return max(0, round((_parse(ts) - t0).total_seconds()))


def _techniques(n: int) -> list[str]:
    # Every copy runs, persists and beacons; copies 2..N also carry a new hash (T1027, obfuscation).
    base = ["T1204.002", "T1543.002", "T1071.001"]
    return base if n == 1 else base + ["T1027"]


def split_docs(docs: list[dict]) -> tuple[dict[str, str], list[dict]]:
    """The run's sdp-lab documents -> ({marker: @timestamp}, [flat Sysmon events]).

    A marker document has event.action lifecycle and no event.code; the first of each marker wins
    (a marker shipped twice must not move the timeline)."""
    markers: dict[str, str] = {}
    events: list[dict] = []
    for doc in docs:
        flat = flatten(doc)
        if flat.get("event.action") == "lifecycle":
            m = flat.get("lab.marker")
            if m and m not in markers:
                markers[m] = flat["@timestamp"]
        elif flat.get("event.code") is not None:
            events.append(flat)
    events.sort(key=lambda e: _parse(e["@timestamp"]))
    return markers, events


def build_run_doc(run_id: str, docs: list[dict], beacon_port: int = 8080) -> dict:
    """A variant B run's documents -> the run document with findings still empty.

    t0 is the rollback marker (the run's zero); without it (a boot outside the timer) the earliest
    marker or event stands in, so every offset is still >= 0."""
    markers, events = split_docs(docs)
    if not events:
        raise SystemExit(f"run {run_id}: no Sysmon events in sdp-lab")
    stamps = list(markers.values()) + [e["@timestamp"] for e in events]
    t0 = _parse(markers["rollback"]) if "rollback" in markers else min(_parse(s) for s in stamps)
    end_ts = markers.get("poweroff_requested") or max(stamps, key=_parse)

    beacon_label = f"lab beacon :{beacon_port}"
    by_variant: dict[int, list[dict]] = {}
    for e in events:
        n = e.get("lab.variant")
        if isinstance(n, (int, float)) and int(n) >= 1:
            by_variant.setdefault(int(n), []).append(e)
    if not by_variant:
        raise SystemExit(f"run {run_id}: no event carries lab.variant")

    variants = []
    for n in sorted(by_variant):
        evs = by_variant[n]
        create = next((e for e in evs if str(e.get("event.code")) == "1"), None)
        sha = (create or {}).get("process.hash.sha256") or next(
            (e["process.hash.sha256"] for e in evs if e.get("process.hash.sha256")), "")
        name = (create or evs[0]).get("process.name", "")
        out_events = []
        for e in evs:
            ev = {k: e[k] for k in EVENT_KEYS if k in e}
            ev["host.name"] = HOST
            ev["event.code"] = str(e["event.code"])
            ev["offset_s"] = _offset(t0, e["@timestamp"])
            if str(e["event.code"]) == "3":
                ev["destination.ip"] = beacon_label
            out_events.append(ev)
        v = {
            "n": n, "host": HOST, "sha256": sha, "renamed": name,
            "events": out_events,
            "ground_truth": {"@timestamp": out_events[0]["@timestamp"], "host": HOST,
                             "techniques": _techniques(n), "variant_sha256": sha},
            "findings": [], "caught_by_hash": False,
        }
        if create and create.get("process.pid") is not None:
            v["pid"] = int(create["process.pid"])
        if create and create.get("process.parent.pid") is not None:
            v["ppid"] = int(create["process.parent.pid"])
        variants.append(v)
    # The page and validate.py expect copies numbered 1..N in order.
    for i, v in enumerate(variants, start=1):
        if v["n"] != i:
            raise SystemExit(f"run {run_id}: copies are not numbered 1..N ({[x['n'] for x in variants]})")

    # In time order (sysmon and the shipper start in parallel); the canonical order breaks ties.
    lifecycle = sorted(({"marker": m, "offset_s": _offset(t0, markers[m]), "label": LIFECYCLE_LABELS[m]}
                        for m in LIFECYCLE_ORDER if m in markers),
                       key=lambda x: (x["offset_s"], LIFECYCLE_ORDER.index(x["marker"])))
    started = markers.get("rollback") or _iso(t0)
    return {
        "schema": SCHEMA,
        "sample": False,
        "run": {"id": run_id, "mode": "isolated-vm", "started_at": started, "finished_at": end_ts,
                "duration_s": _offset(t0, end_ts)},
        "scenario": SCENARIO,
        "artefact": ARTEFACT,
        "beacon": beacon_label,
        "risk_threshold": RISK_THRESHOLD,
        "rules": RULES,
        "variants": variants,
        "lifecycle": lifecycle,
    }


def finish(run_doc: dict, raw_findings: dict, raw_alerts: dict) -> dict:
    """Fold the real findings and alerts in (validate.validate), then add the B-only offsets and
    the run-level counters. The alerts must already be this run's (run.py filters by time)."""
    findings = validate.parse_sa(raw_findings, raw_alerts, run_doc)
    final = validate.validate(run_doc, findings)
    for v in final["variants"]:
        first = v["events"][0]["offset_s"]
        for f in v["findings"]:
            f["at_offset_s"] = first + f["delay_s"]
    inc = final.get("incident") or {}
    if inc.get("opened_at_variant") is not None:
        v = next(x for x in final["variants"] if x["n"] == inc["opened_at_variant"])
        inc["at_offset_s"] = v["events"][0]["offset_s"] + inc["delay_s"]
    final["counters"] = {
        "processes": len(final["variants"]),
        "unique_hashes": len({v["sha256"] for v in final["variants"]}),
        "events": sum(len(v["events"]) for v in final["variants"]),
        "findings": sum(len(v["findings"]) for v in final["variants"]),
        "incidents": 1 if inc.get("opened_at_variant") is not None else 0,
    }
    out = json.dumps(final, separators=(",", ":")).encode("utf-8")
    if len(out) > 64 * 1024:
        raise SystemExit(f"run document is {len(out)} bytes, over the 64 KiB cap")
    validate._assert_no_leak(out)
    return final

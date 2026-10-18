#!/usr/bin/env python3
"""Turn a generated run plus real SIEM detections into the final run document.

Reads run.json (from generate.py, findings empty) and a findings file (the real
Security Analytics findings of detector sdp-lab-rules and the alerts of the lab
monitor, as produced by the SIEM step or a small siem-client). Computes, per
copy: caught_by_hash and each finding's delay_s (seconds from the copy's first
event to the finding/alert time); the incident {opened_at_variant, delay_s,
key}; and ATT&CK coverage (expected vs detected). Writes the final run document
in the exact LabReplay shape the site consumes.

Findings file shape (JSON), all timestamps ISO-8601 UTC:
  {
    "detections": [ {"rule": "<rule id>", "variant": <n>, "at": "<ts>",
                     "only": "same-name"?} , ... ],
    "incident":   {"variant": <n>, "at": "<ts>"} | null
  }

Never emits real host names, addresses or user names: it passes through only
the lab labels already in run.json.

Standard library only.
"""

from __future__ import annotations

import argparse
import datetime
import json
import re
import sys

IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


def _parse(ts: str) -> datetime.datetime:
    t = datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))
    return t if t.tzinfo else t.replace(tzinfo=datetime.timezone.utc)


def _delay_s(first_ts: str, at: str) -> int:
    return round((_parse(at) - _parse(first_ts)).total_seconds())


def validate(run_doc: dict, findings: dict) -> dict:
    tech_of = {r["id"]: r["technique"] for r in run_doc["rules"]}
    rule_ids = set(tech_of)
    by_variant: dict[int, list] = {}
    for d in findings.get("detections", []):
        if d["rule"] not in rule_ids:
            raise SystemExit(f"detection references unknown rule {d['rule']}")
        by_variant.setdefault(d["variant"], []).append(d)

    detected_rules: set[str] = set()
    for variant in run_doc["variants"]:
        n = variant["n"]
        first_ts = variant["events"][0]["@timestamp"]
        out_findings = []
        caught_by_hash = False
        for d in sorted(by_variant.get(n, []), key=lambda x: _parse(x["at"])):
            f = {"rule": d["rule"], "delay_s": _delay_s(first_ts, d["at"])}
            if d.get("only") == "same-name":
                f["only"] = "same-name"
            out_findings.append(f)
            detected_rules.add(d["rule"])
            if d["rule"].startswith("ioc-"):
                caught_by_hash = True
        variant["findings"] = out_findings
        variant["caught_by_hash"] = caught_by_hash

    inc = findings.get("incident")
    if inc:
        v = next(x for x in run_doc["variants"] if x["n"] == inc["variant"])
        run_doc["incident"] = {
            "opened_at_variant": inc["variant"],
            "delay_s": _delay_s(v["events"][0]["@timestamp"], inc["at"]),
            "key": "beacon",
        }
    else:
        run_doc["incident"] = {"opened_at_variant": None, "delay_s": None, "key": "beacon"}

    expected = sorted({t for v in run_doc["variants"] for t in v["ground_truth"]["techniques"]})
    detected = sorted({tech_of[r] for r in detected_rules})
    run_doc["techniques"] = {"expected": expected, "detected": detected}
    return run_doc


def _assert_no_leak(data: bytes) -> None:
    text = data.decode("utf-8")
    if ".lab.local" in text:
        raise SystemExit("final run document leaks a real-style host name (.lab.local)")
    for m in IPV4.findall(text):
        raise SystemExit(f"final run document leaks an address: {m}")


def parse_args(argv):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--run", required=True, help="run.json from generate.py")
    p.add_argument("--findings", required=True, help="findings JSON (real SIEM detections)")
    p.add_argument("--out", required=True, help="path to write the final run document")
    return p.parse_args(argv)


def main(argv):
    args = parse_args(argv)
    with open(args.run, encoding="utf-8") as fh:
        run_doc = json.load(fh)
    with open(args.findings, encoding="utf-8") as fh:
        findings = json.load(fh)
    final = validate(run_doc, findings)
    out_bytes = json.dumps(final, indent=2).encode("utf-8")
    if len(out_bytes) > 64 * 1024:
        raise SystemExit(f"final run document is {len(out_bytes)} bytes, over the 64 KiB cap")
    _assert_no_leak(out_bytes)
    with open(args.out, "wb") as fh:
        fh.write(out_bytes)
    caught = sum(1 for v in final["variants"] if v["caught_by_hash"])
    inc = final["incident"]["opened_at_variant"]
    print(f"hash caught {caught}/{len(final['variants'])}; "
          f"incident at variant {inc}; {len(out_bytes)} bytes -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

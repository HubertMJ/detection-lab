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


def _iso_from_epoch_ms(ms: int) -> str:
    """OpenSearch reports finding/alert times as epoch milliseconds; make them ISO-8601 UTC."""
    return datetime.datetime.fromtimestamp(ms / 1000, tz=datetime.timezone.utc).isoformat()


_ATTACK_TAG = re.compile(r"^attack\.t(\d+(?:\.\d+)?)$", re.IGNORECASE)


def _technique_from_tags(tags) -> str | None:
    """The ATT&CK technique a Security Analytics query carries in its tags (attack.t1547.001 -> T1547.001)."""
    for tag in tags or []:
        m = _ATTACK_TAG.match(str(tag))
        if m:
            return "T" + m.group(1)
    return None


def parse_sa_findings(raw_findings: dict, run_doc: dict) -> list[dict]:
    """Real Security Analytics findings -> validator detections, for this run only.

    Each finding carries the matched document (with lab.variant and lab.run_id)
    and the detector query's ATT&CK tags. A finding counts only when its document
    belongs to this run and its technique maps to one of the run's rules (so a
    finding for an out-of-run variant, e.g. an isolated-VM copy, is ignored). The
    detector run time (the finding's `timestamp`, epoch ms) is the detection time.
    """
    tech_to_rule = {r["technique"]: r["id"] for r in run_doc["rules"]}
    run_id = run_doc["run"]["id"]
    variant_ns = {v["n"] for v in run_doc["variants"]}
    detections = []
    for finding in raw_findings.get("findings", []):
        docs = finding.get("document_list") or []
        if not docs:
            continue
        doc = json.loads(docs[0]["document"])
        lab = doc.get("lab", {})
        variant = lab.get("variant")
        if lab.get("run_id") != run_id or variant not in variant_ns:
            continue
        queries = finding.get("queries") or [{}]
        rule = tech_to_rule.get(_technique_from_tags(queries[0].get("tags")))
        if rule is None:
            continue
        detections.append({"rule": rule, "variant": variant,
                           "at": _iso_from_epoch_ms(finding["timestamp"])})
    return detections


def _beacon_rule_id(run_doc: dict) -> str | None:
    for r in run_doc["rules"]:
        if r.get("kind") == "monitor" and "beacon" in r["id"]:
            return r["id"]
    return None


def _incident_variant(run_doc: dict, threshold: int = 2) -> int | None:
    """The copy whose beacon brings the count of distinct beaconing hashes to the
    monitor's threshold: the bucket-level polymorphic-beacon alert opens there."""
    seen: set[str] = set()
    for v in sorted(run_doc["variants"], key=lambda x: x["n"]):
        if any(str(e.get("event.code")) == "3" for e in v["events"]):
            seen.add(v["sha256"])
            if len(seen) >= threshold:
                return v["n"]
    return None


def parse_alerts(raw_alerts: dict, run_doc: dict) -> tuple[list[dict], dict | None]:
    """The Alerting bucket-level alert -> (beacon detections, incident).

    One alert per beacon address is one incident, keyed by behaviour. It opens at
    the copy that first makes two distinct hashes beacon to that address; the
    alert's start_time (epoch ms) is the detection time. The address carried in
    the alert bucket is never copied into the output (lab labels only)."""
    alerts = raw_alerts.get("alerts") or []
    if not alerts:
        return [], None
    alert = min(alerts, key=lambda a: a.get("start_time", 0))
    variant = _incident_variant(run_doc)
    if variant is None:
        return [], None
    at = _iso_from_epoch_ms(alert["start_time"])
    detections = []
    beacon_rule = _beacon_rule_id(run_doc)
    if beacon_rule is not None:
        detections.append({"rule": beacon_rule, "variant": variant, "at": at})
    return detections, {"variant": variant, "at": at}


def parse_sa(raw_findings: dict, raw_alerts: dict, run_doc: dict) -> dict:
    """Real SA findings + Alerting alerts -> the findings dict validate() consumes."""
    detections = parse_sa_findings(raw_findings, run_doc)
    beacon_detections, incident = parse_alerts(raw_alerts, run_doc)
    detections.extend(beacon_detections)
    return {"detections": detections, "incident": incident}


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
    p.add_argument("--findings", help="pre-parsed findings JSON (detections + incident)")
    p.add_argument("--raw-findings",
                   help="raw OpenSearch Security Analytics findings response JSON")
    p.add_argument("--raw-alerts",
                   help="raw OpenSearch Alerting alerts response JSON")
    p.add_argument("--out", required=True, help="path to write the final run document")
    return p.parse_args(argv)


def load_findings(args, run_doc: dict) -> dict:
    """The detections + incident, either pre-parsed (--findings) or parsed from the
    raw OpenSearch responses (--raw-findings and --raw-alerts)."""
    if args.findings:
        with open(args.findings, encoding="utf-8") as fh:
            return json.load(fh)
    if args.raw_findings and args.raw_alerts:
        with open(args.raw_findings, encoding="utf-8") as fh:
            raw_findings = json.load(fh)
        with open(args.raw_alerts, encoding="utf-8") as fh:
            raw_alerts = json.load(fh)
        return parse_sa(raw_findings, raw_alerts, run_doc)
    raise SystemExit("need --findings, or both --raw-findings and --raw-alerts")


def main(argv):
    args = parse_args(argv)
    with open(args.run, encoding="utf-8") as fh:
        run_doc = json.load(fh)
    findings = load_findings(args, run_doc)
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

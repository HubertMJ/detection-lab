#!/usr/bin/env python3
"""Ship one lifecycle marker to siem01, the moment it happens (variant B).

The VM's run has stages the /lab/ page shows as a live console and that drive the "LIVE" state while a
run is in flight: rollback, start, booted, sysmon_up, shipper_up, run_start, drained,
poweroff_requested. Sysmon does not emit these, so run-and-ship.sh posts one sdp-lab document per
marker, as it reaches it, straight to siem01 over mTLS with the lab-vm-shipper certificate (not through
Fluent Bit, so the API sees progress immediately).

A marker document carries NO event.code, so none of the detector's rules (which require event.code
1/3/11) ever match it; it is pure timeline. All offsets are seconds from the run's t0 (the rollback
marker). Host is masked to lab-vm. Standard library only.
"""

from __future__ import annotations

import argparse
import datetime
import json
import ssl
import sys
from urllib.parse import urlsplit

MARKERS = ("rollback", "start", "booted", "sysmon_up", "shipper_up", "run_start",
           "drained", "poweroff_requested")
HOST = "lab-vm"


def build_marker_doc(run_id: str, marker: str, offset_s: int, ts_iso: str) -> dict:
    """The sdp-lab lifecycle document. No event.code on purpose, so no rule matches it."""
    if marker not in MARKERS:
        raise ValueError(f"unknown marker {marker!r}")
    return {
        "@timestamp": ts_iso,
        "event.kind": "event",
        "event.dataset": "lab",
        "event.action": "lifecycle",
        "lab.run_id": run_id,
        "lab.mode": "isolated-vm",
        "lab.marker": marker,
        "lab.offset_s": int(offset_s),
        "host.name": HOST,
    }


def nest(doc: dict) -> dict:
    """Flat dotted keys -> nested objects, as the Lua mapper and variant A's indexer ship them
    ("@timestamp" stays top level)."""
    out: dict = {}
    for key, value in doc.items():
        if key == "@timestamp":
            out[key] = value
            continue
        node = out
        parts = key.split(".")
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        node[parts[-1]] = value
    return out


def _ssl_ctx(cert: str, key: str, cacert: str) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=cacert)
    ctx.load_cert_chain(cert, key)
    return ctx


def ship(endpoint: str, stream: str, doc: dict, cert: str, key: str, cacert: str) -> int:
    import http.client
    u = urlsplit(endpoint)
    conn = http.client.HTTPSConnection(u.hostname, u.port or 9200,
                                       context=_ssl_ctx(cert, key, cacert), timeout=15)
    try:
        body = json.dumps(nest(doc), separators=(",", ":")).encode("utf-8")
        # create a fresh document (append-only, like Fluent Bit's Write_Operation create).
        conn.request("POST", f"/{stream}/_doc", body=body,
                     headers={"Content-Type": "application/json"})
        resp = conn.getresponse()
        payload = resp.read()
        if resp.status >= 300:
            print(f"marker {doc['lab.marker']} failed: HTTP {resp.status} "
                  f"{payload.decode('utf-8', 'replace')}", file=sys.stderr)
            return 1
        return 0
    finally:
        conn.close()


def _now_iso() -> str:
    t = datetime.datetime.now(datetime.timezone.utc)
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"


def main(argv=None):
    p = argparse.ArgumentParser(description="ship one lifecycle marker to siem01")
    p.add_argument("--run-id", required=True)
    p.add_argument("--marker", required=True, choices=MARKERS)
    p.add_argument("--offset-s", type=int, required=True)
    p.add_argument("--timestamp", default=None, help="ISO8601 UTC; default now")
    p.add_argument("--endpoint", default="https://10.4.2.10:9200")
    p.add_argument("--stream", default="sdp-lab")
    p.add_argument("--client-cert", default="/etc/lab/siem/tls.crt")
    p.add_argument("--client-key", default="/etc/lab/siem/tls.key")
    p.add_argument("--cacert", default="/etc/lab/siem/ca.crt")
    p.add_argument("--print", dest="print_only", action="store_true",
                   help="print the document and do not ship (for testing)")
    args = p.parse_args(argv)
    doc = build_marker_doc(args.run_id, args.marker, args.offset_s, args.timestamp or _now_iso())
    if args.print_only:
        print(json.dumps(doc, separators=(",", ":"), sort_keys=True))
        return 0
    return ship(args.endpoint, args.stream, doc, args.client_cert, args.client_key, args.cacert)


if __name__ == "__main__":
    raise SystemExit(main())

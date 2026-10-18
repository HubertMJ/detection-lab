#!/usr/bin/env python3
"""Drive one real detection-lab run end to end (variant A).

Chains the whole run that a cluster CronJob invokes:

  1. generate  - synthetic sdp-lab events + the run document (reuse generate.py);
  2. index     - bulk-index the events into the sdp-lab data stream over mutual
                 TLS with the lab-writer identity (reuse indexer.py);
  3. poll       - poll Security Analytics findings (of the lab detector) and
                 Alerting alerts (of the lab monitor) for this run, by lab.run_id
                 and a time window, until the detector and the monitor have both
                 fired or a timeout elapses;
  4. validate  - parse the real findings/alerts and compare them with the ground
                 truth (reuse validate.py), producing the final run document;
  5. publish   - index that run document into the lab-runs index over mutual TLS
                 with the lab-validator identity (a small bulk of one document).

Every endpoint, index, detector/monitor id and certificate comes from CLI
arguments or the environment: there are no defaults for them and no secrets in
this file. It exits non-zero on any failure, and re-running it is idempotent-ish
(a fresh run_id each time unless one is pinned; the latest run document wins by
run.finished_at). Standard library only, so the container image stays tiny.
"""

from __future__ import annotations

import argparse
import datetime
import http.client
import json
import os
import ssl
import sys
import time
from urllib.parse import urlsplit

import generate
import indexer
import validate

# OpenSearch plugin API paths are protocol constants, not configuration.
FINDINGS_PATH = "/_plugins/_security_analytics/findings/_search"
ALERTS_PATH = "/_plugins/_alerting/monitors/alerts"


def _ssl_context(certfile: str, keyfile: str, cafile: str | None) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=cafile) if cafile else ssl.create_default_context()
    if cafile is None:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
    return ctx


def https(method: str, endpoint: str, path: str, ctx: ssl.SSLContext,
          body: bytes | None = None, headers: dict | None = None) -> tuple[int, bytes]:
    url = urlsplit(endpoint)
    if url.scheme != "https":
        raise SystemExit("endpoint must be https")
    conn = http.client.HTTPSConnection(url.hostname, url.port or 443, context=ctx, timeout=30)
    try:
        conn.request(method, path, body=body, headers=headers or {})
        resp = conn.getresponse()
        return resp.status, resp.read()
    finally:
        conn.close()


def _get_json(endpoint: str, path: str, ctx: ssl.SSLContext) -> dict:
    status, payload = https("GET", endpoint, path, ctx)
    if status >= 300:
        raise SystemExit(f"GET {path} failed: HTTP {status} {payload.decode('utf-8', 'replace')}")
    return json.loads(payload)


def _run_findings(raw_findings: dict, run_id: str) -> list:
    """The raw findings whose matched document belongs to this run."""
    out = []
    for finding in raw_findings.get("findings", []):
        docs = finding.get("document_list") or []
        if docs and json.loads(docs[0]["document"]).get("lab", {}).get("run_id") == run_id:
            out.append(finding)
    return out


def poll(endpoint: str, ctx: ssl.SSLContext, detector_id: str, monitor_id: str,
         run_id: str, timeout_s: int, interval_s: int) -> tuple[dict, dict]:
    """Poll findings and alerts until the detector and the monitor have both fired
    for this run, or the timeout elapses. Returns the raw responses."""
    findings_path = f"{FINDINGS_PATH}?detectorId={detector_id}&size=10000"
    alerts_path = f"{ALERTS_PATH}?monitorId={monitor_id}&size=200"
    deadline = time.monotonic() + timeout_s
    raw_findings: dict = {"findings": []}
    raw_alerts: dict = {"alerts": []}
    while True:
        raw_findings = _get_json(endpoint, findings_path, ctx)
        raw_alerts = _get_json(endpoint, alerts_path, ctx)
        have_findings = bool(_run_findings(raw_findings, run_id))
        have_alert = bool(raw_alerts.get("alerts"))
        if have_findings and have_alert:
            return raw_findings, raw_alerts
        if time.monotonic() >= deadline:
            raise SystemExit(
                f"timed out after {timeout_s}s waiting for detections "
                f"(findings={have_findings}, alert={have_alert}) for run {run_id}")
        time.sleep(interval_s)


def publish_run_doc(endpoint: str, index: str, run_doc: dict,
                    ctx: ssl.SSLContext) -> None:
    """Index the final run document into the lab-runs index (one document)."""
    body = (json.dumps({"index": {"_index": index}}, separators=(",", ":")) + "\n"
            + json.dumps(run_doc, separators=(",", ":")) + "\n").encode("utf-8")
    status, payload = https("POST", endpoint, "/_bulk", ctx, body=body,
                            headers={"Content-Type": "application/x-ndjson"})
    if status >= 300:
        raise SystemExit(f"publish failed: HTTP {status} {payload.decode('utf-8', 'replace')}")
    result = json.loads(payload)
    if result.get("errors"):
        raise SystemExit(f"publish reported errors: {payload.decode('utf-8', 'replace')}")


def _env_arg(p, flag: str, env: str, *, help: str, required: bool = True) -> None:
    """A flag that falls back to an environment variable. Nothing is baked in."""
    default = os.environ.get(env)
    p.add_argument(flag, default=default,
                   help=f"{help} (env {env})" + ("" if required else " [optional]"))


def parse_args(argv):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    _env_arg(p, "--endpoint", "LAB_ENDPOINT", help="https://host:port of OpenSearch")
    _env_arg(p, "--stream", "LAB_STREAM", help="events data stream, e.g. sdp-lab")
    _env_arg(p, "--runs-index", "LAB_RUNS_INDEX", help="index for the run document, e.g. lab-runs")
    _env_arg(p, "--detector-id", "LAB_DETECTOR_ID", help="Security Analytics detector id")
    _env_arg(p, "--monitor-id", "LAB_MONITOR_ID", help="Alerting monitor id")
    _env_arg(p, "--writer-cert", "LAB_WRITER_CERT", help="lab-writer client certificate (PEM)")
    _env_arg(p, "--writer-key", "LAB_WRITER_KEY", help="lab-writer client key (PEM)")
    _env_arg(p, "--validator-cert", "LAB_VALIDATOR_CERT", help="lab-validator client certificate (PEM)")
    _env_arg(p, "--validator-key", "LAB_VALIDATOR_KEY", help="lab-validator client key (PEM)")
    _env_arg(p, "--cacert", "LAB_CACERT", help="CA bundle verifying the server (PEM)", required=False)
    # Generation parameters (match generate.py; not endpoints or secrets).
    p.add_argument("--copies", type=int, default=4)
    p.add_argument("--hosts", default="ws1.lab.local,ws2.lab.local")
    p.add_argument("--beacon-ip", default="198.51.100.10",
                   help="synthetic lab beacon address (RFC 5737 TEST-NET-2)")
    p.add_argument("--beacon-port", type=int, default=8080)
    p.add_argument("--mode", default="generated", choices=["generated"])
    p.add_argument("--run-id", default=None)
    p.add_argument("--workdir", default=None, help="where to write events.ndjson/run.json (default: temp)")
    p.add_argument("--timeout-s", type=int, default=600, help="max seconds to wait for detections")
    p.add_argument("--poll-interval-s", type=int, default=20)
    return p.parse_args(argv)


def _require(args, names: list[str]) -> None:
    missing = [n for n in names if not getattr(args, n.replace("-", "_"))]
    if missing:
        raise SystemExit("missing required argument(s): "
                         + ", ".join("--" + n for n in missing))


def main(argv):
    args = parse_args(argv)
    _require(args, ["endpoint", "stream", "runs-index", "detector-id", "monitor-id",
                    "writer-cert", "writer-key", "validator-cert", "validator-key"])
    if args.copies < 1:
        raise SystemExit("--copies must be >= 1")
    hosts = [h.strip() for h in args.hosts.split(",") if h.strip()]
    if not hosts:
        raise SystemExit("--hosts must list at least one host")

    now = datetime.datetime.now(datetime.timezone.utc)
    start = now.replace(microsecond=0)
    run_id = args.run_id or generate._run_id(now)

    workdir = args.workdir
    import tempfile
    tmp = None
    if workdir is None:
        tmp = tempfile.TemporaryDirectory(prefix="lab-run-")
        workdir = tmp.name
    try:
        # 1. generate
        events, run_doc = generate.generate(args.copies, hosts, args.beacon_ip,
                                             args.beacon_port, start, run_id, args.mode)
        os.makedirs(workdir, exist_ok=True)
        nd_path = os.path.join(workdir, "events.ndjson")
        with open(nd_path, "w", encoding="utf-8") as fh:
            for e in events:
                fh.write(json.dumps(generate.nest(e), separators=(",", ":"), sort_keys=True))
                fh.write("\n")
        print(f"generated run {run_id}: {len(events)} events -> {nd_path}", flush=True)

        # 2. index events (lab-writer)
        writer_ctx = _ssl_context(args.writer_cert, args.writer_key, args.cacert)
        body = indexer.build_bulk_body(nd_path, args.stream)
        result = indexer.post_bulk(args.endpoint, body, args.writer_cert, args.writer_key, args.cacert)
        if result.get("errors"):
            raise SystemExit("bulk index reported errors")
        print(f"indexed {len(result.get('items', []))} events into {args.stream}", flush=True)

        # 3. poll findings + alerts
        raw_findings, raw_alerts = poll(args.endpoint, writer_ctx, args.detector_id,
                                        args.monitor_id, run_id, args.timeout_s,
                                        args.poll_interval_s)
        print(f"detector and monitor fired: {len(_run_findings(raw_findings, run_id))} "
              f"finding(s), {len(raw_alerts.get('alerts', []))} alert(s)", flush=True)

        # 4. validate
        findings = validate.parse_sa(raw_findings, raw_alerts, run_doc)
        final = validate.validate(run_doc, findings)
        out_bytes = json.dumps(final, separators=(",", ":")).encode("utf-8")
        if len(out_bytes) > 64 * 1024:
            raise SystemExit(f"final run document is {len(out_bytes)} bytes, over the 64 KiB cap")
        validate._assert_no_leak(out_bytes)

        # 5. publish (lab-validator)
        validator_ctx = _ssl_context(args.validator_cert, args.validator_key, args.cacert)
        publish_run_doc(args.endpoint, args.runs_index, final, validator_ctx)
        caught = sum(1 for v in final["variants"] if v["caught_by_hash"])
        inc = final["incident"]["opened_at_variant"]
        print(f"published run {run_id} to {args.runs_index}: "
              f"hash caught {caught}/{len(final['variants'])}; incident at variant {inc}", flush=True)
        return 0
    finally:
        if tmp is not None:
            tmp.cleanup()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

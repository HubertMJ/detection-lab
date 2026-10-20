#!/usr/bin/env python3
"""Drive one real detection-lab run end to end (variant A), or validate a real VM run (B).

This is the entrypoint the cluster CronJob invokes (the lab-runner image's
`python3 /app/lab/run.py`, with no arguments). It chains the whole run:

  1. generate  - synthetic sdp-lab events + the run document (reuse generate.py);
  2. index     - bulk-index the events into the sdp-lab data stream over mutual
                 TLS with the single lab-runner identity (reuse indexer.py);
  3. discover  - resolve the Security Analytics detector id and the Alerting
                 monitor id by NAME (their ids are OpenSearch-generated and
                 dynamic, so they are never hard-coded);
  4. poll      - poll Security Analytics findings (of the lab detector) and
                 Alerting alerts (of the lab monitor) for this run, by lab.run_id
                 and a time window, until the detector and the monitor have both
                 fired or a timeout elapses;
  5. validate  - parse the real findings/alerts and compare them with the ground
                 truth (reuse validate.py), producing the final run document;
  6. publish   - index that run document into the lab-runs index over the same
                 mutual-TLS identity (a small bulk of one document).

Environment contract (what the CronJob sets; every value reaches run.py through
the environment or an equivalent CLI flag, never baked in, no secrets in this
file). The authoritative counterpart is the CronJob manifest
`cluster/infra/lab/cronjob.yaml` in the self-defending-portfolio repository (a
different repo, so it cannot be imported here); test_lab.py freezes this set so
the two cannot drift apart silently:

  required (no default):
    SIEM_URL         - https://host:port of OpenSearch           (--endpoint)
    SIEM_CLIENT_CERT - the lab-runner client certificate (PEM)   (--client-cert)
    SIEM_CLIENT_KEY  - the lab-runner client key (PEM)           (--client-key)
    SIEM_CA_CERT     - CA bundle verifying the server (PEM)       (--cacert)
  optional (defaulted, so the CronJob need not set them):
    LAB_MODE          - run mode, "generated"                    (--mode)
    LAB_STREAM        - events data stream, default "sdp-lab"     (--stream)
    LAB_RUNS_INDEX    - run-document index, default "lab-runs"    (--runs-index)
    LAB_DETECTOR_NAME - detector to resolve, default "sdp-lab-rules"
    LAB_MONITOR_NAME  - monitor to resolve,
                        default "sdp-git: lab-polymorphic-beacon"

There is ONE identity now: the lab-runner client certificate carries every
permission the run needs (write sdp-lab, read the detector's findings and the
monitor's alerts, write lab-runs), so SIEM_CLIENT_CERT/KEY serve indexing,
polling and publishing alike. It exits non-zero on any failure, and re-running
it is idempotent-ish (a fresh run_id each time unless one is pinned; the latest
run document wins by run.finished_at). Standard library only, so the container
image stays tiny.

Variant B (--mode isolated-vm, the validator timer on siem01 as lab-validator):
no generate/index. The run already happened on the isolated VM and its events
are in sdp-lab, so this resolves the run (--run-id, default the newest
isolated-vm run), waits until the VM has powered off and the detector and the
monitor have fired (bounded by --timeout-s; a partial run is still published),
rebuilds the run document with vm_validate.py and publishes it under its run id
(re-validating a run replaces its document). --dry-run writes it to stdout or
--out instead.
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
import vm_validate

# OpenSearch plugin API paths are protocol constants, not configuration.
FINDINGS_PATH = "/_plugins/_security_analytics/findings/_search"
ALERTS_PATH = "/_plugins/_alerting/monitors/alerts"
DETECTORS_SEARCH_PATH = "/_plugins/_security_analytics/detectors/_search"
MONITORS_SEARCH_PATH = "/_plugins/_alerting/monitors/_search"


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


def _post_json(endpoint: str, path: str, ctx: ssl.SSLContext, body: dict) -> dict:
    data = json.dumps(body, separators=(",", ":")).encode("utf-8")
    status, payload = https("POST", endpoint, path, ctx, body=data,
                            headers={"Content-Type": "application/json"})
    if status >= 300:
        raise SystemExit(f"POST {path} failed: HTTP {status} {payload.decode('utf-8', 'replace')}")
    return json.loads(payload)


def _resolve_id_by_name(resp: dict, name: str, kind: str) -> str:
    """The single OpenSearch document whose `_source.name` equals `name`, else a
    clear failure. All detectors/monitors are fetched and the name is matched exactly here
    (OpenSearch does not match_phrase the keyword name field); a missing or
    ambiguous name is fatal rather than guessed."""
    hits = ((resp.get("hits") or {}).get("hits")) or []
    matches = [h for h in hits
               if (h.get("_source") or {}).get("name") == name
               and (h.get("_source") or {}).get("type") != "workflow"]
    if not matches:
        raise SystemExit(f"no {kind} named {name!r} found "
                         f"(searched {len(hits)} candidate(s))")
    if len(matches) > 1:
        raise SystemExit(f"{len(matches)} {kind}s named {name!r} found; cannot resolve a single id")
    return matches[0]["_id"]


def discover_detector_id(endpoint: str, ctx: ssl.SSLContext, name: str) -> str:
    """Resolve the Security Analytics detector id for the detector named `name`."""
    body = {"size": 500, "query": {"match_all": {}}}
    resp = _post_json(endpoint, DETECTORS_SEARCH_PATH, ctx, body)
    return _resolve_id_by_name(resp, name, "detector")


def discover_monitor_id(endpoint: str, ctx: ssl.SSLContext, name: str) -> str:
    """Resolve the Alerting monitor id for the monitor named `name`."""
    body = {"size": 500, "query": {"match_all": {}}}
    resp = _post_json(endpoint, MONITORS_SEARCH_PATH, ctx, body)
    return _resolve_id_by_name(resp, name, "monitor")


def _run_findings(raw_findings: dict, run_id: str) -> list:
    """The raw findings whose matched document belongs to this run."""
    out = []
    for finding in raw_findings.get("findings", []):
        docs = finding.get("document_list") or []
        if docs and json.loads(docs[0]["document"]).get("lab", {}).get("run_id") == run_id:
            out.append(finding)
    return out


def poll(endpoint: str, ctx: ssl.SSLContext, monitor_id: str,
         run_id: str, timeout_s: int, interval_s: int) -> tuple[dict, dict]:
    """Poll findings and alerts until the detector and the monitor have both fired
    for this run, or the timeout elapses. Returns the raw responses.

    The findings search carries no detector_id filter: that parameter makes
    Security Analytics resolve the detector server-side, which needs the
    cluster:admin/.../securityanalytics/detector/get action the lab-runner role
    deliberately does not grant (same narrow read scope as sdp_lab_validator and
    sdp_api_read). sdp-lab-rules is the only detector, and _run_findings already
    keeps only this run's findings by run_id, so the unfiltered search is both
    correct and sufficient."""
    findings_path = f"{FINDINGS_PATH}?size=10000"
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
                    ctx: ssl.SSLContext, doc_id: str | None = None) -> None:
    """Index the final run document into the lab-runs index (one document). With doc_id the
    document replaces an earlier one of the same run (variant B re-validation)."""
    action = {"_index": index, **({"_id": doc_id} if doc_id else {})}
    body = (json.dumps({"index": action}, separators=(",", ":")) + "\n"
            + json.dumps(run_doc, separators=(",", ":")) + "\n").encode("utf-8")
    status, payload = https("POST", endpoint, "/_bulk", ctx, body=body,
                            headers={"Content-Type": "application/x-ndjson"})
    if status >= 300:
        raise SystemExit(f"publish failed: HTTP {status} {payload.decode('utf-8', 'replace')}")
    result = json.loads(payload)
    if result.get("errors"):
        raise SystemExit(f"publish reported errors: {payload.decode('utf-8', 'replace')}")


def _env_arg(p, flag: str, env: str, *, help: str, default=None, required: bool = True) -> None:
    """A flag that falls back to an environment variable. Nothing is baked in."""
    value = os.environ.get(env, default)
    note = "" if required else " [optional]"
    p.add_argument(flag, default=value, help=f"{help} (env {env}{note})")


def parse_args(argv):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    # Connection + single identity (required; the CronJob always supplies these).
    _env_arg(p, "--endpoint", "SIEM_URL", help="https://host:port of OpenSearch")
    _env_arg(p, "--client-cert", "SIEM_CLIENT_CERT", help="lab-runner client certificate (PEM)")
    _env_arg(p, "--client-key", "SIEM_CLIENT_KEY", help="lab-runner client key (PEM)")
    _env_arg(p, "--cacert", "SIEM_CA_CERT", help="CA bundle verifying the server (PEM)")
    # Stream / index / detection names (defaulted; overridable but not required).
    _env_arg(p, "--stream", "LAB_STREAM", default="sdp-lab",
             help="events data stream", required=False)
    _env_arg(p, "--runs-index", "LAB_RUNS_INDEX", default="lab-runs",
             help="index for the run document", required=False)
    _env_arg(p, "--detector-name", "LAB_DETECTOR_NAME", default="sdp-lab-rules",
             help="Security Analytics detector to resolve by name", required=False)
    _env_arg(p, "--monitor-name", "LAB_MONITOR_NAME", default="sdp-git: lab-polymorphic-beacon",
             help="Alerting monitor to resolve by name", required=False)
    p.add_argument("--mode", default=os.environ.get("LAB_MODE", "generated"),
                   choices=["generated", "isolated-vm"], help="run mode (env LAB_MODE)")
    # Variant B only (CLI flags, not env: the CronJob's env contract stays frozen).
    p.add_argument("--dry-run", action="store_true",
                   help="isolated-vm: write the run document to --out or stdout, publish nothing")
    p.add_argument("--out", default=None, help="isolated-vm --dry-run: file for the run document")
    # Generation parameters (match generate.py; not endpoints or secrets).
    p.add_argument("--copies", type=int, default=4)
    p.add_argument("--hosts", default="ws1.lab.local,ws2.lab.local")
    p.add_argument("--beacon-ip", default="198.51.100.10",
                   help="synthetic lab beacon address (RFC 5737 TEST-NET-2)")
    p.add_argument("--beacon-port", type=int, default=8080)
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


def latest_vm_run_id(endpoint: str, ctx: ssl.SSLContext, stream: str) -> str:
    """The newest isolated-VM run that has powered off (so a run still in flight never displaces the
    one before it); without any, the newest isolated-VM run at all."""
    for marker in ({"term": {"lab.marker": "poweroff_requested"}}, None):
        filters = [{"term": {"lab.mode": "isolated-vm"}}] + ([marker] if marker else [])
        resp = _post_json(endpoint, f"/{stream}/_search", ctx, {
            "size": 1, "query": {"bool": {"filter": filters}},
            "sort": [{"@timestamp": "desc"}], "_source": ["lab.run_id"]})
        hits = resp.get("hits", {}).get("hits", [])
        rid = hits and vm_validate.flatten(hits[0].get("_source", {})).get("lab.run_id")
        if rid:
            return rid
    raise SystemExit(f"no isolated-vm run in {stream}")


def vm_run_docs(endpoint: str, ctx: ssl.SSLContext, stream: str, run_id: str) -> list[dict]:
    """Every sdp-lab document of one run (events and lifecycle markers), oldest first."""
    resp = _post_json(endpoint, f"/{stream}/_search", ctx, {
        "size": 1000, "query": {"term": {"lab.run_id": run_id}}, "sort": [{"@timestamp": "asc"}]})
    return [h["_source"] for h in resp.get("hits", {}).get("hits", [])]


def _run_window_alerts(raw_alerts: dict, run_doc: dict, slack_s: int = 900) -> dict:
    """The monitor's alerts that started during this run (rollback .. power-off + the monitor's
    15-minute window), so an earlier run's alert is never credited to this one.

    Variants A and B beacon to the same synthetic address, i.e. one bucket of the monitor. Their
    daily runs are scheduled apart (B 03:00 UTC, ~4 min; A 03:30 UTC), so neither falls inside the
    other's window nor finds the other's alert still active. A manual B run within ~15 min of an A
    run can share A's alert; it then gets no incident here rather than A's."""
    t0 = validate._parse(run_doc["run"]["started_at"]).timestamp() * 1000
    t1 = (validate._parse(run_doc["run"]["finished_at"]).timestamp() + slack_s) * 1000
    return {"alerts": [a for a in raw_alerts.get("alerts", [])
                       if t0 <= a.get("start_time", 0) <= t1]}


def vm_findings_path(run_doc: dict, slack_s: int = 900) -> str:
    """The lab detector's findings during this run only (detectorType + time range), not every
    finding siem01 holds."""
    t0 = int(validate._parse(run_doc["run"]["started_at"]).timestamp() * 1000)
    t1 = int((validate._parse(run_doc["run"]["finished_at"]).timestamp() + slack_s) * 1000)
    return (f"{FINDINGS_PATH}?detectorType=sdp_lab&startTime={t0}&endTime={t1}"
            "&size=1000&sortOrder=desc")


def main_vm(args, ctx: ssl.SSLContext) -> int:
    """Variant B: validate a run the isolated VM already made (see the module docstring)."""
    run_id = args.run_id or latest_vm_run_id(args.endpoint, ctx, args.stream)
    monitor_id = discover_monitor_id(args.endpoint, ctx, args.monitor_name)
    # Newest first and bounded: the monitor's alerts accumulate over the days.
    alerts_path = f"{ALERTS_PATH}?monitorId={monitor_id}&size=200&sortString=start_time&sortOrder=desc"
    deadline = time.monotonic() + args.timeout_s
    stable, last_count = 0, -1
    while True:
        docs = vm_run_docs(args.endpoint, ctx, args.stream, run_id)
        markers, _ = vm_validate.split_docs(docs)
        try:
            run_doc = vm_validate.build_run_doc(run_id, docs, args.beacon_port)
        except SystemExit:
            # Only markers so far (the VM is still booting): keep waiting, refuse at the deadline.
            if time.monotonic() >= deadline:
                raise
            time.sleep(args.poll_interval_s)
            continue
        raw_findings = _get_json(args.endpoint, vm_findings_path(run_doc), ctx)
        raw_alerts = _run_window_alerts(_get_json(args.endpoint, alerts_path, ctx), run_doc)
        mine = _run_findings(raw_findings, run_id)
        caught = {json.loads(f["document_list"][0]["document"]).get("lab", {}).get("variant") for f in mine}
        powered_off = "poweroff_requested" in markers
        stable = stable + 1 if (powered_off and len(mine) == last_count) else 0
        last_count = len(mine)
        # Done once the VM is off, the monitor fired, and every copy has a finding (each copy writes a
        # persistence unit) - or the findings have stopped coming for three polls.
        if powered_off and raw_alerts["alerts"] and (
                len(caught) >= len(run_doc["variants"]) or stable >= 3):
            complete = True
            break
        if time.monotonic() >= deadline:
            complete = False
            print(f"run {run_id}: timed out after {args.timeout_s}s (powered off={powered_off}, "
                  f"findings={len(mine)}, alert={bool(raw_alerts['alerts'])}); publishing it as "
                  "incomplete", flush=True)
            break
        time.sleep(args.poll_interval_s)
    run_doc["run"]["complete"] = complete
    final = vm_validate.finish(run_doc, raw_findings, raw_alerts)
    caught = sum(1 for v in final["variants"] if v["caught_by_hash"])
    summary = (f"run {run_id}: {final['counters']['events']} events, {final['counters']['findings']} "
               f"finding(s), hash caught {caught}/{len(final['variants'])}; "
               f"incident at variant {final['incident']['opened_at_variant']}")
    if args.dry_run:
        out = json.dumps(final, indent=2)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(out + "\n")
        else:
            print(out)
        print(summary + " (dry run, not published)", file=sys.stderr, flush=True)
        return 0
    publish_run_doc(args.endpoint, args.runs_index, final, ctx, doc_id=run_id)
    print(f"published {summary}", flush=True)
    return 0


def main(argv):
    args = parse_args(argv)
    _require(args, ["endpoint", "client-cert", "client-key", "cacert"])
    if args.mode == "isolated-vm":
        return main_vm(args, _ssl_context(args.client_cert, args.client_key, args.cacert))
    if args.copies < 1:
        raise SystemExit("--copies must be >= 1")
    hosts = [h.strip() for h in args.hosts.split(",") if h.strip()]
    if not hosts:
        raise SystemExit("--hosts must list at least one host")

    now = datetime.datetime.now(datetime.timezone.utc)
    start = now.replace(microsecond=0)
    run_id = args.run_id or generate._run_id(now)

    # One identity, one TLS context, for every operation (index, search, publish).
    ctx = _ssl_context(args.client_cert, args.client_key, args.cacert)

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

        # 2. index events (lab-runner identity)
        body = indexer.build_bulk_body(nd_path, args.stream)
        result = indexer.post_bulk(args.endpoint, body, args.client_cert, args.client_key, args.cacert)
        if result.get("errors"):
            raise SystemExit("bulk index reported errors")
        print(f"indexed {len(result.get('items', []))} events into {args.stream}", flush=True)

        # 3. discover the detector and monitor ids by name (ids are dynamic)
        detector_id = discover_detector_id(args.endpoint, ctx, args.detector_name)
        monitor_id = discover_monitor_id(args.endpoint, ctx, args.monitor_name)
        print(f"resolved detector {args.detector_name!r} -> {detector_id}, "
              f"monitor {args.monitor_name!r} -> {monitor_id}", flush=True)

        # 4. poll findings + alerts
        raw_findings, raw_alerts = poll(args.endpoint, ctx, monitor_id,
                                        run_id, args.timeout_s,
                                        args.poll_interval_s)
        print(f"detector and monitor fired: {len(_run_findings(raw_findings, run_id))} "
              f"finding(s), {len(raw_alerts.get('alerts', []))} alert(s)", flush=True)

        # 5. validate
        findings = validate.parse_sa(raw_findings, raw_alerts, run_doc)
        final = validate.validate(run_doc, findings)
        out_bytes = json.dumps(final, separators=(",", ":")).encode("utf-8")
        if len(out_bytes) > 64 * 1024:
            raise SystemExit(f"final run document is {len(out_bytes)} bytes, over the 64 KiB cap")
        validate._assert_no_leak(out_bytes)

        # 6. publish (same lab-runner identity)
        publish_run_doc(args.endpoint, args.runs_index, final, ctx)
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

#!/usr/bin/env python3
"""Bulk-index events.ndjson into an OpenSearch data stream over mutual TLS.

Thin wrapper for use on siem01 with the lab-writer identity. The client
certificate and key are passed as arguments and read from disk at run time;
there are no credentials in this file and no default endpoint. Uses the bulk
"create" action with no _id, which is what a data stream requires.

Standard library only (http.client + ssl).
"""

from __future__ import annotations

import argparse
import http.client
import json
import ssl
import sys
from urllib.parse import urlsplit


def build_bulk_body(ndjson_path: str, stream: str) -> bytes:
    action = json.dumps({"create": {"_index": stream}}, separators=(",", ":"))
    lines = []
    with open(ndjson_path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            json.loads(line)  # reject malformed events before shipping
            lines.append(action)
            lines.append(line)
    return ("\n".join(lines) + "\n").encode("utf-8")


def post_bulk(endpoint: str, body: bytes, certfile: str, keyfile: str,
              cafile: str | None) -> dict:
    url = urlsplit(endpoint)
    if url.scheme != "https":
        raise SystemExit("endpoint must be https")
    ctx = ssl.create_default_context(cafile=cafile) if cafile else ssl.create_default_context()
    if cafile is None:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
    conn = http.client.HTTPSConnection(url.hostname, url.port or 443, context=ctx, timeout=30)
    try:
        conn.request("POST", "/_bulk", body=body,
                     headers={"Content-Type": "application/x-ndjson"})
        resp = conn.getresponse()
        payload = resp.read()
        if resp.status >= 300:
            raise SystemExit(f"bulk failed: HTTP {resp.status} {payload.decode('utf-8', 'replace')}")
        return json.loads(payload)
    finally:
        conn.close()


def parse_args(argv):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--endpoint", required=True, help="https://host:port of OpenSearch")
    p.add_argument("--stream", required=True, help="data stream name, e.g. sdp-lab")
    p.add_argument("--events", required=True, help="events.ndjson from generate.py")
    p.add_argument("--cert", required=True, help="client certificate (PEM)")
    p.add_argument("--key", required=True, help="client private key (PEM)")
    p.add_argument("--cacert", default=None, help="CA bundle to verify the server (PEM)")
    return p.parse_args(argv)


def main(argv):
    args = parse_args(argv)
    body = build_bulk_body(args.events, args.stream)
    result = post_bulk(args.endpoint, body, args.cert, args.key, args.cacert)
    if result.get("errors"):
        failed = [i for i in result.get("items", []) if i.get("create", {}).get("status", 200) >= 300]
        raise SystemExit(f"bulk reported errors on {len(failed)} item(s)")
    took = result.get("took")
    count = len(result.get("items", []))
    print(f"indexed {count} event(s) into {args.stream} (took {took} ms)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

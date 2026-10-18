# detection-lab

An incident generator for SIEM training: emulated attacks with a known ground truth, and the
detections that should catch them. The flagship case is polymorphism: every copy of a harmless test
program gets a new hash and a new name, the hash rule misses all but the first, and detection keyed
on behaviour still opens one incident.

**Status: variant A (generated events, real detection) implemented. See [`lab/`](lab/).**

| What | Where |
|---|---|
| The generator, validator and indexer (python3 stdlib only) | [lab/](lab/) |
| A synthetic replay of scenario C, the data behind the preview | [replay/scenario-c.json](replay/scenario-c.json) |
| The preview on the site | https://hubertjablon.ski/lab/ (source: [hubertjablon.ski](https://github.com/HubertMJ/hubertjablon.ski)) |

## How it fits together

```mermaid
flowchart LR
    subgraph NOW["Today"]
        R[("replay/scenario-c.json<br/>synthetic, sample: true")] --> P["hubertjablon.ski/lab/<br/>design preview"]
    end
    subgraph A["Variant A: generated events, real detection"]
        GEN["lab/generate.py<br/>4 copies: new hash, new name"] --> EV["events.ndjson (sdp-lab)<br/>+ run.json ground truth"]
        EV --> IDX["lab/indexer.py<br/>bulk-index on siem01"]
        IDX --> OS[("OpenSearch on siem01<br/>Sigma rules · Alerting monitors")]
        OS --> VAL["lab/validate.py<br/>findings vs ground truth,<br/>coverage, time to detect"]
        EV -. run.json .-> VAL
        VAL --> FIN["final run document<br/>-> hubertjablon.ski/lab/"]
    end
    GEN -. same format .-> R
```

Variant A executes nothing: `generate.py` only writes synthetic JSON (the events a run would
produce, plus the ground truth). The events are indexed into the real SIEM, its own Sigma rules and
Alerting monitors do the detecting, and `validate.py` compares what they caught against the ground
truth. The preview reads a replay file and computes everything in the browser; the generator writes
events in the same shape, so the page and a real run can be compared one to one.

## The generator (`lab/`)

Python 3 standard library only (it runs on siem01, Debian, no `pip`). Variant A executes no binary;
a real test binary belongs to variant B (an isolated VM), which is out of scope here.

- **`generate.py`** writes one run: `--copies N` (default 4) copies of a harmless marker artefact,
  each with a new SHA-256 and a new file name. Copy 1 is deterministic (a fixed byte blob, constant
  hash) so a hash IOC rule can pin to it; copies 2..N get a fresh random 16-byte marker. For each
  copy it emits a process-create (`event.code` 1), a Run-key write from a Temp path (`13`) and a
  steady beacon (`3`, enough connections for the 5+/10-min logic). Outputs:
  - `events.ndjson` — one event per line in the `sdp-lab` field contract, as nested objects
    (`{"event": {"code": ...}, "process": {...}}`, `@timestamp` top-level): Security Analytics
    rules match nested documents, not flat dotted keys. Ready to bulk-index;
  - `run.json` — the ground-truth / run document in the site's `LabReplay` shape (`schema: 1`,
    `sample: false`), with lab labels only (`ws1`/`ws2`, `lab beacon :<port>`) and findings left
    empty for the validator to fill. Under 64 KiB.
- **`validate.py`** reads `run.json` and the real detections (`--findings`), then fills per-copy
  `caught_by_hash` and each finding's `delay_s`, the `incident` (when a behaviour-keyed alert opens
  it and after which copy), and ATT&CK coverage (expected vs detected). The hash rule catches copy 1
  only; the beacon monitor opens one incident. It emits only lab labels, never real hosts/addresses.
- **`indexer.py`** bulk-POSTs `events.ndjson` into an OpenSearch data stream over mutual TLS
  (`--cert`/`--key`, the `lab-writer` identity on siem01). Bulk `create` with no `_id`, as a data
  stream requires. No credentials in the file.

Example:

```sh
python3 lab/generate.py --out ./out
python3 -m unittest discover -s test -p 'test_*.py'
```

Detection content (the Sigma rules and the Alerting monitor) lives in the self-defending-portfolio
`siem/` tree; the SIEM is a commercial-SIEM-equivalent OpenSearch instance with Security Analytics.

## Decisions (2026-10-14)

- The Windows lab (GOAD) is not built on the current hardware: it needs roughly 28-36 GB of RAM.
- The SIEM is the OpenSearch instance of
  [self-defending-portfolio](https://github.com/HubertMJ/self-defending-portfolio) (Security
  Analytics with Sigma rules, Alerting monitors).
- Copies are renamed by default, not only rebuilt: a real attacker changes the name too. Risk
  scored per program name never reaches the threshold; scored per behaviour (the address every
  copy calls) it opens one incident at the second copy.
- A synthetic replay is the possible next step: the generator writes Sysmon-format events
  (`replay/`) that can be indexed into OpenSearch without any Windows machine.

## The replay format

`replay/scenario-c.json` (`schema: 1`, `sample: true`): the artefact, the beacon address, the risk
threshold, the rules with their score and ATT&CK technique, and four variants. Each variant has its
host, SHA-256, renamed file name, Sysmon-style events (`event.code` 1, 3, 13), ground truth and the
findings each rule would raise, with the delay to detection. Every value is generated; no machine
ran it.

## License

MIT, see [LICENSE](LICENSE). Planned dependencies keep their own licenses (GOAD GPL-3.0,
Sigma rules DRL 1.1) and are to be used as submodules, not copied.

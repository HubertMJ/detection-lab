# Variant B — the real run on an isolated VM

Variant A (`lab/`) *synthesises* Sysmon-shaped events. Variant B does the real thing: a small,
harmless program actually runs on an isolated Linux VM, and Sysmon for Linux reports what the kernel
saw. Same detection content, same run-document shape (`lab.mode: isolated-vm`), but the evidence on
`/lab/` is a genuine machine, not a mock-up.

## The canary (`scenario.c`)

A deliberately harmless program. When run it performs exactly three real, observable actions, then
exits:

| action | Sysmon event | what the rule keys on |
|---|---|---|
| it runs | 1 process-create | `process.hash.sha256` of the copy |
| it writes a user systemd unit (`~/.config/systemd/user/<name>.service`, `ExecStart` = its own `/tmp` path) | 11 file-create | executable under `/tmp/` + a persistence-unit path |
| it connects a few times to one lab sink address | 3 network-connection | 5+ connections at a steady interval, cardinality of hashes per address |

It installs nothing, **enables no unit** (the file is written, not activated), starts no daemon,
holds no secret and forks no payload. The VM is reverted to a clean snapshot after every run, so even
the written file does not survive.

## Polymorphism

`scenario.c` carries a 48-byte slot: a fixed 16-byte magic (`LABCANARYMARK01:`) followed by 32
marker bytes. `run_scenario.py` makes four copies by overwriting those 32 bytes:

- **copy 1** keeps the marker all-zero, so it is byte-for-byte the compiled base image and hashes to
  a fixed, reproducible SHA-256 — the value the `ioc-lab-known-hash` rule pins. The known-hash rule
  catches this one only.
- **copies 2–4** get a fresh random marker and a new random name (`svc-<8 hex>`), so each has a new
  SHA-256. Behaviour is identical — that is the point: a hash rule misses them, behaviour rules do
  not.

## Reproducible build

`make` builds `dist/lab-canary` with fixed, deterministic flags (static, no-PIE, stripped, no unwind
tables, normalised paths, `SOURCE_DATE_EPOCH=0`). A given toolchain always produces the same copy-1
hash; a different gcc/libc produces a different, equally valid hash that must be re-pinned in the
rule. CI builds it twice and fails if the two hashes differ.

The copy-1 hash is toolchain-specific, so it is pinned from the **VM's** toolchain (the Debian image
the VM is built from), not from a developer box, and the provisioning ships that exact base image to
the VM — the VM never compiles at run time.

## Running it (on the VM)

```sh
run_scenario.py --base /opt/lab/lab-canary --workdir /tmp \
  --sink-ip <siem01> --sink-port 8080 --beacons 6 --interval-ms 20000 --gap-s 15
```

It writes two things: a **name map** (`/run/lab/namemap`: the run id and one `name variant` line per
copy, written *before* the copies run) and a **ground-truth manifest** (`/run/lab/manifest.json`:
per copy the name, SHA-256, pid, start time and persistence path). The runner itself ships and
detects nothing.

## Shipping (`fluent-bit/`)

Sysmon for Linux logs every event to the journal as Windows-Sysmon XML. `fluent-bit.conf` reads
those from the journal; `sysmon_to_lab.lua` keeps only this run's canary events (matched by file
name against the name map), maps events 1/3/11 to the exact sdp-lab shape variant A produces
(nested documents, the copy's SHA-256 on the network events too), masks `host.name` to `lab-vm` and
the beacon destination to variant A's synthetic address `198.51.100.10`, and the OpenSearch output
ships them to siem01's `sdp-lab` stream over mTLS as the `lab-vm-shipper` identity. The mapper is
tested offline against real Sysmon XML fixtures (`test_mapper.lua`). Because only matched events are
shipped, none of the VM's other activity ever leaves the host.

## The boot action (`run-and-ship.sh`)

The VM's systemd oneshot at boot: run the scenario, wait for Fluent Bit to drain every event to
siem01 (its loopback metrics, bounded by a timeout), then power off. The VM is reverted to a clean
snapshot before each boot, so this is the whole life of a run. The siem01 validator (`lab/run.py`,
isolated-vm mode) later lines the manifest up against the real findings and alerts to build the run
document in `lab-runs`.

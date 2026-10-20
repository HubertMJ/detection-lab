// "Start run now" and the live view of a run in progress (variant B, the isolated VM).
//
// The visitor may start a real run: the button POSTs to /cluster/api/lab/run, which only queues the
// request; the Proxmox host polls the API (outbound only) and starts the VM itself. Limits are the
// API's (one run at a time, a cooldown, a daily cap, a closed window around the daily runs); this
// file only shows them. While the VM runs, the page follows it from GET /cluster/api/lab/raw: the
// lifecycle markers and Sysmon events as siem01 indexed them, drawn as a run with no detections yet.
// Pure DOM building (no innerHTML); nothing here scrolls the page.

import { h } from "../lib/dom";
import type { LabRawRecord, LabRawRecords, LabReplay, LabRunControl, LabVariant } from "../lib/lab";

const HHMM = new Intl.DateTimeFormat("en-GB", { timeZone: "UTC", hour: "2-digit", minute: "2-digit" });

function mmss(s: number): string {
  const m = Math.floor(s / 60);
  return `${m}:${String(s % 60).padStart(2, "0")}`;
}

/** The control, rendered empty; updateRunControl fills it from each poll (and ticks the countdown). */
export function runControl(): HTMLElement {
  return h("div", { class: "lab-run", id: "lab-run-control", hidden: true },
    h("button", { type: "button", class: "btn btn--primary lab-run__btn", disabled: true }, "Start a real run now"),
    h("span", { class: "lab-run__msg small" }, ""));
}

/** What the button and the line next to it say for a state (`nowMs` for the countdown). */
export function runControlText(c: LabRunControl, nowMs: number): { label: string; msg: string; enabled: boolean } {
  const left = c.max_per_day !== undefined && c.runs_today !== undefined ? Math.max(0, c.max_per_day - c.runs_today) : null;
  const until = c.next_allowed_at ? Math.max(0, Math.round((Date.parse(c.next_allowed_at) - nowMs) / 1000)) : null;
  switch (c.state) {
    case "available":
      return { label: "Start a real run now", enabled: c.can_start,
        msg: "Reverts the isolated VM to its clean snapshot and runs the four copies (about 4 min)" +
          (left !== null ? ` · ${left} of ${c.max_per_day} runs left today` : "") };
    case "queued":
      return { label: "Starting…", enabled: false, msg: "Request queued; the VM host picks it up within seconds." };
    case "starting":
      return { label: "Starting…", enabled: false, msg: "The VM is being reverted to its clean snapshot." };
    case "running":
      return { label: "Run in progress", enabled: false, msg: "Following it live below." };
    case "cooldown":
      if (c.reason === "daily limit") {
        return { label: "Start a real run now", enabled: false,
          msg: `Today's ${c.max_per_day ?? ""} runs are used up; next run possible at ${c.next_allowed_at ? HHMM.format(new Date(c.next_allowed_at)) + " UTC" : "midnight UTC"}.`.replace("  ", " ") };
      }
      return { label: "Start a real run now", enabled: false,
        msg: until !== null && until > 0 ? `The VM rests between runs: next run possible in ${mmss(until)}.` : "Next run possible shortly." };
    case "closed":
      return { label: "Start a real run now", enabled: false,
        msg: `The daily runs are on now; next run possible at ${c.next_allowed_at ? HHMM.format(new Date(c.next_allowed_at)) + " UTC" : "a little later"}.` };
    default:
      return { label: "Start a real run now", enabled: false, msg: c.reason ? `Runs cannot be started right now (${c.reason}).` : "Runs cannot be started right now." };
  }
}

/** Fill the control from a poll; null hides it (the endpoint is absent, e.g. the standalone image). */
export function updateRunControl(el: HTMLElement, c: LabRunControl | null, nowMs: number, note?: string): void {
  const btn = el.querySelector<HTMLButtonElement>(".lab-run__btn");
  const msg = el.querySelector<HTMLElement>(".lab-run__msg");
  if (!btn || !msg) return;
  if (!c) { el.hidden = true; return; }
  const t = runControlText(c, nowMs);
  el.hidden = false;
  el.dataset.state = c.state;
  btn.textContent = t.label;
  btn.disabled = !t.enabled;
  msg.textContent = note ?? t.msg;
}

const LABELS: Record<string, string> = {
  rollback: "Reverted to clean snapshot", start: "VM started", booted: "Booted", sysmon_up: "Sysmon started",
  shipper_up: "Fluent Bit started", run_start: "Scenario started", drained: "All events shipped to siem01",
  poweroff_requested: "Powered off",
};
const ORDER = Object.keys(LABELS);

/** A run in progress, drawn from its raw records: the lifecycle so far, every copy's events so far,
 * placeholders for the copies still to come, and no detections yet. `base` (the last validated run)
 * lends the scenario, the rules and the number of copies. null when the records hold no marker yet. */
export function replayFromRaw(raw: LabRawRecords, base: LabReplay, nowMs: number): LabReplay | null {
  const marks = new Map<string, number>();
  const events: LabRawRecord[] = [];
  for (const r of raw.records) {
    const t = Date.parse(r["@timestamp"]);
    if (!Number.isFinite(t)) continue;
    if (r.event?.action === "lifecycle" && r.lab?.marker) {
      if (!marks.has(r.lab.marker)) marks.set(r.lab.marker, t);
    } else if (r.event?.code !== undefined) events.push(r);
  }
  if (marks.size === 0 && events.length === 0) return null;
  const stamps = [...marks.values(), ...events.map((e) => Date.parse(e["@timestamp"]))];
  const t0 = marks.get("rollback") ?? Math.min(...stamps);
  const off = (t: number) => Math.max(0, Math.round((t - t0) / 1000));
  const end = marks.get("poweroff_requested") ?? Math.max(nowMs, ...stamps);
  const iso = (t: number) => new Date(t).toISOString();

  const byCopy = new Map<number, LabRawRecord[]>();
  for (const e of events) {
    const n = Number(e.lab?.variant);
    if (Number.isInteger(n) && n >= 1) byCopy.set(n, [...(byCopy.get(n) ?? []), e]);
  }
  const copies = Math.max(base.variants.length, ...byCopy.keys(), 1);
  const variants: LabVariant[] = [];
  for (let n = 1; n <= copies; n++) {
    const evs = (byCopy.get(n) ?? []).sort((a, b) => Date.parse(a["@timestamp"]) - Date.parse(b["@timestamp"]));
    const p = (r: LabRawRecord) => (r.process ?? {}) as { name?: string; pid?: number; executable?: string; hash?: { sha256?: string }; parent?: { pid?: number } };
    const create = evs.find((e) => e.event?.code === "1");
    const flat = evs.map((e) => {
      const pr = p(e);
      const dst = (e.destination ?? {}) as { port?: number };
      const f = (e.file ?? {}) as { path?: string };
      const ev: Record<string, string | number> = { "@timestamp": e["@timestamp"], offset_s: off(Date.parse(e["@timestamp"])),
        "event.code": String(e.event?.code), "event.action": String(e.event?.action ?? ""), "host.name": "lab-vm" };
      if (pr.name) ev["process.name"] = pr.name;
      if (pr.executable) ev["process.executable"] = pr.executable;
      if (pr.hash?.sha256) ev["process.hash.sha256"] = pr.hash.sha256;
      if (pr.pid !== undefined) ev["process.pid"] = pr.pid;
      if (pr.parent?.pid !== undefined) ev["process.parent.pid"] = pr.parent.pid;
      if (f.path) ev["file.path"] = f.path;
      if (dst.port !== undefined) { ev["destination.port"] = dst.port; ev["destination.ip"] = `lab beacon :${dst.port}`; }
      return ev;
    });
    const sha = (create && p(create).hash?.sha256) ?? "";
    variants.push({
      n, host: "lab-vm", sha256: sha, renamed: (create && p(create).name) ?? `copy ${n}`, events: flat,
      ground_truth: { "@timestamp": flat[0]?.["@timestamp"] as string ?? iso(t0), host: "lab-vm", techniques: [], variant_sha256: sha },
      findings: [], caught_by_hash: false, pending: evs.length === 0,
      ...(create && p(create).pid !== undefined ? { pid: p(create).pid } : {}),
      ...(create && p(create).parent?.pid !== undefined ? { ppid: p(create).parent?.pid } : {}),
    });
  }
  const seen = variants.filter((v) => !v.pending);
  return {
    ...base,
    sample: false,
    live: true,
    run: { id: raw.run_id, mode: "isolated-vm", started_at: iso(t0), finished_at: iso(end), duration_s: off(end) },
    lifecycle: ORDER.filter((m) => marks.has(m)).map((m) => ({ marker: m, offset_s: off(marks.get(m) as number), label: LABELS[m] }))
      .sort((a, b) => a.offset_s - b.offset_s),
    variants,
    counters: { processes: seen.length, unique_hashes: new Set(seen.map((v) => v.sha256)).size,
      events: seen.reduce((n, v) => n + v.events.length, 0), findings: 0, incidents: 0 },
    incident: { opened_at_variant: null, delay_s: null, key: "beacon" },
    history: base.history,
  };
}

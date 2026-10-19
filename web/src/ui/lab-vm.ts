// "Detection lab" variant B (isolated-vm): what the page shows for a REAL run on an isolated VM.
// Where variant A (ui/lab.ts) lets the visitor replay a synthetic sample, this draws a run that
// actually happened: the VM's lifecycle second by second, the real Sysmon evidence per copy
// (pid/ppid, the compiled binary's SHA-256, the persistence file, the beacons), and the verdict.
// Nothing here runs by itself; it only renders the run document. Pure DOM building (no innerHTML).

import { h } from "../lib/dom";
import { type LabReplay, type LabVariant, shortHash } from "../lib/lab";

const RUN_DATE = new Intl.DateTimeFormat("en-GB", {
  timeZone: "UTC", day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit",
});

function mmss(s: number): string {
  const m = Math.floor(s / 60);
  return `${m}:${String(s % 60).padStart(2, "0")}`;
}

/** Above the panel: a real run with its id, date and duration, or a clearly-marked sample. */
function note(d: LabReplay): HTMLElement {
  if (d.sample || !d.run) {
    return h("p", { class: "lab-note" },
      h("span", { class: "tag tag--arm" }, "Sample"),
      " An example of what a real VM run looks like — not a live run.");
  }
  const dur = d.run.duration_s ? ` · ${mmss(d.run.duration_s)} on the VM` : "";
  return h("p", { class: "lab-note" },
    h("span", { class: "tag tag--detect" }, "Live · real machine"),
    " a real run in an isolated lab" + dur + " · ",
    h("time", { datetime: d.run.finished_at }, RUN_DATE.format(new Date(d.run.finished_at))));
}

function counters(d: LabReplay): HTMLElement | null {
  const c = d.counters;
  if (!c) return null;
  const tile = (n: number, label: string) =>
    h("div", { class: "lab-vm-count" }, h("span", { class: "lab-vm-count__n" }, String(n)),
      h("span", { class: "lab-vm-count__l" }, label));
  return h("div", { class: "lab-vm-counts" },
    tile(c.processes, "processes run"),
    tile(c.unique_hashes, "unique hashes"),
    tile(c.events, "events in the SIEM"),
    tile(c.incidents, c.incidents === 1 ? "incident" : "incidents"));
}

/** The VM's run as a timeline: revert → boot → sensor up → scenario → shipped → power off. */
function lifecycle(d: LabReplay): HTMLElement | null {
  if (!d.lifecycle || d.lifecycle.length === 0) return null;
  const steps = d.lifecycle.map((m) =>
    h("li", { class: "lab-vm-step" },
      h("span", { class: "lab-vm-step__t" }, mmss(m.offset_s)),
      h("span", { class: "lab-vm-step__l" }, m.label)));
  return h("ol", { class: "lab-vm-timeline", "aria-label": "VM run timeline" }, steps);
}

function ev(v: LabVariant, code: string): Record<string, string | number> | undefined {
  return v.events.find((e) => e["event.code"] === code);
}

/** The source of the lab canary (variant B), on the repository's reproducible-build section. */
const CANARY_SRC = "https://github.com/HubertMJ/detection-lab/blob/main/vm/README.md#reproducible-build";

function rawEvents(v: LabVariant): HTMLElement {
  const pre = h("pre", { class: "lab-vm-raw__pre mono" });
  pre.textContent = JSON.stringify(v.events, null, 2);
  return h("details", { class: "lab-vm-raw" },
    h("summary", {}, `Raw Sysmon — ${v.events.length} event${v.events.length === 1 ? "" : "s"} as indexed in sdp-lab`),
    pre);
}

function copyCard(d: LabReplay, v: LabVariant): HTMLElement {
  const create = ev(v, "1");
  const file = ev(v, "11");
  const beacons = v.events.filter((e) => e["event.code"] === "3").length;
  const firedPersist = v.findings.some((f) => f.rule.includes("persistence"));
  const firedBeacon = v.findings.some((f) => f.rule.includes("beacon"));
  const incidentHere = d.incident?.opened_at_variant === v.n;
  const kv = (k: string, val: string | number, mono = true) =>
    h("div", { class: "lab-vm-ev" }, h("span", { class: "lab-vm-ev__k" }, k),
      h("span", { class: mono ? "lab-vm-ev__v mono" : "lab-vm-ev__v" }, String(val)));
  const chip = (cls: string, text: string) => h("span", { class: `lab-vm-chip ${cls}` }, text);
  // Copy 1's hash is the one the known-hash rule pins; link it to the reproducible build.
  const shaVal: (string | HTMLElement)[] = v.n === 1
    ? [h("a", { href: CANARY_SRC, title: v.sha256 }, shortHash(v.sha256))]
    : [h("span", { title: v.sha256 }, shortHash(v.sha256))];
  return h("article", { class: "lab-vm-copy" },
    h("header", { class: "lab-vm-copy__h" },
      h("span", { class: "lab-vm-copy__n mono" }, v.renamed),
      h("span", { class: "lab-vm-copy__c" }, `copy ${v.n}`)),
    h("div", { class: "lab-vm-copy__b" },
      h("div", { class: "lab-vm-ev" }, h("span", { class: "lab-vm-ev__k" }, "sha-256"),
        h("span", { class: "lab-vm-ev__v mono" }, shaVal)),
      create ? kv("pid / ppid", `${v.pid ?? create["process.pid"]} / ${v.ppid ?? ""}`) : null,
      create ? kv("exec", String(create["process.executable"])) : null,
      file ? kv("persistence", String(file["file.path"])) : null,
      kv("beacons", beacons ? `${beacons}× → lab beacon :8080` : "—")),
    h("div", { class: "lab-vm-chips" },
      chip(v.caught_by_hash ? "hit" : "miss", v.caught_by_hash ? "✓ known-hash" : "known-hash"),
      firedPersist ? chip("hit", "✓ persistence from /tmp") : null,
      firedBeacon ? chip(incidentHere ? "crit" : "hit", incidentHere ? "✓ beaconing → incident" : "✓ beaconing") : null),
    rawEvents(v));
}

function copies(d: LabReplay): HTMLElement {
  return h("div", { class: "lab-vm-copies" }, d.variants.map((v) => copyCard(d, v)));
}

function verdict(d: LabReplay): HTMLElement {
  const n = d.variants.length;
  const hashCaught = d.variants.filter((v) => v.caught_by_hash).length;
  const behaviour = d.variants.filter((v) => v.findings.some((f) => !f.rule.startsWith("ioc-"))).length;
  const inc = d.incident?.opened_at_variant ?? null;
  const tile = (cls: string, big: string, cap: string) =>
    h("div", { class: `lab-vm-tile ${cls}` }, h("span", { class: "lab-vm-tile__n" }, big),
      h("span", { class: "lab-vm-tile__c" }, cap));
  return h("div", { class: "lab-vm-verdict" },
    tile("good", `${hashCaught} / ${n}`, "caught by the known-hash rule — only the copies whose hash is on the list"),
    tile("", `${behaviour} / ${n}`, "caught by behaviour — persistence from /tmp and steady beaconing, whatever the hash"),
    tile("crit", inc === null ? "—" : `copy ${inc}`, inc === null ? "no incident" : "where the incident opened"));
}

/** Draw a real (or sample) isolated-VM run into the lab panel. */
export function mountLabVm(root: HTMLElement, d: LabReplay): void {
  root.replaceChildren(
    h("div", { class: "lab lab-vm" },
      note(d),
      counters(d),
      h("h3", { class: "panel-title" }, "The machine's run, second by second"),
      lifecycle(d),
      h("h3", { class: "panel-title" }, "Four copies, four hashes, one behaviour"),
      copies(d),
      h("h3", { class: "panel-title" }, "What the rules caught"),
      verdict(d)),
  );
}

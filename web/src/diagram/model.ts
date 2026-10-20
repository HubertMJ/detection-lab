// The detection lab's architecture as data: one model draws the diagram on /lab/ (layout.ts, wide and
// phone, inlined by scripts/build.mjs) and the README's "How it fits together" mermaid
// (scripts/diagram.mjs; a unit test fails when the README's copy is stale). Nothing here touches the
// DOM, so the same module runs in the build, in Node and in vitest.
//
// It starts where the landing page's and the cluster page's diagrams start, at the visitor, with the
// same zones, names, colours and edge words for the shared path (hubertjablon.ski
// src/diagram/model.ts, self-defending-portfolio app/web/src/diagram/model.ts), then follows the lab.
//
// The page is public: names, schedules and ports, but no internal address or VLAN.

/** A box's colour, as on the other two diagrams: the request path, the attacked machine, what detects, what records. */
export type Role = "neutral" | "attack" | "detect" | "record" | "entry";

export interface Zone {
  id: string;
  title: string;
  sub: string;
  /** The phone's shorter subtitle beside the zone's name. */
  subNarrow: string;
  /** Wide drawing: [col, row, cols, rows] (rows may be fractional). */
  at: [number, number, number, number];
}

export interface LabNode {
  id: string;
  label: string;
  /** The small line(s): wrapped at " · " to fit the box. */
  sub: string;
  zone: string;
  role: Role;
  /** Wide drawing: [col, row]. */
  at: [number, number];
}

/** auto: straight when the two share a row or column; hv/vh: one bend; over: up, across above the row, down into b. */
export type Route = "auto" | "hv" | "vh" | "over";

export interface LabEdge {
  from: string;
  to: string;
  label: string;
  /** flow: the main path (solid); side: a side relationship (dotted). */
  kind: "flow" | "side";
  route?: Route;
  /** An arrowhead at both ends (the page and the API talk both ways). */
  both?: boolean;
}

export const ZONES: Zone[] = [
  { id: "internet", title: "Internet", sub: "", subNarrow: "", at: [0, 0, 2, 1] },
  // A short subtitle: the Gateway's route to the API runs above the boxes beside it.
  // Subtitles stop short of the lines that cross a zone's title row (the phone's run down the middle).
  { id: "k3s", title: "k3s01", sub: "one VM · Cilium", subNarrow: "one VM", at: [2, 0, 4, 2] },
  { id: "siem", title: "siem01", sub: "", subNarrow: "own VM", at: [3, 2.3, 3, 2] },
  { id: "pve", title: "Proxmox host", sub: "lab-vm reaches siem01 only", subNarrow: "", at: [0, 2.3, 2, 2] },
  { id: "lab", title: "Lab VM", sub: "", subNarrow: "isolated", at: [2, 3.3, 1, 1] },
];

export const NODES: LabNode[] = [
  // ---- the way in, as on the landing page and /cluster/ ----
  { id: "visitor", label: "Visitor", sub: "browser", zone: "internet", role: "entry", at: [0, 0] },
  { id: "edge", label: "Cloudflare edge", sub: "TLS · WAF", zone: "internet", role: "entry", at: [1, 0] },
  { id: "cloudflared", label: "cloudflared ×2", sub: "no inbound port", zone: "k3s", role: "entry", at: [2, 0] },
  { id: "gateway", label: "Cilium Gateway", sub: "routes by path", zone: "k3s", role: "entry", at: [3, 0] },
  { id: "page", label: "/lab/ page", sub: "the replay · Start run now", zone: "k3s", role: "entry", at: [4, 0] },
  { id: "api", label: "Cluster API", sub: "/cluster/api/lab/ · latest · vm · raw · run", zone: "k3s", role: "entry", at: [5, 0] },
  // ---- variant A, in the cluster ----
  { id: "runner", label: "lab-runner CronJob", sub: "variant A · 03:30 UTC", zone: "k3s", role: "neutral", at: [3, 1] },
  // ---- siem01: the stream, the detections, the run document ----
  { id: "stream", label: "sdp-lab stream", sub: "OpenSearch · append-only", zone: "siem", role: "record", at: [3, 2.3] },
  { id: "detector", label: "Detector + monitor", sub: "Security Analytics · beacon monitor", zone: "siem", role: "detect", at: [4, 3.3] },
  { id: "validator", label: "Validator", sub: "lab-validator timer · every 5 min", zone: "siem", role: "record", at: [5, 3.3] },
  { id: "runs", label: "lab-runs", sub: "run documents", zone: "siem", role: "record", at: [5, 2.3] },
  { id: "sink", label: "lab-sink", sub: ":8080 · beacon sink", zone: "siem", role: "neutral", at: [3, 3.3] },
  // ---- the Proxmox host: what starts a run, and the VM it runs on ----
  { id: "trigger", label: "Run-now trigger", sub: "every 15 s · outbound only", zone: "pve", role: "neutral", at: [1, 2.3] },
  { id: "timer", label: "lab-vm-run timer", sub: "daily 03:00 UTC", zone: "pve", role: "neutral", at: [0, 3.3] },
  { id: "reset", label: "Reset and start", sub: "rollback to lab-clean · markers", zone: "pve", role: "neutral", at: [1, 3.3] },
  { id: "vm", label: "lab-vm", sub: "VM 122 · Sysmon for Linux · Fluent Bit", zone: "lab", role: "attack", at: [2, 3.3] },
];

export const EDGES: LabEdge[] = [
  // The way in: the same words as the other two diagrams.
  { from: "visitor", to: "edge", label: "HTTPS", kind: "flow" },
  { from: "edge", to: "cloudflared", label: "tunnel", kind: "flow", both: true },
  { from: "cloudflared", to: "gateway", label: "HTTPS", kind: "flow" },
  { from: "gateway", to: "page", label: "/lab/", kind: "flow" },
  { from: "gateway", to: "api", label: "/cluster/api", kind: "flow", route: "over" },
  // "Start run now": the page asks the API; the trigger on the Proxmox host collects the request.
  { from: "page", to: "api", label: "POST", kind: "side" },
  { from: "trigger", to: "edge", label: "polls run/claim, outbound", kind: "side" },
  { from: "trigger", to: "reset", label: "on demand", kind: "flow" },
  { from: "timer", to: "reset", label: "daily", kind: "flow" },
  { from: "reset", to: "vm", label: "start", kind: "flow" },
  { from: "vm", to: "stream", label: "events", kind: "flow", route: "vh" },
  { from: "vm", to: "sink", label: "beacons", kind: "side" },
  { from: "runner", to: "stream", label: "synthetic events", kind: "flow" },
  { from: "stream", to: "detector", label: "rules", kind: "flow", route: "hv" },
  { from: "detector", to: "validator", label: "findings", kind: "flow" },
  { from: "validator", to: "runs", label: "writes", kind: "flow" },
  { from: "runs", to: "api", label: "read-only", kind: "flow" },
];

/** The phone's drawing: every node top to bottom, in this order. */
export const NARROW: string[] = [
  "visitor", "edge", "cloudflared", "gateway", "page", "api", "runner",
  "stream", "detector", "validator", "runs", "sink", "trigger", "timer", "reset", "vm",
];

export const TITLE = "How a run reaches this page";

/** The drawing in words, for a screen reader and the README. */
export function describe(): string {
  return (
    "A visitor reaches this page and the cluster API the way every page here is reached: HTTPS to the Cloudflare " +
    "edge, a tunnel to two cloudflared replicas in the k3s01 VM, which opens no inbound port, and the Cilium Gateway, " +
    "which routes /lab/ to the page and /cluster/api to the API. Every day at 03:00 UTC a timer on the Proxmox host, or " +
    "on demand a trigger there that polls the API outbound for a visitor's Start run now, rolls the isolated lab VM " +
    "back to its clean snapshot and starts it. The VM runs four renamed " +
    "copies of a harmless test program; Sysmon for Linux records them and Fluent Bit ships the events over " +
    "mutual TLS to the sdp-lab stream on siem01, and the copies beacon to the lab sink there. The Security " +
    "Analytics detector and the beacon monitor catch them, and within minutes a validator (every 5 minutes) lines the findings up " +
    "against the ground truth and writes the run document to lab-runs. Variant A, a CronJob in the cluster at " +
    "03:30 UTC, writes synthetic events to the same stream. The cluster API serves the run read-only to this page."
  );
}

/** The model's problems: unknown zones or nodes, duplicates, a phone order that misses or repeats a node. */
export function validate(): string[] {
  const out: string[] = [];
  const ids = new Set<string>();
  for (const n of NODES) {
    if (ids.has(n.id)) out.push(`duplicate node ${n.id}`);
    ids.add(n.id);
    if (!ZONES.some((z) => z.id === n.zone)) out.push(`node ${n.id}: unknown zone ${n.zone}`);
  }
  for (const e of EDGES) for (const end of [e.from, e.to]) if (!ids.has(end)) out.push(`edge ${e.from}->${e.to}: unknown node ${end}`);
  if (NARROW.length !== ids.size || new Set(NARROW).size !== NARROW.length || NARROW.some((id) => !ids.has(id))) out.push("the phone order is not every node once");
  return out;
}

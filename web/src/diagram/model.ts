// The detection lab's architecture as data: one model draws the diagram on /lab/ (layout.ts, wide and
// phone, inlined by scripts/build.mjs) and the README's "How it fits together" mermaid
// (scripts/diagram.mjs; a unit test fails when the README's copy is stale). Nothing here touches the
// DOM, so the same module runs in the build, in Node and in vitest.
//
// The page is public: names, schedules and ports, but no internal address or VLAN.

/** A box's colour: where the copies run, what detects, what records, what the visitor reaches. */
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

/** auto: straight when the two share a row or column; hv/vh: one bend; around: under everything and up the right side. */
export type Route = "auto" | "hv" | "vh" | "around";

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
  { id: "k3s", title: "k3s01", sub: "the cluster", subNarrow: "the cluster", at: [3, 0, 3, 1] },
  { id: "pve", title: "Proxmox host", sub: "lab-vm is isolated: egress to siem01 only", subNarrow: "lab-vm isolated", at: [0, 1.3, 3, 2] },
  // No subtitle: the CronJob's line into the stream crosses where it would sit.
  { id: "siem", title: "siem01", sub: "", subNarrow: "own VM", at: [3, 1.3, 3, 2] },
];

export const NODES: LabNode[] = [
  // ---- the Proxmox host: what starts a run, and the VM it runs on ----
  { id: "timer", label: "lab-vm-run timer", sub: "daily 03:00 UTC", zone: "pve", role: "neutral", at: [0, 1.3] },
  { id: "agent", label: "Run-now agent", sub: "polls the cluster API · outbound only", zone: "pve", role: "neutral", at: [1, 2.3] },
  { id: "reset", label: "Reset and start", sub: "rollback to lab-clean · markers", zone: "pve", role: "neutral", at: [1, 1.3] },
  { id: "vm", label: "lab-vm", sub: "VM 122 · Sysmon for Linux · Fluent Bit", zone: "pve", role: "attack", at: [2, 1.3] },
  // ---- siem01: the stream, the detections, the run document ----
  { id: "stream", label: "sdp-lab stream", sub: "OpenSearch · append-only", zone: "siem", role: "record", at: [3, 1.3] },
  { id: "sink", label: "lab-sink", sub: ":8080 · beacon sink", zone: "siem", role: "neutral", at: [3, 2.3] },
  { id: "detector", label: "Detector + monitor", sub: "Security Analytics · beacon monitor", zone: "siem", role: "detect", at: [4, 1.3] },
  { id: "validator", label: "Validator", sub: "lab-validator timer · 03:20 UTC", zone: "siem", role: "record", at: [4, 2.3] },
  { id: "runs", label: "lab-runs", sub: "run documents", zone: "siem", role: "record", at: [5, 2.3] },
  // ---- k3s01: variant A, and what the visitor reaches ----
  { id: "runner", label: "lab-runner CronJob", sub: "variant A · 03:30 UTC", zone: "k3s", role: "neutral", at: [3, 0] },
  { id: "page", label: "/lab/ page", sub: "the replay · Start run now", zone: "k3s", role: "entry", at: [4, 0] },
  { id: "api", label: "Cluster API", sub: "/cluster/api/lab/ · latest · vm · raw · run", zone: "k3s", role: "entry", at: [5, 0] },
];

export const EDGES: LabEdge[] = [
  { from: "timer", to: "reset", label: "daily", kind: "flow" },
  { from: "agent", to: "reset", label: "on demand", kind: "flow" },
  { from: "reset", to: "vm", label: "start", kind: "flow" },
  { from: "vm", to: "stream", label: "events", kind: "flow" },
  { from: "vm", to: "sink", label: "beacons", kind: "side", route: "vh" },
  { from: "runner", to: "stream", label: "synthetic events", kind: "flow" },
  { from: "stream", to: "detector", label: "rules", kind: "flow" },
  { from: "detector", to: "validator", label: "findings", kind: "flow" },
  { from: "validator", to: "runs", label: "writes", kind: "flow" },
  { from: "runs", to: "api", label: "read-only", kind: "flow" },
  { from: "page", to: "api", label: "JSON", kind: "flow", both: true },
  { from: "agent", to: "api", label: "polls for a run request, outbound", kind: "side", route: "around" },
];

/** The phone's drawing: every node top to bottom, in this order. */
export const NARROW: string[] = ["timer", "agent", "reset", "vm", "sink", "stream", "detector", "validator", "runs", "runner", "api", "page"];

export const TITLE = "How a run reaches this page";

/** The drawing in words, for a screen reader and the README. */
export function describe(): string {
  return (
    "Every day at 03:00 UTC a timer on the Proxmox host, or on demand an agent that polls the cluster API " +
    "outbound, rolls the isolated lab VM back to its clean snapshot and starts it. The VM runs four renamed " +
    "copies of a harmless test program; Sysmon for Linux records them and Fluent Bit ships the events over " +
    "mutual TLS to the sdp-lab stream on siem01, and the copies beacon to the lab sink there. The Security " +
    "Analytics detector and the beacon monitor catch them, and at 03:20 UTC a validator lines the findings up " +
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

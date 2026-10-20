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
  /** One or two sentences for the caption the node opens (ui/diagram.ts). */
  blurb: string;
  /** Where it lives: "lab:<path>" in this repository, "sdp:<path>" in self-defending-portfolio. */
  sources: string[];
  /** Wide drawing: [col, row]. */
  at: [number, number];
}

/** The two repositories a node's sources point into. */
export const REPOS = {
  lab: "https://github.com/HubertMJ/detection-lab",
  sdp: "https://github.com/HubertMJ/self-defending-portfolio",
} as const;

/** A source's GitHub address (the default branch; a file or a directory). */
export function sourceUrl(src: string): string {
  const [repo, ...rest] = src.split(":");
  return `${REPOS[repo as keyof typeof REPOS]}/tree/main/${rest.join(":")}`;
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
  { id: "visitor", label: "Visitor", sub: "browser", zone: "internet", role: "entry", blurb: "You. This page, its run data and the Start run now button all come in the same way: over HTTPS to Cloudflare.", sources: [], at: [0, 0] },
  { id: "edge", label: "Cloudflare edge", sub: "TLS · WAF", zone: "internet", role: "entry", blurb: "Cloudflare terminates TLS and filters with its WAF; nothing reaches the cluster any other way: the tunnel is dialled from inside.", sources: ["sdp:docs/adr/0003-cloudflare-tunnel-exposure.md"], at: [1, 0] },
  { id: "cloudflared", label: "cloudflared ×2", sub: "no inbound port", zone: "k3s", role: "entry", blurb: "The tunnel is dialled from inside the VM; nothing listens for the internet. Cloudflare's requests ride back along it. Two replicas, so a rolling update never takes the site down.", sources: ["sdp:cluster/infra/cloudflared/"], at: [2, 0] },
  { id: "gateway", label: "Cilium Gateway", sub: "routes by path", zone: "k3s", role: "entry", blurb: "Cilium's Envoy terminates TLS again inside the cluster, adds the security headers and routes by path: /lab/ to this page's image, /cluster/api to the API.", sources: ["sdp:cluster/infra/gateway/", "sdp:cluster/infra/lab/httproute.yaml"], at: [3, 0] },
  { id: "page", label: "/lab/ page", sub: "the replay · Start run now", zone: "k3s", role: "entry", blurb: "This page: a static, signed nginx image built in this repository. It draws the latest run, follows a live one, and its Start run now button asks the API for a run.", sources: ["lab:web/", "sdp:cluster/infra/lab/"], at: [4, 0] },
  { id: "api", label: "Cluster API", sub: "/cluster/api/lab/ · latest · vm · raw · run", zone: "k3s", role: "entry", blurb: "The cluster's Go API serves the lab read-only: the latest run document, the VM's state and a live run's raw records; it queues a visitor's run request for the trigger to collect, one at a time and within daily limits.", sources: ["sdp:app/api/internal/lab/", "sdp:app/api/internal/labrun/"], at: [5, 0] },
  // ---- variant A, in the cluster ----
  { id: "runner", label: "lab-runner CronJob", sub: "variant A · 03:30 UTC", zone: "k3s", role: "neutral", blurb: "Variant A: a daily CronJob runs run.py, which writes synthetic events with a known ground truth into the SIEM, waits for its rules and writes the run document. Nothing is executed.", sources: ["lab:lab/run.py", "lab:runner/", "sdp:cluster/infra/lab/cronjob.yaml"], at: [3, 1] },
  // ---- siem01: the stream, the detections, the run document ----
  { id: "stream", label: "sdp-lab stream", sub: "OpenSearch · append-only", zone: "siem", role: "record", blurb: "The sdp-lab data stream on siem01: every event of a run, Sysmon's and the lifecycle markers, append-only, in the lab's own field contract.", sources: ["sdp:siem/fields/lab.yaml", "sdp:siem/log-types/lab.yaml"], at: [3, 2.3] },
  { id: "detector", label: "Detector + monitor", sub: "Security Analytics · beacon monitor", zone: "siem", role: "detect", blurb: "Security Analytics runs the lab's Sigma rules (a known hash, a persistence unit from /tmp); the Alerting monitor scores the beacon per address and opens one incident however the copies are named.", sources: ["sdp:siem/detectors/lab.yaml", "sdp:siem/rules/ioc-lab-known-hash.yml", "sdp:siem/rules/lab-persistence-user-unit-from-tmp.yml", "sdp:siem/monitors/lab-polymorphic-beacon.json"], at: [4, 3.3] },
  { id: "validator", label: "Validator", sub: "lab-validator timer · every 5 min", zone: "siem", role: "record", blurb: "Every 5 minutes a timer on siem01 looks for a finished VM run it has not judged: it lines the findings and the alert up against the run's ground truth and writes the run document, once.", sources: ["lab:lab/vm_validate.py", "lab:lab/run.py", "sdp:ansible/roles/lab_validator/"], at: [5, 3.3] },
  { id: "runs", label: "lab-runs", sub: "run documents", zone: "siem", role: "record", blurb: "The lab-runs index: one run document per run, the shape this page draws. The API reads it, never writes it.", sources: ["sdp:ansible/roles/opensearch_config/files/lab-runs.json"], at: [5, 2.3] },
  { id: "sink", label: "lab-sink", sub: ":8080 · beacon sink", zone: "siem", role: "neutral", blurb: "A socket on siem01 the copies beacon to: it accepts and closes, so the network events are real and nothing leaves the lab.", sources: ["sdp:ansible/roles/lab_sink/"], at: [3, 3.3] },
  // ---- the Proxmox host: what starts a run, and the VM it runs on ----
  { id: "trigger", label: "Run-now trigger", sub: "every 15 s · outbound only", zone: "pve", role: "neutral", blurb: "Start run now, collected: every 15 s the Proxmox host asks the API, over the public way in, whether a visitor's run is waiting. Outbound only; nothing on the host listens.", sources: ["sdp:scripts/lab-vm-provision.sh"], at: [1, 2.3] },
  { id: "timer", label: "lab-vm-run timer", sub: "daily 03:00 UTC", zone: "pve", role: "neutral", blurb: "A systemd timer on the Proxmox host starts the daily run at 03:00 UTC.", sources: ["sdp:scripts/lab-vm-provision.sh"], at: [0, 3.3] },
  { id: "reset", label: "Reset and start", sub: "rollback to lab-clean · markers", zone: "pve", role: "neutral", blurb: "Every run starts identical: the VM is rolled back to its clean snapshot, started, and handed the run's lifecycle markers.", sources: ["sdp:scripts/lab-vm-provision.sh"], at: [1, 3.3] },
  { id: "vm", label: "lab-vm", sub: "VM 122 · Sysmon for Linux · Fluent Bit", zone: "lab", role: "attack", blurb: "The isolated VM runs four renamed copies of a harmless test program; Sysmon for Linux records what the kernel saw, Fluent Bit maps it to the lab's fields and ships it over mutual TLS, then the VM powers off. Its firewall lets it reach siem01 and nothing else.", sources: ["lab:vm/README.md", "lab:vm/scenario.c", "lab:vm/run_scenario.py", "lab:vm/fluent-bit/sysmon_to_lab.lua"], at: [2, 3.3] },
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

/** The phone's drawing, top to bottom: the way in and the real run. The CronJob and the beacon sink
 * are left to the wide drawing (and the README), as /cluster/'s phone leaves out the unguarded twin. */
export const NARROW: string[] = [
  "visitor", "edge", "cloudflared", "gateway", "page", "api",
  "stream", "detector", "validator", "runs", "trigger", "timer", "reset", "vm",
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

/** The model's problems: unknown zones or nodes, duplicates, a phone order with an unknown or repeated node, a node without words. */
export function validate(): string[] {
  const out: string[] = [];
  const ids = new Set<string>();
  for (const n of NODES) {
    if (ids.has(n.id)) out.push(`duplicate node ${n.id}`);
    ids.add(n.id);
    if (!ZONES.some((z) => z.id === n.zone)) out.push(`node ${n.id}: unknown zone ${n.zone}`);
    if (n.blurb.length < 20) out.push(`node ${n.id}: no blurb`);
    for (const src of n.sources) if (!/^(lab|sdp):[\w./-]+$/.test(src)) out.push(`node ${n.id}: source ${src} is not lab:<path> or sdp:<path>`);
  }
  for (const e of EDGES) for (const end of [e.from, e.to]) if (!ids.has(end)) out.push(`edge ${e.from}->${e.to}: unknown node ${end}`);
  if (new Set(NARROW).size !== NARROW.length || NARROW.some((id) => !ids.has(id))) out.push("the phone order repeats or names an unknown node");
  return out;
}

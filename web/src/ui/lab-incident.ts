// "How four copies became one incident" (variant B): a second drawing in the hero diagram's language.
// The copies (a new name and a new SHA-256 each) all beacon to one lab address; their arrows converge
// into that address, one arrow carries on into the beacon monitor (a gauge of distinct hashes against
// its threshold of two) and one into the incident. A lone "known hash" arrow leaves copy 1 for the
// IOC rule - the contrast is the drawing itself. As it plays, each copy lights, a dot rides its arrow,
// a pip fills; at the second pip the monitor and the incident light. Boxes open a caption with their
// sources, like the hero's. The query sits under it, line by line, with the hash rule for contrast.
//
// It plays once when it scrolls into view and can be replayed; with reduced motion it shows the
// finished state. Script only toggles data-* attributes and begins SMIL dots (attributes, CSP-clean);
// the SVG keeps its viewBox, so nothing on the page moves. Pure DOM building (no innerHTML).

import { h, prefersReducedMotion, svg } from "../lib/dom";
import type { LabReplay } from "../lib/lab";

const SDP = "https://github.com/HubertMJ/self-defending-portfolio/blob/main/";
export const RULE_LINKS: Record<string, string> = {
  "lab-polymorphic-beacon": `${SDP}siem/monitors/lab-polymorphic-beacon.json`,
  "ioc-lab-known-hash": `${SDP}siem/rules/ioc-lab-known-hash.yml`,
  "lab-persistence-user-unit-from-tmp": `${SDP}siem/rules/lab-persistence-user-unit-from-tmp.yml`,
};
/** The monitor's threshold and window (siem/monitors/lab-polymorphic-beacon.json). */
const THRESHOLD = 2;
const WINDOW_MIN = 15;
const STEP_MS = 1500;
const RIDE_MS = 600;
const LINE = 15;
const GAP = 6;
const GAUGE_H = 50;

const shortHash = (s: string): string => `${s.slice(0, 12)}…${s.slice(-4)}`;
const mmss = (s: number): string => `${Math.floor(s / 60)}:${String(Math.round(s) % 60).padStart(2, "0")}`;
const txt = (s: string): Text => document.createTextNode(s);

export interface CopyBeacon { n: number; name: string; sha: string; byHash: boolean; beacons: number[] }
type Role = "below" | "opened" | "joined";

/** Each copy that beaconed, in copy order (the validator places the incident in that order too: a
 * lost first beacon must not reorder the story), with its beacon offsets from the rollback. */
export function beacons(d: LabReplay): CopyBeacon[] {
  const out: CopyBeacon[] = [];
  for (const v of d.variants) {
    const offs = v.events.filter((e) => e["event.code"] === "3").map((e) => Number(e["offset_s"] ?? NaN))
      .filter(Number.isFinite).sort((a, b) => a - b);
    if (offs.length) out.push({ n: v.n, name: v.renamed, sha: v.sha256, byHash: !!v.caught_by_hash, beacons: offs });
  }
  return out.sort((a, b) => a.n - b.n);
}

/** What each copy did to the monitor's count: below the threshold, opened the incident, or joined it. */
export function roles(list: CopyBeacon[], openedAt: number | null): Role[] {
  const seen = new Set<string>();
  let opened = false;
  return list.map((c) => {
    seen.add(c.sha);
    if (!opened && openedAt !== null && seen.size >= THRESHOLD && c.n === openedAt) { opened = true; return "opened"; }
    return opened ? "joined" : "below";
  });
}

interface Box { x: number; y: number; w: number; h: number }
interface NodeW { id: string; label: string; role: string; sub: string[]; tip: string; gauge?: boolean; outcome?: boolean }
interface Edge { id: string; tone: "run" | "detect" | "incident"; pts: [number, number][]; label?: string; at?: [number, number]; anchor?: string }
interface Drawing { view: "wide" | "narrow"; width: number; height: number; zones: { box: Box; title: string; sub: string }[];
  heads: { x: number; y: number; title: string; sub: string }[]; boxes: Map<string, Box>; edges: Edge[]; headH: number }

const r1 = (n: number): number => Math.round(n * 10) / 10;
const pathD = (pts: [number, number][]): string => pts.map(([x, y], i) => `${i ? "L" : "M"}${r1(x)} ${r1(y)}`).join(" ");
const cx = (b: Box): number => b.x + b.w / 2;
const cy = (b: Box): number => b.y + b.h / 2;
const right = (b: Box): number => b.x + b.w;
const bottom = (b: Box): number => b.y + b.h;
function trimHead(pts: [number, number][]): [number, number][] {
  const o = pts.map((p) => [...p] as [number, number]);
  const p = o[o.length - 1], t = o[o.length - 2];
  const dx = t[0] - p[0], dy = t[1] - p[1], len = Math.hypot(dx, dy) || 1, k = Math.min(GAP, len / 3) / len;
  p[0] += dx * k; p[1] += dy * k;
  return o;
}

export function incidentStory(d: LabReplay): HTMLElement | null {
  if (d.live) return null;
  const copies = beacons(d);
  if (copies.length === 0) return null;
  const openedAt = d.incident?.opened_at_variant ?? null;
  const role = roles(copies, openedAt);
  const openedIdx = role.indexOf("opened");
  const n = copies.length;
  const beacon = d.beacon || "lab beacon :8080";
  const hashes = new Set(copies.map((c) => c.sha)).size;
  const incAt = d.incident?.at_offset_s ?? null;
  const delay = d.incident?.delay_s ?? null;
  const caught = copies.filter((c) => c.byHash);
  const ioc = caught[0];

  // ---------- the nodes' words ----------
  const nodes: NodeW[] = [
    ...copies.map((c) => ({ id: `c${c.n}`, label: c.name, role: "attack",
      tip: c.byHash ? "The copy the known-hash rule can catch: its SHA-256 is on the indicator list." : "A rebuilt copy: a new SHA-256 and a new name, so the known-hash rule sees nothing.",
      sub: [`copy ${c.n} · ${c.byHash ? "on the IOC list" : "unknown hash"}`, `sha-256 ${shortHash(c.sha)}`, `first beacon ${mmss(c.beacons[0])} · ${c.beacons.length}×`] })),
    { id: "hash", label: "Known-bad hash", role: "detect", tip: "A list of known-bad SHA-256 values: it fires only on a copy whose hash is on it.",
      sub: ["Sigma rule · IOC list", "matches one known sha-256", caught.length ? `caught copy ${caught.map((c) => c.n).join(", ")} only` : "caught none"] },
    { id: "sink", label: beacon, role: "neutral", tip: "The address every copy calls: a socket on siem01 that accepts and closes.", sub: ["lab-sink on siem01", "one destination ip:port", `all ${n} copies call it`] },
    { id: "mon", label: "One beacon, many binaries", role: "detect", gauge: true,
      tip: `Counts different program hashes per address; ${THRESHOLD} or more opens an incident.`,
      sub: ["Alerting monitor · every minute", `last ${WINDOW_MIN} min of connections`, "a bucket per destination ip:port"] },
    openedIdx >= 0
      ? { id: "inc", label: "One incident", role: "incident", outcome: true, tip: `One incident holds all ${n} copies: whatever they are called, they call one address.`,
        sub: [`${n} copies · ${hashes} hashes`, "one address", incAt !== null ? `opened ${mmss(incAt)} · +${delay ?? "?"} s` : "opened"] }
      : { id: "inc", label: "No incident", role: "incident", outcome: true, tip: `The monitor never saw ${THRESHOLD} different hashes at one address.`, sub: ["never two hashes", "at one address", `within ${WINDOW_MIN} min`] },
  ];
  const nodeOf = (id: string): NodeW => nodes.find((x) => x.id === id) as NodeW;

  // ---------- geometry ----------
  /** Wide: copies stacked in column 0; the hash rule at the top and the address at the stack's middle
   * in column 1; the monitor (with its gauge) in column 2; the incident in column 3. */
  const wide = (): Drawing => {
    const cw = 190, cwMon = 224, ch = 78, gx = 104, gy = 24, top = 46, left = 16;
    const col = (c: number): number => left + c * (cw + gx) + (c > 2 ? cwMon - cw : 0);
    const boxes = new Map<string, Box>();
    copies.forEach((c, i) => boxes.set(`c${c.n}`, { x: col(0), y: top + i * (ch + gy), w: cw, h: ch }));
    const first = boxes.get(`c${copies[0].n}`) as Box, last = boxes.get(`c${copies[n - 1].n}`) as Box;
    const stackCy = (cy(first) + cy(last)) / 2;
    boxes.set("hash", { x: col(1), y: top, w: cw, h: ch });
    boxes.set("sink", { x: col(1), y: Math.max(top + ch + gy, stackCy - ch / 2), w: cw, h: ch });
    const sinkB = boxes.get("sink") as Box;
    boxes.set("mon", { x: col(2), y: sinkB.y, w: cwMon, h: ch + GAUGE_H });
    boxes.set("inc", { x: col(3), y: sinkB.y, w: cw, h: ch });
    const width = col(3) + cw + 16;
    const height = Math.max(bottom(last), bottom(boxes.get("mon") as Box), bottom(sinkB)) + 12 + 16;
    const zones = [
      { box: { x: 4, y: 10, w: cw + 24, h: height - 26 }, title: "Lab VM", sub: `${n} copies · ${hashes} hashes · ${n} names` },
      { box: { x: col(1) - 12, y: 10, w: width - col(1) + 12 - 4, h: height - 26 }, title: "siem01", sub: "one address → one bucket → one incident" },
    ];
    const edges: Edge[] = [];
    const hash = boxes.get("hash") as Box, mon = boxes.get("mon") as Box, inc = boxes.get("inc") as Box;
    for (const c of caught) {
      const b = boxes.get(`c${c.n}`) as Box;
      const y = cy(b) - 12;
      edges.push({ id: `${c.n}-hash`, tone: "detect", pts: [[right(b), y], [hash.x, y]], label: "known hash", at: [(right(b) + hash.x) / 2, y - 7], anchor: "middle" });
    }
    const mid = (n - 1) / 2;
    const outer = Math.max(...copies.map((_, j) => Math.abs(j - mid)));
    copies.forEach((c, i) => {
      const b = boxes.get(`c${c.n}`) as Box;
      const y0 = c.byHash ? cy(b) + 12 : cy(b);
      const trunk = sinkB.x - 36 - (outer - Math.abs(i - mid)) * 12;
      const yIn = cy(sinkB) + (i - mid) * 12;
      edges.push({ id: `${c.n}-sink`, tone: "run", pts: [[right(b), y0], [trunk, y0], [trunk, yIn], [sinkB.x, yIn]],
        label: `${c.beacons.length} beacons`, at: [right(b) + 6, y0 - 6], anchor: "start" });
    });
    const headY = cy(sinkB);
    edges.push({ id: "sink-mon", tone: "detect", pts: [[right(sinkB), headY], [mon.x, headY]], label: "by ip:port", at: [(right(sinkB) + mon.x) / 2, headY - 7], anchor: "middle" });
    edges.push({ id: "mon-inc", tone: "incident", pts: [[right(mon), headY], [inc.x, headY]], label: `≥ ${THRESHOLD} hashes`, at: [(right(mon) + inc.x) / 2, headY - 7], anchor: "middle" });
    return { view: "wide", width, height, zones, heads: [], boxes, edges, headH: ch };
  };

  /** Phone: one column. The copies, then the hash rule (a lane from copy 1 down the right margin), the
   * address (a lane per copy down the left margin), the monitor with its gauge, the incident. */
  const narrow = (): Drawing => {
    const w = 256, lane = 11, x = 10 + lane * n + 2, gap = 28, ch = 76;
    const boxes = new Map<string, Box>();
    const heads: Drawing["heads"] = [];
    let y = 10;
    heads.push({ x, y: y + 12, title: "Lab VM", sub: `${n} copies · ${hashes} hashes` }); y += 24;
    for (const c of copies) { boxes.set(`c${c.n}`, { x, y, w, h: ch }); y += ch + gap; }
    y += 8; heads.push({ x, y: y + 12, title: "siem01", sub: "one address · one incident" }); y += 24;
    for (const id of ["hash", "sink", "mon", "inc"]) { const hh = id === "mon" ? ch + GAUGE_H : ch; boxes.set(id, { x, y, w, h: hh }); y += hh + gap; }
    const height = y - gap + 10, width = x + w + lane * Math.max(1, caught.length) + 10;
    const edges: Edge[] = [];
    const hash = boxes.get("hash") as Box, sink = boxes.get("sink") as Box, mon = boxes.get("mon") as Box, inc = boxes.get("inc") as Box;
    caught.forEach((c, k) => {
      const b = boxes.get(`c${c.n}`) as Box, lx = right(b) + lane * (k + 1);
      edges.push({ id: `${c.n}-hash`, tone: "detect", pts: [[right(b), cy(b)], [lx, cy(b)], [lx, cy(hash) - k * 8], [right(hash), cy(hash) - k * 8]] });
    });
    const mid = (n - 1) / 2;
    copies.forEach((c, i) => {
      const b = boxes.get(`c${c.n}`) as Box, lx = x - lane * (n - i), yIn = cy(sink) - (i - mid) * 12;
      edges.push({ id: `${c.n}-sink`, tone: "run", pts: [[b.x, cy(b)], [lx, cy(b)], [lx, yIn], [sink.x, yIn]] });
    });
    edges.push({ id: "sink-mon", tone: "detect", pts: [[cx(sink), bottom(sink)], [cx(sink), mon.y]], label: "by ip:port", at: [cx(sink) + 9, (bottom(sink) + mon.y) / 2 + 4], anchor: "start" });
    edges.push({ id: "mon-inc", tone: "incident", pts: [[cx(mon), bottom(mon)], [cx(mon), inc.y]], label: `≥ ${THRESHOLD} hashes`, at: [cx(mon) + 9, (bottom(mon) + inc.y) / 2 + 4], anchor: "start" });
    return { view: "narrow", width, height, zones: [], heads, boxes, edges, headH: ch };
  };

  // ---------- markup ----------
  const drawing = (dr: Drawing): SVGElement => {
    const p = dr.view === "wide" ? "liw" : "lin";
    const root = svg("svg", { class: `li-svg li-svg--${dr.view}`, viewBox: `0 0 ${r1(dr.width)} ${r1(dr.height)}`, role: "group", "aria-labelledby": `${p}-title ${p}-desc` });
    root.append(svg("title", { id: `${p}-title` }, txt("How four copies became one incident")));
    root.append(svg("desc", { id: `${p}-desc` }, txt(`${n} copies of one program, each with a new name and a new SHA-256, beacon to ${beacon}. ` +
      `The known-hash rule catches ${caught.length ? `copy ${caught.map((c) => c.n).join(", ")} only` : "none of them"}. The monitor groups the last ${WINDOW_MIN} minutes ` +
      `of connections by destination and counts different hashes per address; at ${THRESHOLD} it opens an incident, which the later copies join.`)));
    root.append(svg("defs", {}, svg("marker", { id: `${p}-arrow`, viewBox: "0 0 10 10", refX: 9, refY: 5, markerWidth: 8, markerHeight: 8,
      markerUnits: "userSpaceOnUse", orient: "auto-start-reverse" }, svg("path", { class: "ld-head", d: "M0,1 L10,5 L0,9 z" }))));
    for (const z of dr.zones) {
      root.append(svg("g", { class: "ld-zone" }, svg("rect", { x: z.box.x, y: z.box.y, width: z.box.w, height: z.box.h, rx: 10 }),
        svg("text", { class: "ld-zonetitle", x: z.box.x + 12, y: z.box.y + 18 }, txt(z.title), svg("tspan", { class: "ld-zonesub" }, txt(`  ${z.sub}`)))));
    }
    for (const hd of dr.heads) {
      root.append(svg("text", { class: "ld-zonetitle", x: hd.x, y: hd.y }, txt(hd.title), svg("tspan", { class: "ld-zonesub" }, txt(`  ${hd.sub}`))));
    }
    for (const e of dr.edges) {
      const d0 = pathD(trimHead(e.pts));
      root.append(svg("g", { class: "ld-edge ld-edge--flow", "data-edge": e.id, "data-lit": "false" },
        svg("path", { class: "ld-line", id: `${p}-e-${e.id}`, d: d0, "marker-end": `url(#${p}-arrow)` }),
        svg("path", { class: "li-draw", d: d0, pathLength: 1 }),
        ...(e.label && e.at ? [svg("text", { class: "ld-edgelabel", x: e.at[0], y: e.at[1], "text-anchor": e.anchor ?? "middle" }, txt(e.label))] : [])));
    }
    const dots = svg("g", { class: "li-traffic", "aria-hidden": "true" });
    for (const e of dr.edges) {
      dots.append(svg("circle", { class: e.tone === "run" ? "li-dot" : `li-dot li-dot--${e.tone}`, r: 3.4, "data-dot": e.id },
        svg("animateMotion", { dur: `${RIDE_MS / 1000}s`, begin: "indefinite", fill: "remove", calcMode: "linear" }, svg("mpath", { href: `#${p}-e-${e.id}` })),
        svg("animate", { attributeName: "opacity", values: "0;1;1;0", keyTimes: "0;0.12;0.88;1", dur: `${RIDE_MS / 1000}s`, begin: "indefinite", fill: "remove" })));
    }
    root.append(dots);
    for (const nd of nodes) {
      const b = dr.boxes.get(nd.id) as Box;
      const first = b.y + dr.headH / 2 - (nd.sub.length * LINE) / 2 + 4.5;
      const g = svg("g", { class: `ld-node ld-role--${nd.role}${nd.outcome ? " li-outcome" : ""}`, "data-node": nd.id, "data-state": "idle",
        tabindex: 0, role: "button", "aria-label": `${nd.label}: ${nd.sub.join(" · ")}`, "aria-expanded": "false", "data-tip": nd.tip },
        svg("rect", { x: b.x, y: b.y, width: b.w, height: b.h, rx: 8 }),
        svg("text", { class: "ld-label", x: cx(b), y: first }, txt(nd.label)),
        ...nd.sub.map((s, i) => svg("text", { class: "ld-sub", x: cx(b), y: first + LINE * (i + 1) }, txt(s))));
      if (nd.gauge) {
        const gy = b.y + dr.headH, pip = 14, step = 20, gx0 = b.x + 10, row = gy + 24;
        g.append(svg("line", { class: "li-gauge__sep", x1: b.x + 8, x2: right(b) - 8, y1: gy, y2: gy }));
        g.append(svg("text", { class: "li-gauge__t", x: gx0, y: gy + 16 }, txt("different hashes at the address")));
        copies.forEach((_, i) => g.append(svg("rect", { class: "li-gauge__pip", "data-pip": i, "data-on": "false", x: gx0 + i * step, y: row, width: pip, height: pip, rx: 3 })));
        const tx = gx0 + THRESHOLD * step - 3;
        g.append(svg("line", { class: "li-gauge__thr", x1: tx, x2: tx, y1: row - 4, y2: row + pip + 4 }));
        g.append(svg("text", { class: "li-gauge__t", x: gx0 + n * step + 6, y: row + 11 }, txt(`threshold ${THRESHOLD}`)));
        g.append(svg("text", { class: "li-gauge__n", x: right(b) - 10, y: row + 11, "data-count": "" }, txt(`0 < ${THRESHOLD}`)));
      }
      root.append(g);
    }
    return root;
  };

  // ---------- captions (what a click opens) ----------
  const link = (href: string, text: string): HTMLElement => h("a", { href, rel: "noopener noreferrer" }, h("code", {}, text));
  const caption = (id: string): HTMLElement[] => {
    const nd = nodeOf(id);
    const title = (sub: string): HTMLElement => h("p", { class: "ld-caption__title" }, nd.label, h("span", { class: "ld-caption__sub" }, ` · ${sub}`));
    const ci = copies.findIndex((c) => `c${c.n}` === id);
    if (ci >= 0) {
      const c = copies[ci];
      const k = new Set(copies.slice(0, ci + 1).map((x) => x.sha)).size;
      const what = role[ci] === "below" ? `${k} different hash at the address — below the monitor's threshold of ${THRESHOLD}.`
        : role[ci] === "opened" ? `${k} different hashes at one address — the monitor fired and opened the incident${delay !== null ? ` ${delay} s later` : ""}.`
        : `${k} different hashes at the address — it joined the incident copy ${openedAt} opened.`;
      return [title(`copy ${c.n} · ${c.byHash ? "hash on the IOC list" : "hash not on any list"}`),
        h("p", { class: "ld-caption__text" }, c.byHash
          ? `The copy the known-hash rule can catch: its SHA-256 is on the indicator list. It also beacons to ${beacon}, the same address as the others. ${what}`
          : `A rebuilt copy: a new SHA-256 and a new name, so the known-hash rule sees nothing. It beacons to ${beacon}, the same address as the others. ${what}`),
        h("p", { class: "li-copy__beacons" }, h("b", {}, "sha-256 "), c.sha),
        h("p", { class: "li-copy__beacons" }, h("b", {}, `${c.beacons.length} beacons `), c.beacons.map(mmss).join(" · "))];
    }
    if (id === "hash") {
      const out = [title("Sigma rule · ioc-lab-known-hash"),
        h("p", { class: "ld-caption__text" }, "A list of known-bad SHA-256 values. It fires only on a copy whose hash is on the list: every rebuilt copy has a hash nobody has seen before.")];
      if (ioc) out.push(h("div", { class: "li-rule" }, h("code", {}, `process.hash.sha256 = ${shortHash(ioc.sha)}`), h("span", {}, "one hash, one copy")));
      out.push(h("p", { class: "ld-caption__sources small" }, "On GitHub: ", link(RULE_LINKS["ioc-lab-known-hash"], "self-defending-portfolio/siem/rules/ioc-lab-known-hash.yml")));
      return out;
    }
    if (id === "sink") {
      return [title("lab-sink · a socket on siem01"),
        h("p", { class: "ld-caption__text" }, `The address every copy calls. A socket on siem01 accepts the connection and closes it, so the network events are real and nothing leaves the lab. The monitor keys on this: ${n} different programs calling one address is the behaviour, whatever they are called.`),
        h("p", { class: "ld-caption__sources small" }, "On GitHub: ", link(`${SDP}ansible/roles/lab_sink/`, "self-defending-portfolio/ansible/roles/lab_sink/"))];
    }
    if (id === "mon") {
      return [title("Alerting monitor · lab-polymorphic-beacon"),
        h("p", { class: "ld-caption__text" }, `Every minute siem01 takes the last ${WINDOW_MIN} minutes of network connections, puts each destination ip:port in a bucket of its own and counts the different program hashes in it. Two or more is one program pretending to be several: the bucket opens an incident, and every later copy that calls the same address lands in it.`),
        h("p", { class: "ld-caption__sources small" }, "The query it runs is under the figure. On GitHub: ", link(RULE_LINKS["lab-polymorphic-beacon"], "self-defending-portfolio/siem/monitors/lab-polymorphic-beacon.json"))];
    }
    return [title(openedIdx >= 0 ? (incAt !== null ? `opened at ${mmss(incAt)}, ${delay ?? "?"} s after copy ${openedAt} started` : "opened") : "nothing fired"),
      h("p", { class: "ld-caption__text" }, openedIdx >= 0
        ? `One incident holds all ${n} copies: ${hashes} different hashes, ${n} different names, one address. The monitor keys on behaviour — where a program calls — so renaming and rebuilding a copy changes nothing about where it lands.`
        : `The monitor never saw two different hashes at one address inside its ${WINDOW_MIN}-minute window, so no incident was opened in this run.`)];
  };

  // ---------- mount ----------
  const figure = h("figure", { class: "li-figure" });
  figure.append(drawing(wide()), drawing(narrow()));
  const status = h("p", { class: "ld-status li-status", "aria-live": "polite" });
  const cap = h("div", { class: "ld-caption li-caption", hidden: true });
  const replay = h("button", { type: "button", class: "btn btn--ghost btn--small li-replay" }, "↻ Replay");
  const word = (k: number): string => (k === 4 ? "four" : String(k));
  const root = h("section", { class: "li", "aria-label": "How four copies became one incident", "data-fired": "false" },
    h("p", { class: "li-lead" }, `${word(n).replace(/^./, (s) => s.toUpperCase())} names, ${word(hashes)} hashes, one address. The known-hash rule sees ${caught.length === 1 ? "one copy" : `${caught.length} copies`}; the monitor counts `,
      h("em", {}, "different programs per address"), ` and ties all ${word(n)} to one incident.`),
    figure,
    h("div", { class: "li-foot" },
      h("ul", { class: "ld-legend", "aria-label": "colour key" },
        h("li", { class: "ld-legend__item ld-role--attack" }, "copies on the VM"),
        h("li", { class: "ld-legend__item ld-role--detect" }, "rules on siem01"),
        h("li", { class: "ld-legend__item ld-role--neutral" }, "the address"),
        h("li", { class: "ld-legend__item ld-role--incident" }, "the incident")),
      replay),
    status, cap, ruleCard(ioc));

  const allNodes = [...figure.querySelectorAll<SVGElement>(".ld-node")];
  const allEdges = [...figure.querySelectorAll<SVGElement>(".ld-edge")];
  let open: string | undefined;
  const closeCaption = (): void => {
    open = undefined; cap.hidden = true; cap.replaceChildren();
    for (const el of allNodes) el.setAttribute("aria-expanded", "false");
  };
  const showCaption = (id: string): void => {
    if (open === id) { closeCaption(); return; }
    open = id;
    for (const el of allNodes) el.setAttribute("aria-expanded", String(el.dataset.node === id));
    const close = h("button", { type: "button", class: "btn btn--ghost btn--small ld-caption__close", "aria-label": "Close" }, "×");
    close.addEventListener("click", () => {
      closeCaption();
      allNodes.find((el) => el.dataset.node === id && el.getClientRects().length)?.focus({ preventScroll: true });
    });
    cap.replaceChildren(h("div", { class: "ld-caption__body" }, ...caption(id)), close);
    cap.hidden = false;
  };
  for (const el of allNodes) {
    el.addEventListener("click", () => showCaption(String(el.dataset.node)));
    el.addEventListener("keydown", (e) => {
      const k = (e as KeyboardEvent).key;
      if (k === "Enter" || k === " ") { e.preventDefault(); showCaption(String(el.dataset.node)); }
      else if (k === "Escape" && open === el.dataset.node) closeCaption();
    });
  }

  // ---------- the storyboard ----------
  const nodeState = (id: string, st: string): void => { for (const el of allNodes) if (el.dataset.node === id) el.dataset.state = st; };
  const edgeLit = (id: string, tone: string, lit = true): void => {
    for (const el of allEdges) {
      if (el.dataset.edge !== id) continue;
      el.dataset.lit = String(lit);
      if (lit) el.dataset.tone = tone; else delete el.dataset.tone;
    }
  };
  const ride = (id: string): void => {
    for (const dot of figure.querySelectorAll(`[data-dot="${id}"]`)) {
      for (const a of dot.children) (a as SVGAnimationElement).beginElement?.();
    }
  };
  const pips = (k: number): void => {
    for (const pp of figure.querySelectorAll<SVGElement>(".li-gauge__pip")) pp.dataset.on = String(Number(pp.dataset.pip) < k);
    const hk = new Set(copies.slice(0, k).map((c) => c.sha)).size;
    for (const t of figure.querySelectorAll("[data-count]")) t.textContent = `${hk} ${hk >= THRESHOLD ? "≥" : "<"} ${THRESHOLD}`;
  };
  const say = (what: string | null, text: string): void =>
    status.replaceChildren(...(what ? [h("span", { class: "ld-status__what" }, `${what}: `)] : []), text);
  const restWords = (): void => say(null, `${n} copies of one program — ${n} names, ${hashes} hashes — about to call one address, one after another.`);
  const stepWords = (i: number): void => {
    const c = copies[i];
    const k = new Set(copies.slice(0, i + 1).map((x) => x.sha)).size;
    const who = `Copy ${c.n} · ${c.name}`;
    if (role[i] === "below") {
      say(who, `beacons ${beacon}${c.byHash ? " — its hash is on the IOC list, so the known-hash rule catches it" : ""}. ${k} different hash at this address: below the threshold of ${THRESHOLD}.`);
    } else if (role[i] === "opened") {
      say(who, `a new name and a new hash, invisible to the known-hash rule — but it calls the same address. ${k} different hashes ≥ ${THRESHOLD}: the monitor fires and opens the incident` +
        `${incAt !== null ? ` at ${mmss(incAt)}` : ""}${delay !== null ? `, ${delay} s after copy ${c.n} started` : ""}.`);
    } else {
      say(who, `calls the same address: ${k} different hashes, the same incident.`);
    }
  };
  const endWords = (): void => (openedIdx >= 0
    ? say("One incident", `${n} copies, ${hashes} hashes, ${n} names, one address. The monitor keys on behaviour — where a program calls — so a new name and a new hash change nothing.`)
    : say("No incident", `the monitor never saw ${THRESHOLD} different hashes at one address within ${WINDOW_MIN} minutes.`));

  let timers: number[] = [];
  const at = (ms: number, fn: () => void): void => { timers.push(window.setTimeout(fn, ms)); };
  const reset = (): void => {
    timers.forEach(clearTimeout); timers = [];
    for (const el of allNodes) el.dataset.state = "idle";
    for (const el of allEdges) { el.dataset.lit = "false"; delete el.dataset.tone; }
    pips(0); root.dataset.fired = "false"; restWords();
  };
  const finalState = (): void => {
    reset();
    for (const c of copies) {
      nodeState(`c${c.n}`, "run"); edgeLit(`${c.n}-sink`, "run");
      if (c.byHash) { edgeLit(`${c.n}-hash`, "detect"); nodeState("hash", "detect"); }
    }
    nodeState("sink", "run"); pips(n);
    if (openedIdx >= 0) {
      edgeLit("sink-mon", "detect"); nodeState("mon", "detect"); edgeLit("mon-inc", "incident"); nodeState("inc", "incident");
      root.dataset.fired = "true";
    }
    endWords();
  };
  const play = (): void => {
    reset();
    copies.forEach((c, i) => {
      const t0 = 300 + i * STEP_MS;
      at(t0, () => { nodeState(`c${c.n}`, "run"); stepWords(i); ride(`${c.n}-sink`); if (c.byHash) ride(`${c.n}-hash`); });
      at(t0 + 120, () => { edgeLit(`${c.n}-sink`, "run"); if (c.byHash) edgeLit(`${c.n}-hash`, "detect"); });
      at(t0 + RIDE_MS, () => { nodeState("sink", "run"); pips(i + 1); if (c.byHash) nodeState("hash", "detect"); });
      if (openedIdx >= 0 && i >= openedIdx) {
        at(t0 + RIDE_MS + 80, () => { ride("sink-mon"); edgeLit("sink-mon", "detect"); });
        at(t0 + RIDE_MS * 2 + 80, () => { nodeState("mon", "detect"); ride("mon-inc"); edgeLit("mon-inc", "incident"); });
        at(t0 + RIDE_MS * 3 + 80, () => { nodeState("inc", "incident"); root.dataset.fired = "true"; });
      }
    });
    at(300 + n * STEP_MS + 1200, endWords);
  };
  const reduce = prefersReducedMotion();
  replay.addEventListener("click", () => (reduce ? finalState() : play()));
  if (reduce || typeof IntersectionObserver === "undefined") {
    finalState();
  } else {
    reset();
    // In view: a third of it, or half the screen's height of it when it is taller than three screens
    // (ASCII mode's phone drawing), so it always plays.
    const io = new IntersectionObserver((es) => {
      if (es.some((e) => e.isIntersecting && (e.intersectionRatio >= 0.35 || e.intersectionRect.height >= (e.rootBounds?.height ?? innerHeight) * 0.5))) { io.disconnect(); play(); }
    }, { threshold: [0, 0.1, 0.2, 0.35] });
    io.observe(root);
  }
  return root;
}

/** The monitor's query, line by line with its plain words, and the hash rule's for contrast. */
function ruleCard(ioc: CopyBeacon | undefined): HTMLElement {
  const row = (code: string, words: string): HTMLElement[] => [h("code", {}, code), h("span", {}, words)];
  return h("aside", { class: "li-rulecard", "aria-label": "The rule that links the copies" },
    h("div", { class: "li-rulecard__words" },
      h("p", { class: "li-rulecard__eyebrow" }, "The rule that links them"),
      h("h4", { class: "li-rulecard__t" }, "One beacon, many binaries"),
      h("p", { class: "li-rulecard__d" },
        `Every minute, siem01 takes the last ${WINDOW_MIN} minutes of network connections, puts each destination ip:port in a bucket of its own and counts the different program hashes in it. ` +
        "Two or more is one program pretending to be several: the bucket opens an incident, and every later copy that calls the same address lands in it."),
      h("p", { class: "small" }, h("a", { href: RULE_LINKS["lab-polymorphic-beacon"], rel: "noopener" }, "Monitor definition on GitHub →"))),
    h("div", { class: "li-rule", role: "group", "aria-label": "the monitor's query, line by line" },
      ...row(`WHERE  event.code = "3" AND @timestamp > now-${WINDOW_MIN}m`, `network connections, last ${WINDOW_MIN} minutes`),
      ...row("GROUP  BY destination.ip, destination.port", "one bucket per address"),
      ...row(`HAVING cardinality(process.hash.sha256) >= ${THRESHOLD}`, "two or more different programs → incident"),
      h("p", { class: "li-rule__vs" }, "For contrast, ",
        h("a", { href: RULE_LINKS["ioc-lab-known-hash"], rel: "noopener" }, "Known-bad hash"), " asks ",
        h("code", {}, ioc ? `process.hash.sha256 = ${shortHash(ioc.sha)}` : "process.hash.sha256 = <a known hash>"),
        ioc ? ` — one hash, so copy ${ioc.n} and nothing else.` : " — one hash at a time.")));
}

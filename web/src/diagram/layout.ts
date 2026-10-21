import { panelMarkup } from "../node-panel/markup";
// Draws model.ts: the wide drawing (a grid of zones), the phone's (one column, the long links in lanes
// down the margins), and the README's mermaid. Markup as strings for scripts/build.mjs, so the page
// carries the drawing before any script runs and builds no DOM for it. Colours and fonts live in
// styles.css (classes only): the page's CSP allows no style attribute.

import { EDGES, NARROW, NODES, TITLE, ZONES, describe, sourceUrl, type LabEdge, type LabNode } from "./model";

type Pt = [number, number];
interface Box {
  x: number;
  y: number;
  w: number;
  h: number;
}
interface Drawn {
  edge: LabEdge;
  pts: Pt[];
  /** The label's anchor point, or none (a lane on the phone: too narrow for words). */
  at?: Pt;
  anchor: "start" | "middle";
}
export interface Drawing {
  view: "wide" | "narrow";
  width: number;
  height: number;
  zones: { box: Box; title: string; sub: string }[];
  /** The phone's zone names, above the first box of each. */
  heads: { x: number; y: number; title: string; sub: string }[];
  boxes: Map<string, Box>;
  subs: Map<string, string[]>;
  edges: Drawn[];
}

const cx = (b: Box) => b.x + b.w / 2;
const cy = (b: Box) => b.y + b.h / 2;
const right = (b: Box) => b.x + b.w;
const bottom = (b: Box) => b.y + b.h;
/** An arrow stops this short of a box, so the head never touches it. */
const GAP = 6;
/** An arrowhead's length and the air a label keeps from it: a label over a line is centred on the shaft
 * before the head (and after the tail's, on a two-way edge), never over it. */
const HEAD = 11;
const shaftMid = (x0: number, x1: number, both: boolean): number => {
  const d = Math.sign(x1 - x0) || 1;
  return (x0 + (both ? d * (GAP + HEAD) : 0) + x1 - d * (GAP + HEAD)) / 2;
};
/** Between baselines of a box's lines. */
const LINE = 15;

/** A sublabel as lines of at most `max` characters: whole " · " parts, greedily. */
export function wrapSub(sub: string, max: number): string[] {
  const lines: string[] = [];
  for (const part of sub.split(" · ")) {
    const last = lines[lines.length - 1];
    if (last !== undefined && `${last} · ${part}`.length <= max) lines[lines.length - 1] = `${last} · ${part}`;
    else lines.push(part);
  }
  return lines.map((l, i) => (i < lines.length - 1 ? `${l} ·` : l));
}

/** Cut a path's ends GAP short of the boxes they reach (only where an arrowhead sits). */
function trim(pts: Pt[], head: boolean, tail: boolean): Pt[] {
  const out = pts.map((p) => [...p] as Pt);
  const pull = (p: Pt, toward: Pt) => {
    const dx = toward[0] - p[0];
    const dy = toward[1] - p[1];
    const len = Math.hypot(dx, dy) || 1;
    const k = Math.min(GAP, len / 3) / len;
    p[0] += dx * k;
    p[1] += dy * k;
  };
  if (tail) pull(out[0], out[1]);
  if (head) pull(out[out.length - 1], out[out.length - 2]);
  return out;
}

// ---------- the wide drawing ----------

// gx: room between columns for a label on the shaft of a two-way arrow ("tunnel") with air either side.
const W = { cw: 168, gx: 80, gy: 46, pad: 16, zoneHead: 26, zonePad: 12, subChars: 23 };

export function wide(): Drawing {
  const subs = new Map(NODES.map((n) => [n.id, wrapSub(n.sub, W.subChars)]));
  const lines = Math.max(...[...subs.values()].map((s) => s.length));
  const ch = 10 + lines * LINE + 3 + 20;
  const px = W.cw + W.gx;
  const py = ch + W.gy;
  const top = W.pad + W.zoneHead + W.zonePad;
  const left = W.pad + W.zonePad;
  const cell = ([c, r]: [number, number]): Box => ({ x: left + c * px, y: top + r * py, w: W.cw, h: ch });
  const boxes = new Map(NODES.map((n) => [n.id, cell(n.at)]));
  const zones = ZONES.map((z) => {
    const [c, r, cs, rs] = z.at;
    const b = cell([c, r]);
    return { box: { x: b.x - W.zonePad, y: b.y - W.zonePad - W.zoneHead, w: cs * px - W.gx + 2 * W.zonePad, h: rs * py - W.gy + 2 * W.zonePad + W.zoneHead }, title: z.title, sub: z.sub };
  });
  const zoneRight = Math.max(...zones.map((z) => right(z.box)));
  const zoneBottom = Math.max(...zones.map((z) => bottom(z.box)));
  const edges = EDGES.map((e): Drawn => {
    const a = boxes.get(e.from) as Box;
    const b = boxes.get(e.to) as Box;
    const r = e.route ?? "auto";
    if (r === "over") {
      // Up out of a, across above the row (under the zone's title line), down into b.
      const y = Math.min(a.y, b.y) - 22;
      return { edge: e, pts: [[cx(a), a.y], [cx(a), y], [cx(b), y], [cx(b), b.y]], at: [(cx(a) + cx(b)) / 2, y - 5], anchor: "middle" };
    }
    if (Math.abs(cy(a) - cy(b)) < 1) {
      const fwd = cx(b) > cx(a);
      const x0 = fwd ? right(a) : a.x;
      const x1 = fwd ? b.x : right(b);
      return { edge: e, pts: [[x0, cy(a)], [x1, cy(a)]], at: [shaftMid(x0, x1, !!e.both), cy(a) - 8], anchor: "middle" };
    }
    if (Math.abs(cx(a) - cx(b)) < 1) {
      const down = cy(b) > cy(a);
      const y0 = down ? bottom(a) : a.y;
      const y1 = down ? b.y : bottom(b);
      return { edge: e, pts: [[cx(a), y0], [cx(a), y1]], at: [cx(a) + 9, (y0 + y1) / 2 + 4], anchor: "start" };
    }
    const down = cy(b) > cy(a);
    const fwd = cx(b) > cx(a);
    if (r === "hv") {
      const x0 = fwd ? right(a) : a.x;
      return { edge: e, pts: [[x0, cy(a)], [cx(b), cy(a)], [cx(b), down ? b.y : bottom(b)]], at: [(x0 + cx(b)) / 2, cy(a) - 8], anchor: "middle" };
    }
    // vh: out of a's bottom or top (off-centre), along to b's row, into its side.
    const x0 = cx(a) + 14;
    const x1 = fwd ? b.x : right(b);
    return { edge: e, pts: [[x0, down ? bottom(a) : a.y], [x0, cy(b)], [x1, cy(b)]], at: [shaftMid(x0, x1, false), cy(b) - 8], anchor: "middle" };
  });
  return { view: "wide", width: zoneRight + W.pad, height: zoneBottom + W.pad, zones, heads: [], boxes, subs, edges };
}

// ---------- the phone's drawing ----------

const N = { x: 40, w: 256, gap: 28, head: 30, pad: 10, subChars: 36, lane: 11 };

export function narrow(): Drawing {
  const nodes = NARROW.map((id) => NODES.find((n) => n.id === id) as LabNode);
  const subs = new Map(nodes.map((n) => [n.id, wrapSub(n.sub, N.subChars)]));
  // Each box as tall as its own words: the column is long, so no box carries another's spare line.
  const heightOf = (id: string) => 10 + (subs.get(id) as string[]).length * LINE + 3 + 18;
  const boxes = new Map<string, Box>();
  const heads: Drawing["heads"] = [];
  let y = N.pad;
  let zone = "";
  for (const n of nodes) {
    const id = n.id;
    if (n.zone !== zone) {
      zone = n.zone;
      const z = ZONES.find((zz) => zz.id === zone);
      if (heads.length) y += 8;
      heads.push({ x: N.x, y: y + 12, title: z?.title ?? zone, sub: z?.subNarrow ?? "" });
      y += N.head - 6;
    }
    const h = heightOf(id);
    boxes.set(id, { x: N.x, y, w: N.w, h });
    y += h + N.gap;
  }
  const order = new Map(NARROW.map((id, i) => [id, i]));
  // The long links run in lanes, the left margin downwards and the right one upwards; links whose
  // spans overlap get lanes of their own, and each enters its box at its own height.
  const lanes = { left: [] as number[], right: [] as number[] };
  const laneOf = (side: "left" | "right", from: number, to: number): number => {
    const lo = Math.min(from, to);
    const hi = Math.max(from, to);
    const ends = lanes[side];
    let i = ends.findIndex((end) => end <= lo);
    if (i < 0) i = ends.push(hi) - 1;
    else ends[i] = hi;
    return i;
  };
  const drawn = EDGES.filter((e) => order.has(e.from) && order.has(e.to));
  const long = drawn.filter((e) => Math.abs((order.get(e.to) as number) - (order.get(e.from) as number)) > 1);
  long.sort((p, q) => Math.min(order.get(p.from) as number, order.get(p.to) as number) - Math.min(order.get(q.from) as number, order.get(q.to) as number));
  const laneIdx = new Map(long.map((e) => {
    const a = order.get(e.from) as number;
    const b = order.get(e.to) as number;
    return [e, laneOf(b > a ? "left" : "right", a, b)] as const;
  }));
  const edges = drawn.map((e): Drawn => {
    const a = boxes.get(e.from) as Box;
    const b = boxes.get(e.to) as Box;
    const lane = laneIdx.get(e);
    if (lane === undefined) {
      // Next in line: straight down (or up) the middle.
      const [y0, y1] = b.y > a.y ? [bottom(a), b.y] : [a.y, bottom(b)];
      return { edge: e, pts: [[cx(a), y0], [cx(a), y1]], at: [cx(a) + 9, (y0 + y1) / 2 + 4], anchor: "start" };
    }
    // Each lane enters and leaves its boxes at its own height, so two lanes never share an end.
    const dy = -6 + 6 * lane;
    if (b.y > a.y) {
      const x = a.x - N.lane * (lane + 1);
      return { edge: e, pts: [[a.x, cy(a) + dy], [x, cy(a) + dy], [x, cy(b) + dy], [b.x, cy(b) + dy]], anchor: "start" };
    }
    const x = right(a) + N.lane * (lane + 1);
    return { edge: e, pts: [[right(a), cy(a) + dy], [x, cy(a) + dy], [x, cy(b) + dy], [right(b), cy(b) + dy]], anchor: "start" };
  });
  return { view: "narrow", width: N.x + N.w + N.lane * lanes.right.length + 10, height: y - N.gap + N.pad, zones: [], heads, boxes, subs, edges };
}

// ---------- markup ----------

const ESC: Record<string, string> = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
const esc = (s: string) => s.replace(/[&<>"']/g, (c) => ESC[c]);
const r1 = (n: number) => String(Math.round(n * 10) / 10);
type Attrs = Record<string, string | number | undefined>;
function el(tag: string, attrs: Attrs, ...children: string[]): string {
  const a = Object.entries(attrs)
    .filter(([, v]) => v !== undefined)
    .map(([k, v]) => ` ${k}="${esc(typeof v === "number" ? r1(v) : String(v))}"`)
    .join("");
  return children.length ? `<${tag}${a}>${children.join("")}</${tag}>` : `<${tag}${a}/>`;
}
const pathD = (pts: Pt[]) => pts.map(([x, y], i) => `${i ? "L" : "M"}${r1(x)} ${r1(y)}`).join(" ");

/** A blurb's first sentence (two when the first is a word or two): the short words ASCII mode's popup
 * shows beside a box (data-tip). */
export function firstSentence(s: string): string {
  let out = "";
  for (const x of s.match(/.*?[.!?](?=\s|$)/g) ?? [s]) { out += x; if (out.trim().length >= 30) break; }
  return out.trim() || s;
}

/** A node is a button (ui/diagram.ts opens its caption): focusable, named, collapsed at rest. */
function nodeMarkup(n: LabNode, b: Box, subs: string[]): string {
  const first = cy(b) - (subs.length * LINE) / 2 + 4.5;
  return el(
    "g",
    { class: `ld-node ld-role--${n.role}`, "data-node": n.id, "data-state": "idle", tabindex: 0, role: "button", "aria-label": `${n.label}: ${n.sub}`, "aria-expanded": "false", "data-tip": firstSentence(n.blurb) },
    el("rect", { x: b.x, y: b.y, width: b.w, height: b.h, rx: 8 }),
    el("text", { class: "ld-label", x: cx(b), y: first }, esc(n.label)),
    ...subs.map((s, i) => el("text", { class: "ld-sub", x: cx(b), y: first + LINE * (i + 1) }, esc(s))),
  );
}

function edgeMarkup(d: Drawn, marker: string, prefix: string): string {
  const pts = trim(d.pts, true, !!d.edge.both);
  const id = `${d.edge.from}-${d.edge.to}`;
  const lane = laneOf(id);
  return el(
    "g",
    { class: `ld-edge ld-edge--${d.edge.kind}`, "data-edge": id, "data-lit": "false" },
    el("path", { class: "ld-line", d: pathD(pts), "marker-end": `url(#${marker})`, "marker-start": d.edge.both ? `url(#${marker})` : undefined }),
    // Brightens while the traffic's dot passes (styles.css, timing from trafficCss).
    lane ? el("path", { class: `ld-glow ld-glow--${lane}`, id: `${prefix}-glow-${id}`, d: pathD(pts) }) : "",
    d.at ? el("text", { class: "ld-edgelabel", x: d.at[0], y: d.at[1], "text-anchor": d.anchor }, esc(d.edge.label)) : "",
  );
}

/** One drawing as an inline <svg>, with its own ids (two sit on the page). */
export function svg(dr: Drawing): string {
  const p = dr.view === "wide" ? "ld" : "ldn";
  const marker = `${p}-arrow`;
  const zones = dr.zones.map((z) =>
    el("g", { class: "ld-zone" }, el("rect", { x: z.box.x, y: z.box.y, width: z.box.w, height: z.box.h, rx: 10 }), el("text", { class: "ld-zonetitle", x: z.box.x + 12, y: z.box.y + 18 }, esc(z.title), z.sub ? el("tspan", { class: "ld-zonesub" }, esc(`  ${z.sub}`)) : "")),
  );
  const heads = dr.heads.map((hd) => el("text", { class: "ld-zonetitle", x: hd.x, y: hd.y }, esc(hd.title), hd.sub ? el("tspan", { class: "ld-zonesub" }, esc(`  ${hd.sub}`)) : ""));
  return el(
    "svg",
    { class: `lab-diagram__svg lab-diagram__svg--${dr.view}`, viewBox: `0 0 ${r1(dr.width)} ${r1(dr.height)}`, role: "group", "aria-labelledby": `${p}-title ${p}-desc` },
    el("title", { id: `${p}-title` }, esc(TITLE)),
    el("desc", { id: `${p}-desc` }, esc(describe())),
    el("defs", {}, el("marker", { id: marker, viewBox: "0 0 10 10", refX: 9, refY: 5, markerWidth: 8, markerHeight: 8, markerUnits: "userSpaceOnUse", orient: "auto-start-reverse" }, el("path", { class: "ld-head", d: "M0,1 L10,5 L0,9 z" }))),
    ...zones,
    ...heads,
    ...dr.edges.map((d) => edgeMarkup(d, marker, p)),
    // Above the edges, under the boxes: a dot sinks into a box and comes out the other side.
    el("g", { class: "ld-traffic", "aria-hidden": "true" }, ...(Object.keys(TRAFFIC) as Lane[]).map((l) => el("circle", { class: `ld-dot ld-dot--${l}`, id: `${p}-dot-${l}`, r: 3.2 }))),
    ...NODES.filter((n) => dr.boxes.has(n.id)).map((n) => nodeMarkup(n, dr.boxes.get(n.id) as Box, dr.subs.get(n.id) as string[])),
  );
}

// ---------- the traffic ----------

/**
 * What moves, as on /cluster/ and the landing page: at rest a dot runs the way in, the visitor to
 * this page, every few seconds; while a run is live (ui/diagram.ts sets data-run="active") a dot runs
 * the run's path instead, the VM through siem01 to the API. Each edge it passes brightens for a
 * moment. The routes and timing go into a stylesheet (trafficCss) the build bundles with styles.css:
 * the page's CSP allows no style attribute, and offset-path needs the route. styles.css runs them only
 * when motion is welcome.
 */
export const TRAFFIC = {
  in: { edges: ["visitor-edge", "edge-cloudflared", "cloudflared-gateway", "gateway-page"], period: 3.6, travel: 2.6 },
  run: { edges: ["vm-stream", "stream-detector", "detector-validator", "validator-runs", "runs-api"], period: 4.8, travel: 3.8 },
} as const;
export type Lane = keyof typeof TRAFFIC;

const laneOf = (edgeId: string): Lane | undefined => (Object.keys(TRAFFIC) as Lane[]).find((l) => (TRAFFIC[l].edges as readonly string[]).includes(edgeId));

/** One drawing's lanes: each dot's offset-path (from the first box's centre along the lane's edges into
 * the last box's centre) and keyframes, each edge's brightening while the dot is on it. */
function laneCss(dr: Drawing): string {
  const p = dr.view === "wide" ? "ld" : "ldn";
  const css: string[] = [];
  const pct = (n: number) => `${Math.round(Math.min(100, Math.max(0, n)) * 100) / 100}%`;
  for (const lane of Object.keys(TRAFFIC) as Lane[]) {
    const L = TRAFFIC[lane];
    const segs = L.edges.map((id) => dr.edges.find((d) => `${d.edge.from}-${d.edge.to}` === id)).map((d) => (d ? trim(d.pts, true, !!d.edge.both) : undefined));
    if (segs.some((sg) => !sg)) continue;
    const first = dr.boxes.get(L.edges[0].split("-")[0]) as Box;
    const lastEdge = dr.edges.find((d) => `${d.edge.from}-${d.edge.to}` === L.edges[L.edges.length - 1]) as Drawn;
    const last = dr.boxes.get(lastEdge.edge.to) as Box;
    const pts: Pt[] = [[cx(first), cy(first)], ...(segs as Pt[][]).flat(), [cx(last), cy(last)]];
    const len = (a: Pt, b: Pt) => Math.hypot(b[0] - a[0], b[1] - a[1]);
    let total = 0;
    for (let i = 1; i < pts.length; i++) total += len(pts[i - 1], pts[i]);
    // Where each edge starts and ends along the whole route, as fractions.
    const span: [number, number][] = [];
    let at = len(pts[0], (segs[0] as Pt[])[0]);
    (segs as Pt[][]).forEach((sg, k) => {
      let l = 0;
      for (let i = 1; i < sg.length; i++) l += len(sg[i - 1], sg[i]);
      span.push([at / total, (at + l) / total]);
      at += l;
      const next = (segs as Pt[][])[k + 1];
      if (next) at += len(sg[sg.length - 1], next[0]);
    });
    const t = (f: number) => (L.travel * f * 100) / L.period;
    const name = `ld-tr-${p}-${lane}`;
    css.push(`#${p}-dot-${lane} { offset-path: path("${pts.map(([x, y], i) => `${i ? "L" : "M"}${r1(x)} ${r1(y)}`).join(" ")}"); --tr-name: ${name}; --tr-period: ${L.period}s; }`);
    css.push(`@keyframes ${name} { 0% { offset-distance: 0%; opacity: 0; } ${pct(t(0.06))} { opacity: 1; } ${pct(t(0.94))} { opacity: 1; } ${pct(t(1))}, 100% { offset-distance: 100%; opacity: 0; } }`);
    L.edges.forEach((id, k) => {
      const [s0, s1] = span[k];
      const g = `ld-tr-${p}-${id}`;
      css.push(`#${p}-glow-${id} { --tr-name: ${g}; --tr-period: ${L.period}s; }`);
      css.push(`@keyframes ${g} { 0%, ${pct(t(s0) - 0.5)} { opacity: 0; } ${pct(t(s0) + 1)}, ${pct(t(s1))} { opacity: 1; } ${pct(t(s1) + 8)}, 100% { opacity: 0; } }`);
    });
  }
  return css.join("\n");
}

/** The traffic's stylesheet for both drawings (styles.css imports it; the build supplies it). */
export function trafficCss(): string {
  return ["/* Generated by src/diagram/layout.ts (trafficCss) at build time: the diagram traffic's routes. */", laneCss(wide()), laneCss(narrow()), ""].join("\n");
}

// ---------- the README's copy ----------

const mid = (id: string) => id.replace(/[^\w]/g, "_");
const mtext = (s: string) => s.replace(/"/g, "'");

/** The same model as a mermaid flowchart, for README.md's "How it fits together". */
export function mermaid(): string {
  const out = ["flowchart LR"];
  for (const z of ZONES) {
    out.push(`    subgraph ${mid(z.id)}["${mtext(z.title)}${z.sub ? ` · ${mtext(z.sub)}` : ""}"]`);
    for (const n of NODES.filter((m) => m.zone === z.id)) out.push(`        ${mid(n.id)}["${mtext(n.label)}<br/>${mtext(n.sub)}"]`);
    out.push("    end");
  }
  for (const e of EDGES) {
    const [l, r] = e.kind === "side" ? ["-.", ".->"] : ["--", "-->"];
    out.push(`    ${mid(e.from)} ${e.both ? "<" : ""}${l} "${mtext(e.label)}" ${r} ${mid(e.to)}`);
  }
  return out.join("\n");
}

// ---------- the node panel ----------

/** The node panel under both drawings (src/node-panel): each part's words, and where it lives on GitHub. */
export function panel(): string {
  return panelMarkup(
    "lab",
    NODES.map((n) => ({
      id: n.id,
      title: n.label,
      sub: n.sub,
      text: n.blurb,
      role: n.role,
      linksLead: "On GitHub: ",
      links: n.sources.map((s) => {
        const [repo, ...path] = s.split(":");
        return { href: sourceUrl(s), label: `${repo === "sdp" ? "self-defending-portfolio" : "detection-lab"}/${path.join(":")}` };
      }),
    })),
  );
}

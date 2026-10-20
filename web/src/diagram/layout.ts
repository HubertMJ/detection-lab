// Draws model.ts: the wide drawing (a grid of zones), the phone's (one column, the long links in lanes
// down the margins), and the README's mermaid. Markup as strings for scripts/build.mjs, so the page
// carries the drawing before any script runs and builds no DOM for it. Colours and fonts live in
// styles.css (classes only): the page's CSP allows no style attribute.

import { EDGES, NARROW, NODES, TITLE, ZONES, describe, type LabEdge, type LabNode } from "./model";

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

const W = { cw: 168, gx: 52, gy: 46, pad: 16, zoneHead: 26, zonePad: 12, subChars: 23 };

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
    if (r === "around") {
      // Out of a's bottom, under every zone, up past the right edge, into b's right side.
      const yb = zoneBottom + 14;
      const xr = zoneRight + 14;
      return { edge: e, pts: [[cx(a), bottom(a)], [cx(a), yb], [xr, yb], [xr, cy(b)], [right(b), cy(b)]], at: [(cx(a) + xr) / 2, yb + 15], anchor: "middle" };
    }
    if (Math.abs(cy(a) - cy(b)) < 1) {
      const fwd = cx(b) > cx(a);
      const x0 = fwd ? right(a) : a.x;
      const x1 = fwd ? b.x : right(b);
      return { edge: e, pts: [[x0, cy(a)], [x1, cy(a)]], at: [(x0 + x1) / 2, cy(a) - 8], anchor: "middle" };
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
    return { edge: e, pts: [[x0, down ? bottom(a) : a.y], [x0, cy(b)], [x1, cy(b)]], at: [(x0 + x1) / 2, cy(b) - 8], anchor: "middle" };
  });
  return { view: "wide", width: zoneRight + 14 + W.pad, height: zoneBottom + 14 + 22, zones, heads: [], boxes, subs, edges };
}

// ---------- the phone's drawing ----------

const N = { x: 40, w: 256, h: 0, gap: 30, head: 30, pad: 10, subChars: 36, lane: 11 };

export function narrow(): Drawing {
  const subs = new Map(NODES.map((n) => [n.id, wrapSub(n.sub, N.subChars)]));
  const lines = Math.max(...[...subs.values()].map((s) => s.length));
  const h = 10 + lines * LINE + 3 + 18;
  const boxes = new Map<string, Box>();
  const heads: Drawing["heads"] = [];
  let y = N.pad;
  let zone = "";
  for (const id of NARROW) {
    const n = NODES.find((m) => m.id === id) as LabNode;
    if (n.zone !== zone) {
      zone = n.zone;
      const z = ZONES.find((zz) => zz.id === zone);
      if (heads.length) y += 8;
      heads.push({ x: N.x, y: y + 12, title: z?.title ?? zone, sub: z?.subNarrow ?? "" });
      y += N.head - 6;
    }
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
  const long = EDGES.filter((e) => Math.abs((order.get(e.to) as number) - (order.get(e.from) as number)) > 1);
  long.sort((p, q) => Math.min(order.get(p.from) as number, order.get(p.to) as number) - Math.min(order.get(q.from) as number, order.get(q.to) as number));
  const laneIdx = new Map(long.map((e) => {
    const a = order.get(e.from) as number;
    const b = order.get(e.to) as number;
    return [e, laneOf(b > a ? "left" : "right", a, b)] as const;
  }));
  const edges = EDGES.map((e): Drawn => {
    const a = boxes.get(e.from) as Box;
    const b = boxes.get(e.to) as Box;
    const lane = laneIdx.get(e);
    if (lane === undefined) {
      // Next in line: straight down (or up) the middle.
      const [y0, y1] = b.y > a.y ? [bottom(a), b.y] : [a.y, bottom(b)];
      return { edge: e, pts: [[cx(a), y0], [cx(a), y1]], at: [cx(a) + 9, (y0 + y1) / 2 + 4], anchor: "start" };
    }
    const dy = lane === 0 ? -6 : 6;
    if (b.y > a.y) {
      const x = a.x - N.lane * (lane + 1);
      return { edge: e, pts: [[a.x, cy(a) + dy], [x, cy(a) + dy], [x, cy(b) + dy], [b.x, cy(b) + dy]], anchor: "start" };
    }
    const x = right(a) + N.lane * (lane + 1);
    return { edge: e, pts: [[right(a), cy(a) + dy], [x, cy(a) + dy], [x, cy(b) + dy], [right(b), cy(b) + dy]], anchor: "start" };
  });
  return { view: "narrow", width: N.x + N.w + 30, height: y - N.gap + N.pad, zones: [], heads, boxes, subs, edges };
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

function nodeMarkup(n: LabNode, b: Box, subs: string[]): string {
  const first = cy(b) - (subs.length * LINE) / 2 + 4.5;
  return el(
    "g",
    { class: `ld-node ld-role--${n.role}`, "data-node": n.id },
    el("rect", { x: b.x, y: b.y, width: b.w, height: b.h, rx: 8 }),
    el("text", { class: "ld-label", x: cx(b), y: first }, esc(n.label)),
    ...subs.map((s, i) => el("text", { class: "ld-sub", x: cx(b), y: first + LINE * (i + 1) }, esc(s))),
  );
}

function edgeMarkup(d: Drawn, marker: string): string {
  const pts = trim(d.pts, true, !!d.edge.both);
  return el(
    "g",
    { class: `ld-edge ld-edge--${d.edge.kind}`, "data-edge": `${d.edge.from}-${d.edge.to}` },
    el("path", { class: "ld-line", d: pathD(pts), "marker-end": `url(#${marker})`, "marker-start": d.edge.both ? `url(#${marker})` : undefined }),
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
    { class: `lab-diagram__svg lab-diagram__svg--${dr.view}`, viewBox: `0 0 ${r1(dr.width)} ${r1(dr.height)}`, role: "img", "aria-labelledby": `${p}-title ${p}-desc` },
    el("title", { id: `${p}-title` }, esc(TITLE)),
    el("desc", { id: `${p}-desc` }, esc(describe())),
    el("defs", {}, el("marker", { id: marker, viewBox: "0 0 10 10", refX: 9, refY: 5, markerWidth: 8, markerHeight: 8, markerUnits: "userSpaceOnUse", orient: "auto-start-reverse" }, el("path", { class: "ld-head", d: "M0,1 L10,5 L0,9 z" }))),
    ...zones,
    ...heads,
    ...dr.edges.map((d) => edgeMarkup(d, marker)),
    ...NODES.map((n) => nodeMarkup(n, dr.boxes.get(n.id) as Box, dr.subs.get(n.id) as string[])),
  );
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

// The hero's architecture diagram, as /cluster/'s (self-defending-portfolio app/web/src/ui/diagram.ts):
// the SVG is in the static HTML (scripts/build.mjs draws it from src/diagram at build time, so it is
// there without JavaScript); this module attaches behaviour to it by node id. A node opens a caption
// under the drawing - what it is and where it lives on GitHub - by click, tap, Enter or Space. The run
// lights its path from what the page knows (the run control, the VM's state, the live records), and a
// validated run replays its path once, box by box.
//
// Honest motion: a box lights when the run's state says so and stays lit. The only loops are the
// traffic dots (styles.css, routes from src/diagram/layout.ts), off screen, in a hidden tab and under
// reduced motion stopped. Nothing here scrolls the page or moves the layout.

import { NODES, sourceUrl, type LabNode } from "../diagram/model";
import { h, prefersReducedMotion, replace } from "../lib/dom";

export type NodeState = "idle" | "run" | "detect" | "record" | "deliver";
export type EdgeTone = Exclude<NodeState, "idle">;
/** Where a run is: none, asked for, the VM resetting, running, powered off awaiting its verdict, validated. */
export type RunPhase = "idle" | "queued" | "starting" | "running" | "shipped" | "validated";

/** The validated run's path, in the order it travelled: what the replay lights, one step at a time. */
export const RUN_PATH: { node: string; state: EdgeTone; edge?: string }[] = [
  { node: "vm", state: "run" },
  { node: "stream", state: "record", edge: "vm-stream" },
  { node: "detector", state: "detect", edge: "stream-detector" },
  { node: "validator", state: "record", edge: "detector-validator" },
  { node: "runs", state: "record", edge: "validator-runs" },
  { node: "api", state: "deliver", edge: "runs-api" },
  { node: "page", state: "deliver", edge: "page-api" },
];

/** The boxes and edges a phase lights, and the status line's words for it. */
export function phaseOf(phase: RunPhase): { nodes: Map<string, NodeState>; edges: Map<string, EdgeTone>; summary: string } {
  const nodes = new Map<string, NodeState>();
  const edges = new Map<string, EdgeTone>();
  const light = (ids: string[], st: EdgeTone) => ids.forEach((id) => nodes.set(id, st));
  const lit = (ids: string[], tone: EdgeTone) => ids.forEach((id) => edges.set(id, tone));
  if (phase === "idle") return { nodes, edges, summary: "" };
  if (phase === "validated") {
    for (const s of RUN_PATH) {
      nodes.set(s.node, s.state);
      if (s.edge) edges.set(s.edge, s.state);
    }
    return { nodes, edges, summary: "validated - its events reached siem01, the rules caught them, the run document came back here" };
  }
  // Every live phase: a run was asked for or is on, and the trigger collected it.
  light(["page", "api"], "deliver");
  lit(["page-api"], "deliver");
  if (phase === "queued") {
    light(["trigger"], "run");
    lit(["trigger-edge"], "run");
    return { nodes, edges, summary: "a run is queued: the Proxmox host collects it within seconds" };
  }
  // Started by the daily timer or by a visitor's request: the page cannot tell which, so neither is lit.
  light(["reset", "vm"], "run");
  lit(["reset-vm"], "run");
  if (phase === "starting") return { nodes, edges, summary: "the VM is rolled back to its clean snapshot and starting" };
  light(["stream"], "record");
  lit(["vm-stream"], "record");
  if (phase === "running") return { nodes, edges, summary: "the VM is running the four copies; their events reach siem01 as they happen" };
  light(["detector"], "detect");
  light(["validator"], "record");
  lit(["stream-detector"], "detect");
  lit(["detector-validator"], "record");
  return { nodes, edges, summary: "the VM has powered off; the validator is judging what the SIEM caught" };
}

const nodeMeta = (id: string): LabNode | undefined => NODES.find((n) => n.id === id);

/** The caption for a node: its words and where it lives, a link per source. */
export function renderCaption(n: LabNode): HTMLElement {
  return h(
    "div",
    { class: "ld-caption__body" },
    h("p", { class: "ld-caption__title" }, n.label, n.sub ? h("span", { class: "ld-caption__sub" }, ` · ${n.sub}`) : null),
    h("p", { class: "ld-caption__text" }, n.blurb),
    n.sources.length
      ? h(
          "p",
          { class: "ld-caption__sources small" },
          "On GitHub: ",
          ...n.sources.flatMap((s, i) => {
            const [repo, ...path] = s.split(":");
            return [i ? ", " : "", h("a", { href: sourceUrl(s), rel: "noopener noreferrer" }, h("code", {}, `${repo === "sdp" ? "self-defending-portfolio" : "detection-lab"}/${path.join(":")}`))];
          }),
        )
      : null,
  );
}

export interface DiagramHandle {
  /** Where the run is now; the same phase twice changes nothing. */
  setPhase(phase: RunPhase): void;
  /** A validated run is on screen: replay its path once (at once under reduced motion), then rest. */
  replay(): void;
  show(nodeId: string): void;
}

const STEP_MS = 420;
const HOLD_MS = 4000;

/** `figure` holds the two drawings (wide and phone); `caption` and `status` are mounts under them. */
export function mountDiagram(figure: HTMLElement, opts: { caption: HTMLElement; status: HTMLElement }): DiagramHandle {
  const allNodes = [...figure.querySelectorAll<SVGGElement>(".ld-node")];
  const allEdges = [...figure.querySelectorAll<SVGGElement>(".ld-edge")];
  const nodeEls = (id: string) => allNodes.filter((el) => el.dataset.node === id);
  let open: string | undefined;

  const closeCaption = () => {
    open = undefined;
    opts.caption.hidden = true;
    replace(opts.caption);
    for (const el of allNodes) el.setAttribute("aria-expanded", "false");
  };

  const show = (id: string) => {
    const n = nodeMeta(id);
    if (!n) return;
    if (open === id) return closeCaption();
    open = id;
    for (const el of allNodes) el.setAttribute("aria-expanded", String(el.dataset.node === id));
    const close = h("button", { type: "button", class: "btn btn--ghost btn--small ld-caption__close", "aria-label": "Close" }, "×");
    close.addEventListener("click", () => {
      closeCaption();
      nodeEls(id).find((el) => el.getClientRects().length)?.focus({ preventScroll: true });
    });
    replace(opts.caption, renderCaption(n), close);
    opts.caption.hidden = false;
  };

  for (const el of allNodes) {
    const id = el.dataset.node ?? "";
    el.addEventListener("click", () => show(id));
    el.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        show(id);
      } else if (e.key === "Escape" && open === id) closeCaption();
    });
  }

  // The traffic runs only while the figure is on screen in a visible tab.
  let onScreen = true;
  const ambient = () => {
    figure.dataset.ambient = onScreen && !document.hidden ? "on" : "off";
  };
  if (typeof IntersectionObserver === "function") {
    new IntersectionObserver((entries) => {
      for (const e of entries) onScreen = e.isIntersecting;
      ambient();
    }).observe(figure);
  }
  document.addEventListener("visibilitychange", ambient);
  ambient();

  const paint = (nodes: Map<string, NodeState>, edges: Map<string, EdgeTone>) => {
    for (const el of allNodes) el.dataset.state = nodes.get(el.dataset.node ?? "") ?? "idle";
    for (const el of allEdges) {
      const tone = edges.get(el.dataset.edge ?? "");
      el.dataset.lit = String(tone !== undefined);
      if (tone) el.dataset.tone = tone;
      else delete el.dataset.tone;
    }
  };

  const REST = "The way in, and how a run reaches this page. ";
  const say = (what: string | null, summary: string) => {
    if (!what) replace(opts.status, REST, h("span", { class: "needs-js" }, "Pick a part to read what it is and where it lives."));
    else replace(opts.status, h("span", { class: "ld-status__what" }, `${what}: `), summary, ".");
  };

  let phase: RunPhase = "idle";
  let timers: number[] = [];
  const stopReplay = () => {
    for (const t of timers) clearTimeout(t);
    timers = [];
  };

  const setPhase = (next: RunPhase) => {
    if (next === phase && next !== "validated") return;
    stopReplay();
    phase = next;
    const live = next !== "idle" && next !== "validated";
    figure.dataset.run = live ? "active" : next === "validated" ? "over" : "none";
    const { nodes, edges, summary } = phaseOf(next);
    paint(nodes, edges);
    if (next === "idle") say(null, "");
    else say(live ? "Live run" : "Latest run", summary);
  };

  const replay = () => {
    stopReplay();
    phase = "validated";
    figure.dataset.run = "over";
    const { summary } = phaseOf("validated");
    say("Latest run", summary);
    if (prefersReducedMotion()) {
      const all = phaseOf("validated");
      paint(all.nodes, all.edges);
      return;
    }
    const nodes = new Map<string, NodeState>();
    const edges = new Map<string, EdgeTone>();
    RUN_PATH.forEach((s, i) => {
      timers.push(
        window.setTimeout(() => {
          nodes.set(s.node, s.state);
          if (s.edge) edges.set(s.edge, s.state);
          paint(nodes, edges);
        }, i * STEP_MS),
      );
    });
    // Then back to rest, where the way in carries the traffic again.
    timers.push(
      window.setTimeout(() => {
        phase = "idle";
        figure.dataset.run = "none";
        paint(new Map(), new Map());
        say(null, "");
      }, RUN_PATH.length * STEP_MS + HOLD_MS),
    );
  };

  say(null, "");
  return { setPhase, replay, show };
}

// The lab's architecture diagram (src/diagram): the model is consistent, both drawings carry every
// node and edge without a style attribute or a script, nothing public names an internal address or
// VLAN, and README.md's mermaid is what the model generates.

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { EDGES, NARROW, NODES, ZONES, validate } from "../../src/diagram/model";
import { mermaid, narrow, svg, wide, wrapSub } from "../../src/diagram/layout";

describe("the lab diagram's model", () => {
  it("is consistent: known zones and nodes, the phone order holds every node once", () => {
    expect(validate()).toEqual([]);
  });

  it("draws the run end to end: both triggers, the VM, the SIEM's stream, detections and validator, the API and the page; variant A beside it", () => {
    const edge = (from: string, to: string) => EDGES.some((e) => e.from === from && e.to === to);
    expect(edge("timer", "reset") && edge("agent", "reset") && edge("reset", "vm")).toBe(true);
    expect(edge("vm", "stream") && edge("vm", "sink") && edge("stream", "detector") && edge("detector", "validator")).toBe(true);
    expect(edge("validator", "runs") && edge("runs", "api") && edge("page", "api")).toBe(true);
    expect(edge("runner", "stream")).toBe(true);
    // The agent only ever calls out: its one link to the cluster is its own poll.
    expect(EDGES.filter((e) => e.to === "agent")).toEqual([]);
    expect(edge("agent", "api")).toBe(true);
    for (const id of ["timer", "agent", "reset", "vm"]) expect(NODES.find((n) => n.id === id)?.zone).toBe("pve");
    for (const id of ["stream", "sink", "detector", "validator", "runs"]) expect(NODES.find((n) => n.id === id)?.zone).toBe("siem");
    for (const id of ["runner", "api", "page"]) expect(NODES.find((n) => n.id === id)?.zone).toBe("k3s");
  });

  it("names no internal address or VLAN (the page is public)", () => {
    const text = JSON.stringify({ ZONES, NODES, EDGES }) + svg(wide()) + svg(narrow());
    expect(text).not.toMatch(/\b10\.\d+\.\d+\.\d+\b|\b192\.168\.|VLAN/i);
  });
});

describe("the drawings", () => {
  for (const dr of [wide(), narrow()]) {
    it(`${dr.view}: an img svg with a title and description, a group per node and edge, no style or script`, () => {
      const s = svg(dr);
      expect(s).toMatch(new RegExp(`^<svg class="lab-diagram__svg lab-diagram__svg--${dr.view}" viewBox="0 0 [\\d.]+ [\\d.]+" role="img"`));
      expect(s).toContain("<title");
      expect(s).toContain("<desc");
      expect(s).not.toMatch(/ style=|<style|<script|<foreignObject| on\w+=/i);
      for (const n of NODES) expect(s).toContain(`data-node="${n.id}"`);
      for (const e of EDGES) expect(s).toContain(`data-edge="${e.from}-${e.to}"`);
      expect((s.match(/class="ld-edge ld-edge--side"/g) ?? []).length).toBe(EDGES.filter((e) => e.kind === "side").length);
    });

    it(`${dr.view}: every box inside the drawing, no two boxes overlapping`, () => {
      const boxes = [...dr.boxes.values()];
      for (const b of boxes) {
        expect(b.x).toBeGreaterThanOrEqual(0);
        expect(b.y).toBeGreaterThanOrEqual(0);
        expect(b.x + b.w).toBeLessThanOrEqual(dr.width);
        expect(b.y + b.h).toBeLessThanOrEqual(dr.height);
      }
      for (const [i, a] of boxes.entries()) for (const b of boxes.slice(i + 1)) expect(a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h).toBe(false);
    });
  }

  it("the phone draws every node in its order, top to bottom", () => {
    const ys = NARROW.map((id) => narrow().boxes.get(id)?.y ?? -1);
    expect([...ys].sort((p, q) => p - q)).toEqual(ys);
  });

  it("a long sublabel wraps at its separators", () => {
    expect(wrapSub("VM 122 · Sysmon for Linux · Fluent Bit", 23)).toEqual(["VM 122 ·", "Sysmon for Linux ·", "Fluent Bit"]);
  });
});

// The image build sees web/ only, without README.md: there the check cannot run. CI runs it on every
// pull request (build-image.yml), and `npm run diagram -- --check` does the same from web/.
const README = join(process.cwd(), "..", "README.md");

describe("README.md's diagram is generated from the model", () => {
  it.skipIf(!existsSync(README))("the committed block matches `npm run diagram` (run it when this fails)", () => {
    const text = readFileSync(README, "utf8");
    const block = text.split("<!-- diagram: generated from web/src/diagram/model.ts")[1]?.split("<!-- /diagram -->")[0] ?? "";
    expect(block).toContain("```mermaid\n");
    expect(block.split("```mermaid\n")[1]?.split("\n```")[0]).toBe(mermaid());
  });
});

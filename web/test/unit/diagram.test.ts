// The lab's architecture diagram (src/diagram): the model is consistent, both drawings carry every
// node and edge without a style attribute or a script, nothing public names an internal address or
// VLAN, and README.md's mermaid is what the model generates.

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { EDGES, NARROW, NODES, ZONES, sourceUrl, validate } from "../../src/diagram/model";
import { TRAFFIC, mermaid, narrow, svg, trafficCss, wide, wrapSub } from "../../src/diagram/layout";
import { RUN_PATH, phaseOf, renderCaption } from "../../src/ui/diagram";

describe("the lab diagram's model", () => {
  it("is consistent: known zones and nodes, the phone order without repeats, every node with words", () => {
    expect(validate()).toEqual([]);
  });

  it("starts where the landing page's and /cluster/'s diagrams start: the visitor, the edge, the tunnel, the Gateway, with their words", () => {
    const edge = (from: string, to: string) => EDGES.find((e) => e.from === from && e.to === to);
    const path = ["visitor", "edge", "cloudflared", "gateway"];
    expect(NARROW.slice(0, 4)).toEqual(path);
    expect(path.map((id) => NODES.find((n) => n.id === id)?.label)).toEqual(["Visitor", "Cloudflare edge", "cloudflared ×2", "Cilium Gateway"]);
    expect([edge("visitor", "edge")?.label, edge("edge", "cloudflared")?.label, edge("cloudflared", "gateway")?.label]).toEqual(["HTTPS", "tunnel", "HTTPS"]);
    expect(edge("edge", "cloudflared")?.both).toBe(true);
    expect(edge("gateway", "page")?.label).toBe("/lab/");
    expect(edge("gateway", "api")?.label).toBe("/cluster/api");
    for (const id of [...path, "page", "api"]) expect(NODES.find((n) => n.id === id)?.role).toBe("entry");
    expect(ZONES.map((z) => z.title)).toEqual(["Internet", "k3s01", "siem01", "Proxmox host", "Lab VM"]);
  });

  it("then the run: both triggers, the VM, the SIEM's stream, detections and validator, back to the API; variant A beside it", () => {
    const edge = (from: string, to: string) => EDGES.some((e) => e.from === from && e.to === to);
    expect(edge("timer", "reset") && edge("trigger", "reset") && edge("reset", "vm")).toBe(true);
    expect(edge("vm", "stream") && edge("vm", "sink") && edge("stream", "detector") && edge("detector", "validator")).toBe(true);
    expect(edge("validator", "runs") && edge("runs", "api") && edge("page", "api")).toBe(true);
    expect(edge("runner", "stream")).toBe(true);
    // The trigger only ever calls out, through the public way in: nothing points at it.
    expect(EDGES.filter((e) => e.to === "trigger")).toEqual([]);
    expect(edge("trigger", "edge")).toBe(true);
    for (const id of ["trigger", "timer", "reset"]) expect(NODES.find((n) => n.id === id)?.zone).toBe("pve");
    expect(NODES.find((n) => n.id === "vm")?.zone).toBe("lab");
    for (const id of ["stream", "sink", "detector", "validator", "runs"]) expect(NODES.find((n) => n.id === id)?.zone).toBe("siem");
    for (const id of ["cloudflared", "gateway", "page", "api", "runner"]) expect(NODES.find((n) => n.id === id)?.zone).toBe("k3s");
  });

  it("names no internal address or VLAN (the page is public)", () => {
    const text = JSON.stringify({ ZONES, NODES, EDGES }) + svg(wide()) + svg(narrow());
    expect(text).not.toMatch(/\b10\.\d+\.\d+\.\d+\b|\b192\.168\.|VLAN/i);
  });
});

describe("the drawings", () => {
  for (const dr of [wide(), narrow()]) {
    it(`${dr.view}: a group svg with a title and description, every node a focusable button, no style or script`, () => {
      const s = svg(dr);
      expect(s).toMatch(new RegExp(`^<svg class="lab-diagram__svg lab-diagram__svg--${dr.view}" viewBox="0 0 [\\d.]+ [\\d.]+" role="group"`));
      expect(s).toContain("<title");
      expect(s).toContain("<desc");
      expect(s).not.toMatch(/ style=|<style|<script|<foreignObject| on\w+=/i);
      const shown = NODES.filter((n) => dr.boxes.has(n.id));
      for (const n of shown) expect(s).toMatch(new RegExp(`data-node="${n.id}" data-state="idle" tabindex="0" role="button" aria-label="[^"]+" aria-expanded="false"`));
      const drawn = EDGES.filter((e) => dr.boxes.has(e.from) && dr.boxes.has(e.to));
      for (const e of drawn) expect(s).toContain(`data-edge="${e.from}-${e.to}"`);
      expect((s.match(/class="ld-edge ld-edge--side"/g) ?? []).length).toBe(drawn.filter((e) => e.kind === "side").length);
      // The traffic: a dot per lane, a glow on each of its edges.
      for (const l of Object.keys(TRAFFIC) as (keyof typeof TRAFFIC)[]) {
        expect(s).toContain(`class="ld-dot ld-dot--${l}"`);
        for (const id of TRAFFIC[l].edges) expect(s).toContain(`class="ld-glow ld-glow--${l}" id="${dr.view === "wide" ? "ld" : "ldn"}-glow-${id}"`);
      }
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

  it("the phone draws its nodes in their order, top to bottom; the way in and the real run, not the CronJob or the sink", () => {
    expect(NARROW).not.toContain("runner");
    expect(NARROW).not.toContain("sink");
    for (const id of RUN_PATH.map((s) => s.node)) expect(NARROW).toContain(id);
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

describe("captions: every node says what it is and where it lives", () => {
  const repoRoot = join(process.cwd(), "..");
  // The image build tests web/ alone (its Docker context), so the rest of the repository is not there.
  const fullRepo = existsSync(join(repoRoot, "lab")) && existsSync(join(repoRoot, "vm"));
  it("each source is a path in one of the two repositories", () => {
    for (const n of NODES) for (const src of n.sources) expect(src).toMatch(/^(lab|sdp):[\w./-]+$/);
  });
  it.skipIf(!fullRepo)("this repository's sources exist", () => {
    for (const n of NODES) {
      for (const src of n.sources) {
        if (src.startsWith("lab:")) expect(existsSync(join(repoRoot, src.slice(4))), src).toBe(true);
      }
    }
    expect(sourceUrl("lab:vm/scenario.c")).toBe("https://github.com/HubertMJ/detection-lab/tree/main/vm/scenario.c");
    expect(sourceUrl("sdp:scripts/lab-vm-provision.sh")).toBe("https://github.com/HubertMJ/self-defending-portfolio/tree/main/scripts/lab-vm-provision.sh");
  });

  it("the nodes point where the code is", () => {
    const src = (id: string) => NODES.find((n) => n.id === id)?.sources ?? [];
    expect(src("vm")).toEqual(expect.arrayContaining(["lab:vm/README.md", "lab:vm/scenario.c", "lab:vm/fluent-bit/sysmon_to_lab.lua"]));
    expect(src("validator")).toContain("lab:lab/vm_validate.py");
    expect(src("trigger")).toContain("sdp:scripts/lab-vm-provision.sh");
    expect(src("timer")).toContain("sdp:scripts/lab-vm-provision.sh");
    expect(src("detector")).toEqual(expect.arrayContaining(["sdp:siem/monitors/lab-polymorphic-beacon.json", "sdp:siem/detectors/lab.yaml"]));
    expect(src("api")).toEqual(["sdp:app/api/internal/lab/", "sdp:app/api/internal/labrun/"]);
    expect(src("page")).toContain("lab:web/");
    // The way in: the targets /cluster/'s diagram uses.
    expect(src("edge")).toEqual(["sdp:docs/adr/0003-cloudflare-tunnel-exposure.md"]);
    expect(src("cloudflared")).toEqual(["sdp:cluster/infra/cloudflared/"]);
    expect(src("gateway")).toContain("sdp:cluster/infra/gateway/");
  });

  it("a caption is text and links, no markup from the model", () => {
    const vm = NODES.find((n) => n.id === "vm");
    if (!vm) throw new Error("no vm");
    const el = renderCaption(vm);
    expect(el.querySelector(".ld-caption__text")?.textContent).toBe(vm.blurb);
    const links = [...el.querySelectorAll("a")].map((a) => a.getAttribute("href"));
    expect(links).toEqual(vm.sources.map(sourceUrl));
    expect(el.querySelector("script")).toBeNull();
  });
});

describe("the run lights its path", () => {
  it("at rest nothing is lit; a queued run lights the trigger's poll; each later phase adds to the one before; the validated run lights the whole path", () => {
    expect(phaseOf("idle").nodes.size).toBe(0);
    expect(phaseOf("queued").nodes.get("trigger")).toBe("run");
    expect(phaseOf("queued").edges.get("trigger-edge")).toBe("run");
    // Once the VM is starting, the page cannot tell the timer's run from a visitor's: neither is lit.
    expect(phaseOf("starting").nodes.has("trigger")).toBe(false);
    expect(phaseOf("starting").nodes.has("timer")).toBe(false);
    const order = ["starting", "running", "shipped"] as const;
    let before = new Set<string>();
    for (const p of order) {
      const lit = new Set(phaseOf(p).nodes.keys());
      for (const id of before) expect(lit.has(id), `${p} keeps ${id}`).toBe(true);
      expect(lit.size).toBeGreaterThan(before.size);
      before = lit;
    }
    expect(phaseOf("running").nodes.get("vm")).toBe("run");
    expect(phaseOf("running").edges.get("vm-stream")).toBe("record");
    expect(phaseOf("shipped").nodes.get("detector")).toBe("detect");
    const done = phaseOf("validated");
    for (const s of RUN_PATH) expect(done.nodes.get(s.node)).toBe(s.state);
    for (const e of RUN_PATH.flatMap((s) => (s.edge ? [s.edge] : []))) expect(EDGES.some((x) => `${x.from}-${x.to}` === e), e).toBe(true);
  });

  it("the traffic's stylesheet routes a dot per lane in both drawings", () => {
    const css = trafficCss();
    for (const p of ["ld", "ldn"]) for (const l of Object.keys(TRAFFIC)) expect(css).toMatch(new RegExp(`#${p}-dot-${l} \\{ offset-path: path\\("M[\\d. L]+"\\); --tr-name: ld-tr-${p}-${l}; --tr-period: [\\d.]+s; \\}`));
    for (const l of Object.keys(TRAFFIC) as (keyof typeof TRAFFIC)[]) for (const id of TRAFFIC[l].edges) expect(EDGES.some((e) => `${e.from}-${e.to}` === id), id).toBe(true);
  });
});

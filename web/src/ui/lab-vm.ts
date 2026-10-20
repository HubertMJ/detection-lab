// "Detection lab" variant B (isolated-vm): what the page shows for a REAL run on an isolated VM.
// Where variant A (ui/lab.ts) lets the visitor replay a synthetic sample, this draws a run that
// actually happened: the VM's lifecycle second by second, the real Sysmon evidence per copy
// (pid/ppid, the compiled binary's SHA-256, the persistence file, the beacons), and the verdict.
// Nothing here runs by itself; it only renders the run document. Pure DOM building (no innerHTML).

import { h } from "../lib/dom";
import { runControl } from "./lab-live";
import { isLabRawRecords, type LabRawRecords, type LabReplay, type LabVariant, type LabVmStatus, shortHash } from "../lib/lab";

const RUN_DATE = new Intl.DateTimeFormat("en-GB", {
  timeZone: "UTC", day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit",
});

function mmss(s: number): string {
  const m = Math.floor(s / 60);
  return `${m}:${String(s % 60).padStart(2, "0")}`;
}

// A path breaks only after a "/", not mid-word: a zero-width space after each slash gives the line
// wrapper a break opportunity there, so "...systemd/user/x.service" never splits as ".servic e".
function path(p: string): string {
  return p.replace(/\//g, "/​");
}

/** Above the panel: a real run with its id, date and duration, or a clearly-marked sample. */
function note(d: LabReplay): HTMLElement {
  if (d.live && d.run && d.lifecycle?.some((m) => m.marker === "poweroff_requested")) {
    const dur = d.run.duration_s ? ` · ${mmss(d.run.duration_s)} on the VM` : "";
    return h("p", { class: "lab-note" },
      h("span", { class: "tag tag--detect" }, "Live"),
      ` · Finished on an isolated VM${dur} · siem01's verdict appears here within minutes`);
  }
  if (d.live && d.run) {
    return h("p", { class: "lab-note" },
      h("span", { class: "tag tag--detect" }, "Live"),
      " · Running now on an isolated VM · started ",
      h("time", { datetime: d.run.started_at }, RUN_TIME.format(new Date(d.run.started_at)) + " UTC"),
      " · detections arrive from siem01 a few minutes after it ends");
  }
  if (d.sample || !d.run) {
    return h("p", { class: "lab-note" },
      h("span", { class: "tag tag--arm" }, "Sample"),
      " An example of what a real VM run looks like — not a live run.");
  }
  const dur = d.run.duration_s ? `${mmss(d.run.duration_s)} on the VM · ` : "";
  return h("p", { class: "lab-note" },
    h("span", { class: "tag tag--detect" }, "Live"),
    " · A real run on an isolated VM · " + dur,
    h("time", { datetime: d.run.finished_at }, RUN_DATE.format(new Date(d.run.finished_at))));
}

const RUN_TIME = new Intl.DateTimeFormat("en-GB", { timeZone: "UTC", hour: "2-digit", minute: "2-digit" });
const DAY = new Intl.DateTimeFormat("en-GB", { timeZone: "UTC", day: "numeric", month: "short" });

/** The live VM status strip. Rendered empty; lab-page.ts polls /cluster/api/lab/vm and fills it in
 * via updateVmStatus, so it reads as a live system rather than a mock-up. */
function statusStrip(): HTMLElement {
  return h("div", { class: "lab-vm-status", id: "lab-vm-status" },
    h("span", { class: "lab-vm-status__dot", "data-state": "unknown" }),
    h("span", { class: "lab-vm-status__state" }, "checking VM…"),
    h("span", { class: "lab-vm-status__meta mono" }, ""));
}

/** Update the strip from a poll of /cluster/api/lab/vm. `agoS` is seconds since the check. */
export function updateVmStatus(strip: HTMLElement, status: LabVmStatus | null, agoS: number): void {
  const dot = strip.querySelector<HTMLElement>(".lab-vm-status__dot");
  const state = strip.querySelector<HTMLElement>(".lab-vm-status__state");
  const meta = strip.querySelector<HTMLElement>(".lab-vm-status__meta");
  if (!dot || !state || !meta) return;
  if (!status) {
    dot.dataset.state = "unknown";
    state.textContent = "VM status unavailable";
    meta.textContent = "";
    return;
  }
  dot.dataset.state = status.state;
  state.textContent = status.state === "running" ? "VM running — live run in progress" : "VM powered off";
  const bits: string[] = [];
  if (status.last_restore) bits.push(`restored ${DAY.format(new Date(status.last_restore))} ${RUN_TIME.format(new Date(status.last_restore))}`);
  if (status.snapshot_clean !== undefined) bits.push(status.snapshot_clean ? "clean snapshot" : "not from the clean snapshot");
  if (status.next_run) bits.push(`next run ${RUN_TIME.format(new Date(status.next_run))} UTC`);
  bits.push(`checked ${agoS}s ago`);
  meta.textContent = bits.join(" · ");
}

function history(d: LabReplay): HTMLElement | null {
  if (!d.history || d.history.length === 0) return null;
  const dots = d.history.slice(0, 7).map((r) =>
    h("span", {
      class: "lab-vm-hist__dot",
      "data-ok": r.ok ? "true" : "false",
      title: `${r.id} · ${r.ok ? "ok" : "failed"}${r.duration_s ? ` · ${mmss(r.duration_s)}` : ""}`,
    }));
  return h("div", { class: "lab-vm-hist" },
    h("span", { class: "lab-vm-hist__l" }, "Last runs:"), h("span", { class: "lab-vm-hist__dots" }, dots));
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

/** The run's records exactly as siem01 indexed them (GET /cluster/api/lab/raw), fetched once, on the
 * first "Raw Sysmon" a visitor opens. Never a gate: absent or for another run, the copy's events from
 * the run document stand in, and the summary says which one is shown. */
const RAW_URL = "/cluster/api/lab/raw";
let rawOnce: Promise<LabRawRecords | null> | null = null;
function fetchRaw(): Promise<LabRawRecords | null> {
  rawOnce ??= fetch(RAW_URL, { headers: { accept: "application/json" } })
    .then(async (r) => (r.ok ? (await r.json()) as unknown : null))
    .then((v) => (isLabRawRecords(v) ? v : null))
    .catch(() => null);
  return rawOnce;
}

function rawEvents(d: LabReplay, v: LabVariant): HTMLElement {
  const pre = h("pre", { class: "lab-vm-raw__pre mono" });
  pre.textContent = JSON.stringify(v.events, null, 2);
  const label = h("span", {}, `Raw Sysmon — ${v.events.length} event${v.events.length === 1 ? "" : "s"} from the run document`);
  const box = h("details", { class: "lab-vm-raw" }, h("summary", {}, label), pre) as HTMLDetailsElement;
  box.addEventListener("toggle", () => {
    if (!box.open || box.dataset.loaded) return;
    box.dataset.loaded = "1";
    void fetchRaw().then((raw) => {
      if (!raw || raw.run_id !== d.run?.id) return;
      const recs = raw.records.filter((r) => r.lab?.variant === v.n && r.event?.code !== undefined);
      if (recs.length === 0) return;
      pre.textContent = JSON.stringify(recs, null, 2);
      label.textContent = `Raw Sysmon — ${recs.length} record${recs.length === 1 ? "" : "s"} as indexed in sdp-lab`;
    });
  });
  return box;
}

function copyCard(d: LabReplay, v: LabVariant): HTMLElement {
  if (v.pending) {
    return h("article", { class: "lab-vm-copy lab-vm-copy--pending" },
      h("header", { class: "lab-vm-copy__h" },
        h("span", { class: "lab-vm-copy__n mono" }, "—"),
        h("span", { class: "lab-vm-copy__c" }, `copy ${v.n}`)),
      h("div", { class: "lab-vm-copy__b" }, h("p", { class: "lab-vm-copy__wait small" }, "Not started yet.")));
  }
  const create = ev(v, "1");
  const file = ev(v, "11");
  const beacons = v.events.filter((e) => e["event.code"] === "3").length;
  const firedPersist = v.findings.some((f) => f.rule.includes("persistence"));
  const firedBeacon = v.findings.some((f) => f.rule.includes("beacon"));
  const incidentHere = d.incident?.opened_at_variant === v.n;
  const detectS = v.findings.length ? Math.min(...v.findings.map((f) => f.delay_s)) : null;
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
      create ? kv("exec", path(String(create["process.executable"]))) : null,
      file ? kv("persistence", path(String(file["file.path"]))) : null,
      kv("beacons", beacons ? `${beacons}× → lab beacon :8080` : "—"),
      kv("detected", detectS === null ? "—" : `${detectS}s after start`)),
    // Live: no verdict per copy yet (detections come with the validated run), so no chips at all.
    d.live ? null : h("div", { class: "lab-vm-chips" },
      chip(v.caught_by_hash ? "hit" : "miss", v.caught_by_hash ? "✓ known-hash" : "known-hash"),
      firedPersist ? chip("hit", "✓ persistence from /tmp") : null,
      firedBeacon ? chip(incidentHere ? "crit" : "hit", incidentHere ? "✓ beaconing → incident" : "✓ beaconing") : null),
    rawEvents(d, v));
}

function copies(d: LabReplay): HTMLElement {
  return h("div", { class: "lab-vm-copies" }, d.variants.map((v) => copyCard(d, v)));
}

function verdict(d: LabReplay): HTMLElement {
  if (d.live) {
    return h("div", { class: "lab-vm-verdict" },
      h("div", { class: "lab-vm-tile" }, h("span", { class: "lab-vm-tile__n" }, "…"),
        h("span", { class: "lab-vm-tile__c" }, "the rules' verdict appears when siem01 has judged this run, a few minutes after it ends")));
  }
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

// ---- the animated replay (the "it really runs" moment) ----

interface FeedItem { offset: number; feed: "console" | "detect"; text: string; variant?: number; kind?: string; event?: boolean; }

/** Merge the run into one ordered list of things that happened, each at its real offset: the VM
 * lifecycle and per-copy actions (the console), and the SIEM findings (the detection feed). */
function feedItems(d: LabReplay): FeedItem[] {
  const items: FeedItem[] = [];
  for (const m of d.lifecycle ?? []) items.push({ offset: m.offset_s, feed: "console", text: m.label, kind: m.marker === "poweroff_requested" ? "poweroff" : undefined });
  const ruleTitle = new Map(d.rules.map((r) => [r.id, r.title]));
  for (const v of d.variants) {
    for (const e of v.events) {
      const off = Number(e["offset_s"] ?? 0);
      const act = String(e["event.action"] ?? "");
      // Every Sysmon event is one console line and counts once, so the replay's "events" ends on the
      // run's own count (counters.events is the sum of these).
      const text = act === "process-create" ? `copy ${v.n} ran — ${v.renamed}`
        : act === "file-create" ? `copy ${v.n} wrote a persistence unit`
        : act === "network-connection" ? `copy ${v.n} beaconed`
        : `copy ${v.n} · ${act || "event"}`;
      items.push({ offset: off, feed: "console", text, variant: v.n, kind: act === "process-create" ? "exec" : undefined, event: true });
    }
    for (const f of v.findings) {
      const at = f.at_offset_s;
      if (at === undefined) continue;
      const inc = d.incident?.opened_at_variant === v.n && f.rule.includes("beacon");
      items.push({ offset: at, feed: "detect", variant: v.n, kind: inc ? "incident" : undefined,
        text: `${ruleTitle.get(f.rule) ?? f.rule} · copy ${v.n} · +${f.delay_s}s${inc ? " → incident" : ""}` });
    }
  }
  return items.sort((a, b) => a.offset - b.offset);
}

/** The replay player: a scrubber + controls, a VM console feed and a siem01 detection feed filling in
 * at the real offsets, the four copy lanes lighting up, and the counters counting up. Autoplays once
 * (never with reduced motion, where it shows the finished state). */
function replay(d: LabReplay): HTMLElement | null {
  const items = feedItems(d);
  if (items.length === 0) return null;
  const maxOff = Math.max(d.run?.duration_s ?? 0, ...items.map((i) => i.offset), 1);

  const console_ = h("ol", { class: "lab-rp-feed", "aria-label": "VM console" });
  const detect = h("ol", { class: "lab-rp-feed", "aria-label": "siem01 detections" });
  const lanes = d.variants.map((v) =>
    h("div", { class: "lab-rp-lane", "data-state": "pending" },
      h("span", { class: "lab-rp-lane__n mono" }, `copy ${v.n}`),
      h("span", { class: "lab-rp-lane__s" }, "waiting")));
  const cProc = h("span", { class: "lab-rp-c__n mono" }, "0");
  const cEv = h("span", { class: "lab-rp-c__n mono" }, "0");
  const cDet = h("span", { class: "lab-rp-c__n mono" }, "0");
  const cInc = h("span", { class: "lab-rp-c__n mono" }, "0");
  const clock = h("span", { class: "lab-rp-clock mono" }, "0:00");
  const scrub = h("input", { type: "range", class: "lab-rp-scrub", min: "0", max: String(maxOff), value: "0", step: "1",
    "aria-label": "scrub the run" }) as HTMLInputElement;
  const playBtn = h("button", { type: "button", class: "btn btn--ghost btn--small lab-rp-play" }, "▶ Play");
  const speedSel = h("select", { class: "lab-rp-speed", "aria-label": "playback speed" },
    h("option", { value: "1" }, "1×"), h("option", { value: "2", selected: true }, "2×"), h("option", { value: "4" }, "4×")) as HTMLSelectElement;

  // The box never scrolls (by itself or otherwise): it shows the newest lines that fit whole, dropping
  // the oldest, so no line is ever cut at an edge. Measured once the box is laid out (the first render
  // happens before it is in the page, so it is fitted again on attach and on resize).
  function fit(feed: HTMLElement): void {
    if (!feed.isConnected || feed.clientHeight === 0) return;
    while (feed.childElementCount > 1 && feed.scrollHeight > feed.clientHeight) feed.firstElementChild?.remove();
  }
  if (typeof ResizeObserver !== "undefined") {
    const ro = new ResizeObserver(() => { fit(console_); fit(detect); });
    ro.observe(console_); ro.observe(detect);
  }

  let revealed = -1;
  function renderTo(off: number): void {
    // reset when scrubbing backwards
    if (off < (items[revealed]?.offset ?? 0)) { console_.replaceChildren(); detect.replaceChildren(); revealed = -1;
      for (const l of lanes) { l.dataset.state = "pending"; (l.querySelector(".lab-rp-lane__s") as HTMLElement).textContent = "waiting"; } }
    let proc = 0, ev = 0, det = 0, inc = 0;
    while (revealed + 1 < items.length && items[revealed + 1].offset <= off) {
      revealed++;
      const it = items[revealed];
      const line = h("li", { class: it.kind === "incident" ? "lab-rp-line lab-rp-line--crit" : "lab-rp-line" },
        h("span", { class: "lab-rp-line__t mono" }, mmss(it.offset)), h("span", {}, it.text));
      const feed = it.feed === "console" ? console_ : detect;
      feed.append(line);
      fit(feed);
    }
    // counts + lanes from everything up to `off`
    for (let i = 0; i <= revealed; i++) {
      const it = items[i];
      if (it.kind === "exec") { proc++; const l = lanes[(it.variant ?? 1) - 1]; if (l) { l.dataset.state = "running"; (l.querySelector(".lab-rp-lane__s") as HTMLElement).textContent = "running"; } }
      if (it.event) ev++;
      if (it.kind === "poweroff") for (const l of lanes) if (l.dataset.state === "running") { l.dataset.state = "done"; (l.querySelector(".lab-rp-lane__s") as HTMLElement).textContent = "finished"; }
      if (it.feed === "detect") { det++; if (it.kind === "incident") { inc++; const l = lanes[(it.variant ?? 1) - 1]; if (l) { l.dataset.state = "incident"; (l.querySelector(".lab-rp-lane__s") as HTMLElement).textContent = "in incident"; } } }
    }
    const uniq = d.counters?.unique_hashes ?? d.variants.length;
    cProc.textContent = String(proc); cEv.textContent = String(ev);
    cDet.textContent = String(det); cInc.textContent = String(inc);
    cProc.dataset.u = String(uniq);
    clock.textContent = mmss(Math.round(off));
    scrub.value = String(Math.round(off));
  }

  let raf = 0; let t0 = 0; let base = 0; let playing = false;
  const reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const ANIM_MS = 11000; // 1x: the whole run in ~11s
  function stop(): void { if (raf) cancelAnimationFrame(raf); raf = 0; playing = false; playBtn.textContent = "▶ Play"; }
  function frame(now: number): void {
    const speed = Number(speedSel.value) || 1;
    const elapsed = (now - t0) / ANIM_MS * maxOff * speed;
    const off = Math.min(maxOff, base + elapsed);
    renderTo(off);
    if (off >= maxOff) { stop(); return; }
    raf = requestAnimationFrame(frame);
  }
  function play(): void { if (playing) return; if ((Number(scrub.value) || 0) >= maxOff) { renderTo(0); } playing = true; playBtn.textContent = "⏸ Pause"; base = Number(scrub.value) || 0; t0 = performance.now(); raf = requestAnimationFrame(frame); }
  playBtn.addEventListener("click", () => (playing ? stop() : play()));
  scrub.addEventListener("input", () => { stop(); renderTo(Number(scrub.value) || 0); });

  // Live (a run in progress): show everything so far, no animation, no controls to scrub.
  renderTo(reduce || d.live ? maxOff : 0);
  if (!reduce && !d.live) setTimeout(play, 400);

  const count = (n: HTMLElement, label: string) => h("div", { class: "lab-rp-c" }, n, h("span", { class: "lab-rp-c__l" }, label));
  return h("section", { class: d.live ? "lab-rp lab-rp--live" : "lab-rp" },
    h("div", { class: "lab-rp-bar" }, playBtn, h("label", { class: "lab-rp-speedwrap small" }, "speed ", speedSel),
      scrub, clock),
    h("div", { class: "lab-rp-counts" }, count(cProc, "processes"), count(cEv, "events"), count(cDet, "detections"), count(cInc, "incidents")),
    h("div", { class: "lab-rp-feeds" },
      h("div", { class: "lab-rp-col" }, h("p", { class: "lab-rp-h" }, "VM console"), console_),
      h("div", { class: "lab-rp-col" }, h("p", { class: "lab-rp-h" }, "siem01 — detections"), detect)),
    h("div", { class: "lab-rp-lanes" }, lanes));
}

/** Draw a real (or sample) isolated-VM run into the lab panel. */
export function mountLabVm(root: HTMLElement, d: LabReplay): void {
  root.replaceChildren(
    h("div", { class: "lab lab-vm" },
      note(d),
      statusStrip(),
      runControl(),
      history(d),
      h("h3", { class: "panel-title" }, "Watch the run"),
      replay(d),
      h("h3", { class: "panel-title" }, "The run, second by second"),
      lifecycle(d),
      h("h3", { class: "panel-title" }, "Four copies, four hashes, one behaviour"),
      copies(d),
      h("h3", { class: "panel-title" }, "What the rules caught"),
      verdict(d)),
  );
}

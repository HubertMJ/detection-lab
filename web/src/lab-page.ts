// /lab/: the detection lab's design preview (ui/lab.ts) on its own page.
//
// The page draws a LabReplay. It first asks the cluster for the latest real run at
// /cluster/api/lab/latest (same origin, so the CSP's connect-src 'self' covers it). That endpoint is
// not wired up yet; until it answers with a valid run -- and in the standalone image, which has no
// API at all -- the page falls back to the bundled synthetic sample (lib/lab-replay.json, sample:
// true), which labels itself as generated, not a run on real machines.

import labReplay from "./lib/lab-replay.json";
import { byId } from "./lib/dom";
import { isLabRawRecords, isLabReplay, isLabRunControl, isLabVmStatus, type LabReplay, type LabRunControl, type LabVmStatus } from "./lib/lab";
import { setupThemeToggle } from "./lib/theme-toggle";
import { mountLab } from "./ui/lab";
import { replayFromRaw, updateRunControl } from "./ui/lab-live";
import { mountLabVm, updateVmStatus } from "./ui/lab-vm";

document.documentElement.classList.add("js");
setupThemeToggle();

const LATEST = "/cluster/api/lab/latest";
// The fetch is an upgrade, never a gate: the page renders the sample at once and must reach `load`
// fast whatever the endpoint does, so a slow or hung API cannot hold the page. AbortController caps
// the wait, and the render does not await it.
const LATEST_TIMEOUT_MS = 4000;

async function fetchLatest(): Promise<unknown | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), LATEST_TIMEOUT_MS);
  try {
    const res = await fetch(LATEST, { headers: { accept: "application/json" }, signal: controller.signal });
    return res.ok ? ((await res.json()) as unknown) : null;
  } catch {
    // Absent (the standalone image), unreachable, or slower than the timeout: the sample stands in.
    return null;
  } finally {
    clearTimeout(timer);
  }
}

// The isolated VM's live state (read-only). The page polls it so the status strip and the "LIVE"
// badge are real, never a mock-up; absent or slow, the strip simply reads "status unavailable".
const VM_URL = "/cluster/api/lab/vm";

// "Start run now" (GET/POST /cluster/api/lab/run) and the raw records of the run in progress
// (GET /cluster/api/lab/raw). Same origin, read-only except the POST, which only queues a request.
const RUN_URL = "/cluster/api/lab/run";
const RAW_URL = "/cluster/api/lab/raw";
async function fetchJson(url: string, init?: RequestInit): Promise<{ status: number; body: unknown } | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), LATEST_TIMEOUT_MS);
  try {
    const res = await fetch(url, { headers: { accept: "application/json" }, signal: controller.signal, ...init });
    let body: unknown = null;
    try { body = await res.json(); } catch { body = null; }
    return { status: res.status, body };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

let polling = false;
let lastStatus: LabVmStatus | null = null;
let lastRun: LabRunControl | null = null;
let runNote: string | undefined;
let lastCheck = 0;
/** The last validated run on screen (the base a live view borrows its scenario and rules from). */
let validated: LabReplay | null = null;
/** While the VM runs a run that has no validated document yet: its id and how many records we drew. */
let liveRunId: string | null = null;
let liveCount = -1;

const ACTIVE = new Set(["queued", "starting", "running"]);
const busy = (): boolean => lastStatus?.state === "running" || ACTIVE.has(lastRun?.state ?? "") || liveRunId !== null;

function refresh(): void {
  const strip = document.getElementById("lab-vm-status");
  if (strip) updateVmStatus(strip, lastStatus, Math.max(0, Math.round((Date.now() - lastCheck) / 1000)));
  const ctl = document.getElementById("lab-run-control");
  if (ctl) updateRunControl(ctl, lastRun, Date.now(), runNote);
}

/** What a refused POST says, in the page's words. */
function refusal(status: number, body: unknown): string {
  const err = typeof body === "object" && body !== null ? String((body as { error?: unknown }).error ?? "") : "";
  if (status === 409) return "A run is already queued or running.";
  if (status === 429 && err === "daily limit") return "Today's runs are used up; try again tomorrow.";
  if (status === 429 && err === "visitor limit") return "You have started your runs for today; others can still start one.";
  if (status === 429 && err === "too many requests") return "Too many clicks; wait a moment.";
  if (status === 429) return "The VM rests between runs; try again in a few minutes.";
  if (status === 423) return "The daily runs are on now; try again a little later.";
  return "The run could not be started right now.";
}

/** Poll the VM, the run control and - while a run is in progress - its raw records: every 5 s while
 * something is happening, every 30 s otherwise. A run in progress is drawn live from its records;
 * once it has powered off, the page waits for its validated document and swaps it in. */
function startVmPolling(panel: HTMLElement, reload: () => void): void {
  if (polling) return; // one poller for the life of the page
  polling = true;
  const tick = async (): Promise<void> => {
    const [vm, run] = await Promise.all([fetchJson(VM_URL), fetchJson(RUN_URL)]);
    lastStatus = vm && vm.status === 200 && isLabVmStatus(vm.body) ? vm.body : null;
    lastRun = run && run.status === 200 && isLabRunControl(run.body) ? run.body : null;
    lastCheck = Date.now();
    if (lastStatus?.state === "running" && validated) {
      byId("lab-eyebrow").textContent = "Detection lab · LIVE";
      const raw = await fetchJson(RAW_URL);
      if (raw && raw.status === 200 && isLabRawRecords(raw.body) && raw.body.run_id !== validated.run?.id &&
          (raw.body.run_id !== liveRunId || raw.body.records.length !== liveCount)) {
        const d = replayFromRaw(raw.body, validated, Date.now());
        if (d) {
          liveRunId = raw.body.run_id;
          liveCount = raw.body.records.length;
          mountLabVm(panel, d);
        }
      }
    } else if (liveRunId) {
      reload(); // powered off: fetch the latest run until it is this one, validated
    }
    refresh();
    window.setTimeout(() => void tick(), busy() ? 5000 : 30000);
  };
  // The button lives inside the panel, which is redrawn: listen once, on the panel.
  panel.addEventListener("click", (e) => {
    const btn = (e.target as HTMLElement).closest<HTMLButtonElement>(".lab-run__btn");
    if (!btn || btn.disabled) return;
    btn.disabled = true;
    void fetchJson(RUN_URL, { method: "POST" }).then((res) => {
      runNote = !res ? "The run could not be started right now." : res.status === 202 ? undefined : refusal(res.status, res.body);
      if (res && res.status === 202) lastRun = { state: "queued", can_start: false };
      refresh();
      window.setTimeout(() => { runNote = undefined; }, 15000);
      window.setTimeout(() => void tick(), 1500);
    });
  });
  void tick();
  window.setInterval(refresh, 1000);
}

/** The latest validated run arrived: draw it, unless a live run is on screen and this is not it yet. */
function showValidated(panel: HTMLElement, data: LabReplay): boolean {
  if (liveRunId && data.run?.id !== liveRunId) return false;
  liveRunId = null;
  liveCount = -1;
  validated = data;
  mountLab(panel, data);
  refresh();
  return true;
}

// The static hero describes the bundled sample ("design preview", "not a run on real machines").
// When the API hands us a real run, the hero must tell the truth too, so rewrite its eyebrow and
// lead. Left untouched on the sample fallback (the standalone image, an absent or slow API), where
// the static wording is correct.
function heroLive(): void {
  byId("lab-eyebrow").textContent = "Detection lab · live";
  const lead = byId("lab-lead");
  lead.textContent =
    "A rule on a known hash catches one copy of a program. What catches the next three, when each has a new hash ";
  const strong = document.createElement("strong");
  strong.textContent = "and a new name";
  lead.append(
    strong,
    "? Shows the latest daily run: generated events indexed into siem01, where real detection rules and a monitor catch them.",
  );
  // The closing "next step" line described wiring the page to the SIEM as future work. On a real run
  // that step is done, so say so (keeping the link to the cluster's correlation view).
  const next = byId("lab-next");
  next.textContent = "These events go to the OpenSearch SIEM behind ";
  const link = document.createElement("a");
  link.href = "/cluster/#correlation";
  link.textContent = "the self-defending cluster";
  next.append(link, ": the findings above come from its real rules, not from this page.");
}

// A real (or sample) run on the isolated VM (variant B): the hook is the same, but the page is now
// about a machine that ran, not a replay the visitor steps through, so retitle the hero and the
// "Replay" section to match the panel ui/lab-vm.ts draws.
function heroVm(real: boolean): void {
  byId("lab-eyebrow").textContent = real ? "Detection lab · live · real machine" : "Detection lab · sample";
  const lead = byId("lab-lead");
  lead.textContent =
    "A rule on a known hash catches one copy of a program. What catches the next three, when each has a new hash ";
  const strong = document.createElement("strong");
  strong.textContent = "and a new name";
  lead.append(strong, real
    ? "? This is the latest run on a real isolated VM — daily, or started by a visitor below: the Sysmon events it left, and what the SIEM made of them."
    : "? Below is a sample of what a real isolated-VM run shows on this page — not a live run.");
  byId("lab-replay-eyebrow").textContent = real ? "Real run" : "Sample run";
  byId("lab-replay-lead").textContent =
    "The machine was reverted to a clean snapshot, ran four copies — each with a new hash and a new name — then powered off. This is what it really left behind.";
  // The "How the generator works" section is about synthetic Windows events; a B run is a real Linux
  // pipeline, so describe that instead.
  byId("lab-gen-eyebrow").textContent = "Pipeline";
  byId("generator-title").textContent = "How a real run works";
  byId("lab-gen-lead").textContent =
    "A real machine, reverted to a clean snapshot and run on a schedule, so the detections are judged against what actually happened on it.";
  const step = (title: string, body: string): HTMLLIElement => {
    const li = document.createElement("li");
    const h3 = document.createElement("h3");
    h3.textContent = title;
    const p = document.createElement("p");
    p.textContent = body;
    li.append(h3, p);
    return li;
  };
  byId("lab-steps").replaceChildren(
    step("Snapshot", "The isolated VM is reverted to a clean snapshot, so every run starts identical."),
    step("Run", "It really runs four copies of the test program — each rebuilt with a new hash and a new name — which drop a persistence unit from /tmp and beacon."),
    step("Sysmon for Linux", "The kernel's process, file and network events are recorded by Sysmon for Linux."),
    step("Fluent Bit → siem01", "Fluent Bit ships only this run's events to the OpenSearch SIEM over mTLS, then the VM powers off."),
    step("Rules", "Sigma rules and Alerting monitors on siem01 catch the behaviour — real detection, not computed in this page."),
    step("Validator", "A validator lines the findings up against the ground truth and writes the run shown above."),
  );
  const next = byId("lab-next");
  next.textContent = "These events come from a real isolated VM, shipped to the OpenSearch SIEM behind ";
  const link = document.createElement("a");
  link.href = "/cluster/#correlation";
  link.textContent = "the self-defending cluster";
  next.append(link, ", where real rules catch them.");
}

function start(): void {
  const panel = byId("lab-panel");
  // Draw the bundled synthetic sample immediately: first paint never waits on the API.
  mountLab(panel, labReplay);
  // The upgrade fetch starts only after `load`, so an in-flight request can never delay the load
  // event (notably in Firefox). Then swap in the latest real run if the API answers with a valid one.
  const upgrade = (): void => {
    void fetchLatest().then((data) => {
      if (!isLabReplay(data)) return;
      if (data.run?.mode === "isolated-vm") {
        if (!showValidated(panel, data)) return;
        heroVm(!data.sample);
        startVmPolling(panel, upgrade);
      } else {
        mountLab(panel, data);
        if (!data.sample) heroLive();
      }
    });
  };
  if (document.readyState === "complete") upgrade();
  else addEventListener("load", upgrade, { once: true });
}

start();

// /lab/: the detection lab's design preview (ui/lab.ts) on its own page.
//
// The page draws a LabReplay. It first asks the cluster for the latest real run at
// /cluster/api/lab/latest (same origin, so the CSP's connect-src 'self' covers it). That endpoint is
// not wired up yet; until it answers with a valid run -- and in the standalone image, which has no
// API at all -- the page falls back to the bundled synthetic sample (lib/lab-replay.json, sample:
// true), which labels itself as generated, not a run on real machines.

import labReplay from "./lib/lab-replay.json";
import { byId } from "./lib/dom";
import { isLabReplay, isLabVmStatus, type LabVmStatus } from "./lib/lab";
import { setupThemeToggle } from "./lib/theme-toggle";
import { mountLab } from "./ui/lab";
import { updateVmStatus } from "./ui/lab-vm";

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
async function fetchVm(): Promise<unknown | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), LATEST_TIMEOUT_MS);
  try {
    const res = await fetch(VM_URL, { headers: { accept: "application/json" }, signal: controller.signal });
    return res.ok ? ((await res.json()) as unknown) : null;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

let vmPoll: number | undefined;
let lastStatus: LabVmStatus | null = null;
let lastCheck = 0;
let followed = false;

/** Poll the VM status every 30 s (and tick "checked Ns ago" each second). When the VM is running a
 * run, flip the badge to LIVE and re-fetch the latest run once, so the page follows the 03:00 run. */
function startVmPolling(reload: () => void): void {
  if (vmPoll !== undefined) return; // one poller for the life of the page
  const refresh = (): void => {
    const strip = document.getElementById("lab-vm-status");
    if (strip) updateVmStatus(strip, lastStatus, Math.max(0, Math.round((Date.now() - lastCheck) / 1000)));
  };
  const poll = async (): Promise<void> => {
    const data = await fetchVm();
    lastStatus = isLabVmStatus(data) ? data : null;
    lastCheck = Date.now();
    refresh();
    if (lastStatus?.state === "running") {
      byId("lab-eyebrow").textContent = "Detection lab · LIVE";
      if (!followed) {
        followed = true;
        reload();
      }
    } else {
      followed = false;
    }
  };
  void poll();
  vmPoll = window.setInterval(() => void poll(), 30000);
  window.setInterval(refresh, 1000);
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
    ? "? This is the latest daily run on a real isolated VM: the Sysmon events it left, and what the SIEM made of them."
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
      mountLab(panel, data);
      if (data.run?.mode === "isolated-vm") {
        heroVm(!data.sample);
        startVmPolling(upgrade);
      } else if (!data.sample) {
        heroLive();
      }
    });
  };
  if (document.readyState === "complete") upgrade();
  else addEventListener("load", upgrade, { once: true });
}

start();

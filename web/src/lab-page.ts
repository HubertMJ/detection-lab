// /lab/: the detection lab's design preview (ui/lab.ts) on its own page.
//
// The page draws a LabReplay. It first asks the cluster for the latest real run at
// /cluster/api/lab/latest (same origin, so the CSP's connect-src 'self' covers it). That endpoint is
// not wired up yet; until it answers with a valid run -- and in the standalone image, which has no
// API at all -- the page falls back to the bundled synthetic sample (lib/lab-replay.json, sample:
// true), which labels itself as generated, not a run on real machines.

import labReplay from "./lib/lab-replay.json";
import { byId } from "./lib/dom";
import { isLabReplay } from "./lib/lab";
import { setupThemeToggle } from "./lib/theme-toggle";
import { mountLab } from "./ui/lab";

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

function start(): void {
  const panel = byId("lab-panel");
  // Draw the bundled synthetic sample immediately: first paint never waits on the API.
  mountLab(panel, labReplay);
  // The upgrade fetch starts only after `load`, so an in-flight request can never delay the load
  // event (notably in Firefox). Then swap in the latest real run if the API answers with a valid one.
  const upgrade = (): void => {
    void fetchLatest().then((data) => {
      if (isLabReplay(data)) mountLab(panel, data);
    });
  };
  if (document.readyState === "complete") upgrade();
  else addEventListener("load", upgrade, { once: true });
}

start();

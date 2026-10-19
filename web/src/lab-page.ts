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
      if (!data.sample) heroLive();
    });
  };
  if (document.readyState === "complete") upgrade();
  else addEventListener("load", upgrade, { once: true });
}

start();

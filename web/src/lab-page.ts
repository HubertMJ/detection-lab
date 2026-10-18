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

async function load(): Promise<void> {
  const panel = byId("lab-panel");
  try {
    const res = await fetch(LATEST, { headers: { accept: "application/json" } });
    if (res.ok) {
      const data: unknown = await res.json();
      if (isLabReplay(data)) {
        mountLab(panel, data);
        return;
      }
    }
  } catch {
    // The API is absent (the standalone image) or unreachable: the bundled sample stands in.
  }
  mountLab(panel, labReplay);
}

void load();

// "How four copies became one incident" (variant B): the beacon monitor's story, told with the run's
// own data. Each copy beacons to the same lab address; the monitor counts distinct SHA-256 per
// address over 15 minutes and fires at two, so copy 1 alone stays below the threshold, copy 2 opens
// the incident and copies 3 and 4 join it - one incident for four renamed, rehashed copies. The
// rule itself is shown in plain words and as the query it runs, linked to its definition.
//
// It plays once when it scrolls into view (a step every ~1 s; never with reduced motion, which shows
// the finished state) and can be replayed. Only classes change while it plays: every box keeps its
// size, so nothing moves on the page. Pure DOM building (no innerHTML).

import { h } from "../lib/dom";
import { type LabReplay, shortHash } from "../lib/lab";

const SDP = "https://github.com/HubertMJ/self-defending-portfolio/blob/main";
export const RULE_LINKS: Record<string, string> = {
  "lab-polymorphic-beacon": `${SDP}/siem/monitors/lab-polymorphic-beacon.json`,
  "ioc-lab-known-hash": `${SDP}/siem/rules/ioc-lab-known-hash.yml`,
  "lab-persistence-user-unit-from-tmp": `${SDP}/siem/rules/lab-persistence-user-unit-from-tmp.yml`,
};
/** The monitor's threshold and window (siem/monitors/lab-polymorphic-beacon.json). */
const THRESHOLD = 2;
const WINDOW_S = 15 * 60;
const STEP_MS = 1100;

function mmss(s: number): string {
  const m = Math.floor(s / 60);
  return `${m}:${String(Math.round(s) % 60).padStart(2, "0")}`;
}

interface CopyBeacon { n: number; name: string; sha: string; first: number; count: number; byHash: boolean }

/** Each copy's first beacon (offset from the rollback) and count, in copy order: the copies start one
 * after another and beacon at once, and the validator places the incident in that order too (a lost
 * first beacon must not reorder the story). */
export function beacons(d: LabReplay): CopyBeacon[] {
  const out: CopyBeacon[] = [];
  for (const v of d.variants) {
    const offs = v.events.filter((e) => e["event.code"] === "3").map((e) => Number(e["offset_s"] ?? NaN)).filter(Number.isFinite);
    if (offs.length === 0) continue;
    out.push({ n: v.n, name: v.renamed, sha: v.sha256, first: Math.min(...offs), count: offs.length, byHash: !!v.caught_by_hash });
  }
  return out.sort((a, b) => a.n - b.n);
}

/** What each copy did to the monitor's count: below the threshold, opened the incident, or joined it. */
export function roles(list: CopyBeacon[], openedAt: number | null): ("below" | "opened" | "joined" | "outside")[] {
  const seen = new Set<string>();
  let opened = false;
  const firstAt = list[0]?.first ?? 0;
  return list.map((c) => {
    if (c.first - firstAt > WINDOW_S) return "outside";
    seen.add(c.sha);
    if (!opened && seen.size >= THRESHOLD && (openedAt === null || c.n === openedAt)) { opened = true; return "opened"; }
    return opened ? "joined" : "below";
  });
}

export function incidentStory(d: LabReplay): HTMLElement | null {
  if (d.live) return null;
  const list = beacons(d);
  if (list.length === 0) return null;
  const openedAt = d.incident?.opened_at_variant ?? null;
  const role = roles(list, openedAt);
  const beacon = d.beacon || "lab beacon :8080";
  const incAt = d.incident?.at_offset_s;
  // Every copy inside the monitor's window belongs to the one bucket, so to the one incident.
  const members = role.filter((r) => r !== "outside").length;

  const caption = (i: number): string => {
    const hashes = new Set(list.slice(0, i + 1).filter((_, j) => role[j] !== "outside").map((x) => x.sha)).size;
    switch (role[i]) {
      case "below": return `${hashes} hash at this address — below the threshold of ${THRESHOLD}`;
      case "opened": return `${hashes} different hashes at one address — the monitor fires: incident opened`;
      case "joined": return `${hashes} hashes — joins the same incident`;
      default: return `beaconed more than 15 min later — outside this window`;
    }
  };

  const cards = list.map((c, i) =>
    h("li", { class: "lab-inc-copy", "data-role": role[i] },
      h("p", { class: "lab-inc-copy__h" },
        h("span", { class: "lab-inc-copy__n mono" }, c.name),
        h("span", { class: "lab-inc-copy__c" }, `copy ${c.n}`)),
      h("p", { class: "lab-inc-copy__k mono" }, "sha-256 ", h("span", { title: c.sha }, shortHash(c.sha)),
        c.byHash ? h("span", { class: "lab-inc-copy__ioc" }, " · on the IOC list") : null),
      h("p", { class: "lab-inc-copy__b mono" }, `${mmss(c.first)} → ${beacon}`, h("span", { class: "lab-inc-copy__x" }, ` · ${c.count}×`)),
      h("p", { class: "lab-inc-copy__s" }, caption(i))));

  const meter = h("div", { class: "lab-inc-meter", role: "img",
    "aria-label": `distinct hashes calling ${beacon}: ${list.length} of ${list.length}; the threshold is ${THRESHOLD}` },
    ...list.map((_, i) => h("span", { class: "lab-inc-meter__seg", "data-i": i })),
    h("span", { class: "lab-inc-meter__thr", "data-at": THRESHOLD }, `threshold ${THRESHOLD}`));
  // The threshold mark sits between segment THRESHOLD-1 and THRESHOLD (a class per position, CSP-safe).
  meter.classList.add(`lab-inc-meter--n${Math.min(list.length, 6)}`);

  const incident = h("div", { class: "lab-inc-box" },
    h("p", { class: "lab-inc-box__t" }, openedAt === null ? "No incident" : "One incident"),
    h("p", { class: "lab-inc-box__d" }, openedAt === null
      ? "The monitor never saw two different hashes at one address in its window."
      : `${members} copies, ${new Set(list.map((c) => c.sha)).size} different hashes, one address (${beacon})` +
        (incAt !== undefined ? ` · opened at ${mmss(incAt)}, ${d.incident?.delay_s ?? "?"} s after copy ${openedAt} started` : "")),
    h("p", { class: "lab-inc-box__w small" }, "Keyed on behaviour — where the copies call — so a new name and a new hash change nothing."));

  const live = h("p", { class: "visually-hidden", "aria-live": "polite" });
  const steps = h("ol", { class: "lab-inc-copies" }, cards);
  const replayBtn = h("button", { type: "button", class: "btn btn--ghost btn--small lab-inc-replay" }, "↻ Replay");

  const root = h("section", { class: "lab-inc", "aria-label": "How four copies became one incident" },
    h("div", { class: "lab-inc-stage" }, steps, h("div", { class: "lab-inc-join" }, meter, incident), replayBtn, live),
    ruleCard(d));

  // ---- playback: only data-* / classes change ----
  let timers: number[] = [];
  const segs = [...meter.querySelectorAll<HTMLElement>(".lab-inc-meter__seg")];
  const set = (k: number): void => {
    cards.forEach((c, i) => c.classList.toggle("is-on", i < k));
    segs.forEach((s, i) => s.classList.toggle("is-on", i < k && role[i] !== "outside"));
    const openedIdx = role.indexOf("opened");
    root.classList.toggle("lab-inc--fired", openedIdx >= 0 && k > openedIdx);
    if (k > 0 && k <= list.length) live.textContent = `copy ${list[k - 1].n}: ${caption(k - 1)}`;
  };
  const play = (): void => {
    timers.forEach(clearTimeout); timers = [];
    set(0);
    for (let k = 1; k <= list.length; k++) timers.push(window.setTimeout(() => set(k), k * STEP_MS));
  };
  const reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  if (reduce || typeof IntersectionObserver === "undefined") {
    set(list.length);
  } else {
    set(0);
    const io = new IntersectionObserver((entries) => {
      if (entries.some((e) => e.isIntersecting)) { io.disconnect(); play(); }
    }, { threshold: 0.35 });
    io.observe(root);
  }
  replayBtn.addEventListener("click", () => (reduce ? set(list.length) : play()));
  return root;
}

/** The rule that ties the copies together, in plain words and as the query it runs, with the other
 * two rules for contrast; each links to its definition. */
function ruleCard(d: LabReplay): HTMLElement {
  const title = (id: string, fallback: string) => d.rules.find((r) => r.id === id)?.title ?? fallback;
  const link = (id: string, text: string) => h("a", { href: RULE_LINKS[id], rel: "noopener" }, text);
  return h("aside", { class: "lab-inc-rule" },
    h("p", { class: "lab-inc-rule__eyebrow" }, "The rule that caught it"),
    h("h4", { class: "lab-inc-rule__t" }, title("lab-polymorphic-beacon", "One beacon, many binaries")),
    h("p", { class: "lab-inc-rule__d" },
      "An Alerting bucket-level monitor on siem01, every minute: the last 15 minutes of network connections, " +
      "grouped by where they go; a group that holds two or more different program hashes is one incident."),
    h("pre", { class: "lab-inc-rule__q mono" },
      "WHERE  event.code = \"3\"  AND  @timestamp > now-15m\n" +
      "GROUP  BY destination.ip, destination.port\n" +
      "HAVING cardinality(process.hash.sha256) >= 2"),
    h("p", { class: "lab-inc-rule__l small" }, link("lab-polymorphic-beacon", "Monitor definition on GitHub →")),
    h("ul", { class: "lab-inc-rule__others small" },
      h("li", {}, link("ioc-lab-known-hash", title("ioc-lab-known-hash", "Known-bad hash")),
        " — matches one hash, so it caught copy 1 and nothing else."),
      h("li", {}, link("lab-persistence-user-unit-from-tmp", title("lab-persistence-user-unit-from-tmp", "Persistence unit from /tmp")),
        " — fires on each copy alone; the monitor is what links them.")));
}

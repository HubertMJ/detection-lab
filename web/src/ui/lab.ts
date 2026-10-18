// "Detection lab" (#lab): the design preview of the incident generator, drawn from a synthetic sample
// (lib/lab-replay.json). The visitor picks how many of the four copies have run and whether the copies
// keep one name (by default each is renamed, as an attacker would); the panel redraws in place - the latest copy and what changed in it, which rules
// fired on which copy, the risk scored two ways (per program name, per address it calls), the one
// incident that adds up to, and the ground truth against the findings. Nothing plays by itself and
// nothing scrolls: a click changes only this panel, and every box keeps its place.

import { h, replace } from "../lib/dom";
import { type LabMode, type LabReplay, type LabState, type RiskEntity, coverage, isLabReplay, labState, shortHash } from "../lib/lab";

const KIND_LABEL = { sigma: "Sigma rule", monitor: "Alerting monitor" } as const;

export function mountLab(root: HTMLElement, data: unknown): void {
  if (!isLabReplay(data)) return; // the static text in #lab-body stays
  const d: LabReplay = data;
  let ran = 1;
  let mode: LabMode = "renamed";

  const live = h("p", { class: "visually-hidden", "aria-live": "polite", "aria-atomic": "true" });
  const copyEl = h("div", { class: "lab-copy-card" });
  const rulesEl = h("div", { class: "lab-rules" });
  const outcomeEl = h("div", { class: "lab-outcome" });
  const takeawayEl = h("p", { class: "lab-takeaway" });
  const coverageEl = h("div", { class: "lab-coverage" });
  const buttons = d.variants.map((v) =>
    h("button", { type: "button", class: "btn btn--ghost btn--small lab-picker__btn", "data-n": v.n, "aria-label": `Copy #${v.n}` }, `#${v.n}`),
  );
  const keepName = h("input", { type: "checkbox", class: "lab-rename__box" });

  const draw = () => {
    const s = labState(d, ran, mode);
    for (const b of buttons) b.setAttribute("aria-pressed", String(Number(b.dataset.n) === s.ran));
    replace(copyEl, h("h3", { class: "panel-title" }, `Copy #${s.ran}`), copyCard(d, s));
    replace(rulesEl, h("h3", { class: "panel-title" }, "What OpenSearch made of it"), rulesList(s));
    replace(outcomeEl, outcome(d, s));
    replace(takeawayEl, takeaway(d, s));
    replace(coverageEl, h("h3", { class: "panel-title" }, "Ground truth against findings"), coverageTable(d, s));
    const incident = s.incidentAtByName ?? s.incidentAtByBeacon;
    live.textContent =
      `${s.ran} of ${d.variants.length} copies ran${mode === "renamed" ? ", each under its own name" : ""}. ` +
      `The hash rule caught ${s.hashOnly}, the behaviour rules and monitors ${s.caught}. ` +
      (incident === null ? "No incident yet." : "One incident.");
  };
  for (const b of buttons)
    b.addEventListener("click", () => {
      ran = Number(b.dataset.n);
      draw();
    });
  keepName.addEventListener("change", () => {
    mode = keepName.checked ? "same-name" : "renamed";
    draw();
  });

  replace(
    root,
    h(
      "div",
      { class: "panel lab" },
      h(
        "p",
        { class: "lab-note" },
        h("span", { class: "tag tag--arm" }, "Design preview"),
        " ",
        d.sample ? "Synthetic sample: generated events, not a run on real machines, and nothing here runs live." : "",
      ),
      h("h3", { class: "lab-title" }, `Scenario ${d.scenario.id}: ${d.scenario.title}`),
      h("p", { class: "small lab-summary" }, d.scenario.summary),
      h(
        "div",
        { class: "lab-controls" },
        h("div", { class: "lab-picker", role: "group", "aria-label": "How many copies have run" }, h("span", { class: "small" }, "Copies run:"), buttons),
        h("label", { class: "lab-rename small" }, keepName, " Keep one name for every copy"),
      ),
      h("div", { class: "lab-grid" }, copyEl, rulesEl),
      outcomeEl,
      takeawayEl,
      coverageEl,
      live,
    ),
  );
  draw();
}

/** The latest copy, field by field: what the attacker changed is marked, what stayed the same is not. */
function copyCard(d: LabReplay, s: LabState): HTMLElement {
  const v = d.variants[s.ran - 1];
  const first = d.variants[0];
  const name = s.names[s.ran - 1];
  const proc = v.events.find((e) => e["event.code"] === "1") ?? {};
  const net = v.events.find((e) => e["event.code"] === "3") ?? {};
  const reg = v.events.find((e) => e["event.code"] === "13") ?? {};
  const dir = d.artefact.path.slice(0, d.artefact.path.length - d.artefact.name.length);
  const rows: [string, string, boolean][] = [
    ["name", name, v.n > 1 && name !== s.names[0]],
    ["folder", dir, false],
    ["parent", String(proc["process.parent.name"] ?? ""), false],
    ["sha256", shortHash(v.sha256), v.sha256 !== first.sha256],
    ["host", v.host.split(".")[0].toUpperCase(), false],
    ["run key", String(reg["registry.path"] ?? "").split("\\").pop() ?? "", false],
    ["calls", `${net["destination.ip"]}:${net["destination.port"]}`, false],
  ];
  return h(
    "dl",
    { class: "lab-kv" },
    rows.map(([k, val, changed]) =>
      h(
        "div",
        { class: "lab-kv__row", "data-changed": String(changed) },
        h("dt", {}, k),
        h("dd", { title: k === "sha256" ? v.sha256 : null }, val, changed ? h("span", { class: "visually-hidden" }, " (changed)") : null),
      ),
    ),
  );
}

function rulesList(s: LabState): HTMLElement {
  return h(
    "ul",
    { class: "lab-rule-list", role: "list" },
    s.rules.map((r) => {
      const hits = r.fired.filter(Boolean).length;
      return h(
        "li",
        { class: "lab-rule", "data-fired": String(hits > 0) },
        h(
          "div",
          { class: "lab-rule__head" },
          h("span", { class: "lab-rule__title" }, r.rule.title),
          h("span", { class: "lab-rule__kind small" }, `${KIND_LABEL[r.rule.kind]} · ${r.rule.technique}`),
        ),
        h("p", { class: "lab-rule__logic small" }, r.rule.logic),
        h(
          "div",
          { class: "lab-rule__hits", "aria-label": `Fired on ${hits} of ${s.ran} copies` },
          r.fired.map((f, i) => h("span", { class: "lab-hit", "data-hit": String(f), title: `Copy #${i + 1}: ${f ? "fired" : "missed"}` }, f ? "●" : "○")),
          h("span", { class: "small" }, ` ${hits} of ${s.ran}`),
        ),
      );
    }),
  );
}

/** One risk meter: the bar runs to 1.6 × the threshold, the mark stands at the threshold. */
function meter(label: string, key: string, e: RiskEntity, threshold: number, note: string): HTMLElement {
  const over = e.score >= threshold;
  // CSSOM, not a style attribute: the CSP's style-src 'self' refuses inline style markup.
  const fill = h("span", { class: "lab-meter__fill" });
  fill.style.setProperty("width", `${Math.min(100, Math.round((e.score / (threshold * 1.6)) * 100))}%`);
  const mark = h("span", { class: "lab-meter__mark", title: `Incident at ${threshold}` });
  mark.style.setProperty("left", `${Math.round((1 / 1.6) * 100)}%`);
  return h(
    "div",
    { class: "lab-risk" },
    h("p", { class: "lab-risk__label" }, h("span", {}, label, " ", h("code", {}, key)), h("strong", {}, `${e.score} / ${threshold}`)),
    h("div", { class: "lab-meter", "data-over": String(over) }, fill, mark),
    h("p", { class: "small" }, note),
  );
}

function outcome(d: LabReplay, s: LabState): HTMLElement[] {
  const top = s.byName[0];
  const names = s.byName.length;
  const incidentAt = s.incidentAtByName ?? s.incidentAtByBeacon;
  const by =
    s.incidentAtByName !== null && s.incidentAtByBeacon !== null
      ? "both ways of scoring"
      : s.incidentAtByName !== null
        ? "the program's name"
        : "the address it calls";
  return [
    h(
      "div",
      { class: "lab-meters" },
      meter(
        "Scored per program name",
        top.key,
        top,
        d.risk_threshold,
        names > 1 ? `${names} names share the points; the highest has ${top.score}.` : "Every copy adds its points to the one name.",
      ),
      meter("Scored per address it calls", s.byBeacon.key, s.byBeacon, d.risk_threshold, "A new name or hash does not change where a copy calls home."),
    ),
    h(
      "div",
      { class: "lab-incident", "data-open": String(incidentAt !== null) },
      incidentAt !== null
        ? [
            h("p", { class: "lab-incident__title" }, h("span", { class: "tag tag--detect" }, "Incident"), ` One incident: ${s.ran} copies, ${s.hosts.length} ${s.hosts.length === 1 ? "host" : "hosts"}`),
            h("p", { class: "small" }, `Opened at copy #${incidentAt}, scored by ${by}; later copies join it instead of opening new ones.`),
          ]
        : [h("p", { class: "lab-incident__title" }, "No incident yet"), h("p", { class: "small" }, `Nothing has reached ${d.risk_threshold} points. Run the next copy.`)],
    ),
  ];
}

function takeaway(d: LabReplay, s: LabState): (Node | string)[] {
  const n = s.ran;
  if (s.mode === "renamed") {
    return [
      h("strong", {}, `Copy #${n}:`),
      n === 1
        ? " the hash rule hits. Run the next copies: each comes with a new hash and a new name."
        : ` the hash rule stays quiet after #1, and so does the monitor keyed on the name: every name looks new. Scored per name, no name gets past ${s.byName[0].score} points. Scored by what the copies do, here the address they all call, the same copies add up to one incident.`,
    ];
  }
  if (n === 1) return [h("strong", {}, "Copy #1, one name for all:"), " the hash rule hits. If it were the only layer, the next copy would walk past it."];
  return [h("strong", {}, `Copy #${n}, one name for all:`), ` a new hash, so the hash rule is quiet. The behaviour rules still fire, and the name keeps collecting points: ${d.artefact.name} now has ${s.byName[0].score}.`];
}

function coverageTable(d: LabReplay, s: LabState): HTMLElement {
  const rows = coverage(d, s.ran, s.mode);
  return h(
    "div",
    { class: "lab-table-wrap" },
    h(
      "table",
      { class: "lab-table" },
      h("thead", {}, h("tr", {}, h("th", { scope: "col" }, "Technique"), h("th", { scope: "col" }, "Rule"), h("th", { scope: "col" }, "Detected"), h("th", { scope: "col" }, "Time to detect"))),
      h(
        "tbody",
        {},
        rows.map((r) =>
          h(
            "tr",
            { "data-gap": String(r.detected < r.expected) },
            h("td", {}, h("code", {}, r.technique)),
            h("td", {}, r.rules.join(", ") || "none"),
            h("td", {}, `${r.detected} of ${r.expected}`),
            h("td", {}, r.mttdS === null ? "–" : `${r.mttdS} s`),
          ),
        ),
      ),
    ),
  );
}

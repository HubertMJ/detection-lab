// The detection lab preview (#lab): a replay of the incident generator's scenario C - one harmless
// test program rebuilt so each copy has a new SHA-256 - and what OpenSearch's Sigma rules and Alerting
// monitors would make of it. The data is synthetic (lab-replay.json, `sample: true`): no machine ran
// it, the page says so, and nothing here calls the API. Pure functions only; ui/lab.ts
// draws them.

export interface LabRule {
  id: string;
  title: string;
  /** "sigma": one event matches a rule; "monitor": an Alerting monitor counts across events. */
  kind: "sigma" | "monitor";
  technique: string;
  /** What the rule adds to the risk score of the program's name when it fires. */
  score: number;
  logic: string;
}

export interface LabFinding {
  rule: string;
  /** Seconds from the variant's start to the finding: the time to detect. */
  delay_s: number;
  /** "same-name": the finding exists only while every copy keeps the first copy's name. */
  only?: "same-name";
}

/** The two what-ifs the panel compares: every copy keeps one name, or every copy is renamed too. */
export type LabMode = "same-name" | "renamed";

export interface LabVariant {
  n: number;
  host: string;
  sha256: string;
  /** The copy's file name when copies are renamed as well. */
  renamed: string;
  events: Record<string, string | number>[];
  ground_truth: { "@timestamp": string; host: string; techniques: string[]; variant_sha256: string };
  findings: LabFinding[];
}

export interface LabReplay {
  schema: 1;
  sample: boolean;
  scenario: { id: string; title: string; summary: string };
  artefact: { name: string; path: string };
  /** Where every copy calls home (ip:port): the same whatever the copy's name or hash. */
  beacon: string;
  risk_threshold: number;
  rules: LabRule[];
  variants: LabVariant[];
}

const isStr = (v: unknown): v is string => typeof v === "string" && v.length > 0;
const isNum = (v: unknown): v is number => typeof v === "number" && Number.isFinite(v);
const isObj = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);

/** A replay is drawn only when every part of it is what the panel reads. */
export function isLabReplay(v: unknown): v is LabReplay {
  if (!isObj(v) || v.schema !== 1 || typeof v.sample !== "boolean" || !isNum(v.risk_threshold) || !isStr(v.beacon)) return false;
  const s = v.scenario;
  const a = v.artefact;
  if (!isObj(s) || !isStr(s.id) || !isStr(s.title) || !isStr(s.summary)) return false;
  if (!isObj(a) || !isStr(a.name) || !isStr(a.path)) return false;
  if (!Array.isArray(v.rules) || !Array.isArray(v.variants) || v.variants.length === 0) return false;
  const ids = new Set<string>();
  for (const r of v.rules) {
    if (!isObj(r) || !isStr(r.id) || !isStr(r.title) || !isStr(r.technique) || !isStr(r.logic) || !isNum(r.score)) return false;
    if (r.kind !== "sigma" && r.kind !== "monitor") return false;
    ids.add(r.id);
  }
  return v.variants.every(
    (x, i) =>
      isObj(x) &&
      x.n === i + 1 &&
      isStr(x.host) &&
      typeof x.sha256 === "string" &&
      isStr(x.renamed) &&
      /^[0-9a-f]{64}$/.test(x.sha256) &&
      Array.isArray(x.events) &&
      isObj(x.ground_truth) &&
      Array.isArray(x.findings) &&
      x.findings.every((f) => isObj(f) && isStr(f.rule) && ids.has(f.rule) && isNum(f.delay_s) && (f.only === undefined || f.only === "same-name")),
  );
}

export interface RuleState {
  rule: LabRule;
  /** Per variant run so far: whether this rule fired on it. */
  fired: boolean[];
}

/** One thing the SIEM adds risk points to: a program name, or the address the copies call. */
export interface RiskEntity {
  key: string;
  score: number;
}

export interface LabState {
  /** How many variants have run (1..variants.length). */
  ran: number;
  mode: LabMode;
  /** Each copy's name in this mode. */
  names: string[];
  rules: RuleState[];
  /** Risk scored per program name: one entity per distinct name, highest first. */
  byName: RiskEntity[];
  /** Risk scored per beacon address: every finding of a copy counts for the address it calls. */
  byBeacon: RiskEntity;
  /** The copy whose findings took an entity over the threshold, per way of scoring; null: no incident. */
  incidentAtByName: number | null;
  incidentAtByBeacon: number | null;
  hosts: string[];
  techniques: string[];
  /** Variants caught by the hash rule, and by the rules that ignore the hash (behaviour and monitors). */
  hashOnly: number;
  caught: number;
  /** Mean time to detect over the variants that ran: each variant's first finding. */
  mttdS: number | null;
}

/** The findings a copy has in a mode: renamed copies never share a name, so a per-name monitor stays quiet. */
export function findingsIn(v: LabVariant, mode: LabMode): LabFinding[] {
  return v.findings.filter((f) => f.only === undefined || f.only === mode);
}

/** What the SIEM knows after the first `ran` variants. */
export function labState(d: LabReplay, ran: number, mode: LabMode = "same-name"): LabState {
  const k = Math.max(1, Math.min(ran, d.variants.length));
  const run = d.variants.slice(0, k);
  const nameOf = (v: LabVariant) => (mode === "renamed" ? v.renamed : d.artefact.name);
  const scoreOf = new Map(d.rules.map((r) => [r.id, r.score]));
  const rules = d.rules.map((rule) => ({ rule, fired: run.map((v) => findingsIn(v, mode).some((f) => f.rule === rule.id)) }));
  const perName = new Map<string, number>();
  let beacon = 0;
  let incidentAtByName: number | null = null;
  let incidentAtByBeacon: number | null = null;
  for (const v of run) {
    const pts = findingsIn(v, mode).reduce((a, f) => a + (scoreOf.get(f.rule) ?? 0), 0);
    const name = nameOf(v);
    perName.set(name, (perName.get(name) ?? 0) + pts);
    beacon += pts;
    if (incidentAtByName === null && (perName.get(name) ?? 0) >= d.risk_threshold) incidentAtByName = v.n;
    if (incidentAtByBeacon === null && beacon >= d.risk_threshold) incidentAtByBeacon = v.n;
  }
  const hashRules = new Set(d.rules.filter((r) => r.id.startsWith("ioc-")).map((r) => r.id));
  const firsts = run.map((v) => findingsIn(v, mode)).filter((fs) => fs.length > 0).map((fs) => Math.min(...fs.map((f) => f.delay_s)));
  return {
    ran: k,
    mode,
    names: d.variants.map(nameOf),
    rules,
    byName: [...perName].map(([key, score]) => ({ key, score })).sort((a, b) => b.score - a.score),
    byBeacon: { key: d.beacon, score: beacon },
    incidentAtByName,
    incidentAtByBeacon,
    hosts: [...new Set(run.map((v) => v.host))],
    techniques: [...new Set(run.flatMap((v) => v.ground_truth.techniques))].sort(),
    hashOnly: run.filter((v) => findingsIn(v, mode).some((f) => hashRules.has(f.rule))).length,
    caught: run.filter((v) => findingsIn(v, mode).some((f) => !hashRules.has(f.rule))).length,
    mttdS: firsts.length ? Math.round(firsts.reduce((a, b) => a + b, 0) / firsts.length) : null,
  };
}

export interface CoverageRow {
  technique: string;
  /** Copies whose ground truth names the technique. */
  expected: number;
  /** Of those, the copies on which a rule for the technique fired. */
  detected: number;
  /** The rules that cover the technique, by title. */
  rules: string[];
  /** Mean seconds to the first finding for the technique, over the copies it was detected on. */
  mttdS: number | null;
}

/** Ground truth against findings, per technique: the purple-team table. */
export function coverage(d: LabReplay, ran: number, mode: LabMode = "same-name"): CoverageRow[] {
  const run = d.variants.slice(0, Math.max(1, Math.min(ran, d.variants.length)));
  const techniques = [...new Set(run.flatMap((v) => v.ground_truth.techniques))].sort();
  return techniques.map((t) => {
    const ruleIds = new Set(d.rules.filter((r) => r.technique === t).map((r) => r.id));
    const expected = run.filter((v) => v.ground_truth.techniques.includes(t));
    const delays = expected
      .map((v) => findingsIn(v, mode).filter((f) => ruleIds.has(f.rule)).map((f) => f.delay_s))
      .filter((ds) => ds.length > 0)
      .map((ds) => Math.min(...ds));
    return {
      technique: t,
      expected: expected.length,
      detected: delays.length,
      rules: d.rules.filter((r) => ruleIds.has(r.id)).map((r) => r.title),
      mttdS: delays.length ? Math.round(delays.reduce((a, b) => a + b, 0) / delays.length) : null,
    };
  });
}

/** "3f2a9c41e0b7…9d04": enough of a hash to see that it changed. */
export function shortHash(sha: string): string {
  return `${sha.slice(0, 12)}…${sha.slice(-4)}`;
}

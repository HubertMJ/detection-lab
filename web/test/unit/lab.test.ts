import { describe, expect, it } from "vitest";
import replay from "../../src/lib/lab-replay.json";
import { coverage, isLabReplay, labState, shortHash } from "../../src/lib/lab";

const d = (() => {
  if (!isLabReplay(replay)) throw new Error("lab-replay.json is not a valid replay");
  return replay;
})();

describe("detection lab replay", () => {
  it("is a synthetic sample: four copies of one name, four hashes, four different names when renamed", () => {
    expect(d.sample).toBe(true);
    expect(new Set(d.variants.map((v) => v.sha256)).size).toBe(4);
    expect(new Set(d.variants.map((v) => v.renamed)).size).toBe(4);
    for (const v of d.variants) expect(v.events.every((e) => e["process.name"] === d.artefact.name)).toBe(true);
  });

  it("same name: the hash rule catches copy #1 only; the name's score opens one incident", () => {
    const one = labState(d, 1);
    expect(one.incidentAtByName).toBeNull();
    expect(one.byName[0].score).toBeLessThan(d.risk_threshold);
    const all = labState(d, 4);
    expect(all.hashOnly).toBe(1);
    expect(all.caught).toBe(4);
    expect(all.byName).toHaveLength(1);
    expect(all.incidentAtByName).toBe(2);
    expect(all.hosts).toHaveLength(2);
  });

  it("renamed: no name gets to the threshold, the address the copies call still does", () => {
    const all = labState(d, 4, "renamed");
    expect(all.byName).toHaveLength(4);
    expect(all.incidentAtByName).toBeNull();
    expect(all.byName.every((e) => e.score < d.risk_threshold)).toBe(true);
    expect(all.incidentAtByBeacon).toBe(2);
    expect(all.rules.find((r) => r.rule.id === "same-name-new-hash")?.fired.some(Boolean)).toBe(false);
    expect(all.caught).toBe(4);
  });

  it("coverage: the hash's technique is a gap after copy #1; renaming opens a gap for T1027", () => {
    const same = coverage(d, 4);
    expect(same.find((r) => r.technique === "T1204.002")).toMatchObject({ expected: 4, detected: 1 });
    expect(same.find((r) => r.technique === "T1027")).toMatchObject({ expected: 3, detected: 3 });
    expect(coverage(d, 4, "renamed").find((r) => r.technique === "T1027")).toMatchObject({ detected: 0, mttdS: null });
  });

  it("clamps the count and refuses a malformed replay", () => {
    expect(labState(d, 0).ran).toBe(1);
    expect(labState(d, 9).ran).toBe(4);
    expect(isLabReplay({ ...d, variants: [] })).toBe(false);
    expect(isLabReplay({ ...d, variants: [{ ...d.variants[0], findings: [{ rule: "nope", delay_s: 1 }] }] })).toBe(false);
    expect(shortHash("a".repeat(64))).toBe(`${"a".repeat(12)}…aaaa`);
  });
});

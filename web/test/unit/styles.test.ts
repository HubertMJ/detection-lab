// The stylesheet's braces balance: one lost "}" (a merge once dropped one) silently nests every rule
// after it inside the previous one, and the browser throws those rules away.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

describe("styles.css", () => {
  it("opens and closes every block", () => {
    const css = readFileSync(join(process.cwd(), "src", "styles.css"), "utf8").replace(/\/\*[\s\S]*?\*\//g, "");
    let depth = 0;
    for (const ch of css) {
      if (ch === "{") depth++;
      else if (ch === "}") depth--;
      expect(depth).toBeGreaterThanOrEqual(0);
    }
    expect(depth).toBe(0);
  });
});

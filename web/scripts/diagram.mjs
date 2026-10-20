// Writes README.md's "How it fits together" diagram from src/diagram/model.ts (`npm run diagram`): the
// mermaid between the two markers is the model's, so the README and the /lab/ page draw the same thing.
// A unit test (test/unit/diagram.test.ts) fails when the committed copy differs.
//
//   node scripts/diagram.mjs            rewrite the block
//   node scripts/diagram.mjs --check    exit 1 if the README's copy is stale

import { readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { loadDiagram } from "./diagram-lib.mjs";

const readme = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "README.md");
export const START = "<!-- diagram: generated from web/src/diagram/model.ts by `npm run diagram` in web/; do not edit -->";
export const END = "<!-- /diagram -->";

const { mermaid, validate } = await loadDiagram();
const problems = validate();
if (problems.length) {
  console.error(problems.join("\n"));
  process.exit(1);
}
const text = await readFile(readme, "utf8");
const i = text.indexOf(START);
const j = text.indexOf(END);
if (i < 0 || j < i) {
  console.error(`README.md has no diagram block (${START} ... ${END})`);
  process.exit(1);
}
const next = `${text.slice(0, i)}${START}\n\`\`\`mermaid\n${mermaid()}\n\`\`\`\n${text.slice(j)}`;
if (process.argv.includes("--check")) {
  if (next !== text) {
    console.error("README.md's diagram is stale: run `npm run diagram` in web/");
    process.exit(1);
  }
  console.log("README diagram: current");
} else {
  await writeFile(readme, next);
  console.log("wrote the README diagram");
}

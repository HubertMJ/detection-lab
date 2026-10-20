// Loads src/diagram/index.ts for a Node script: esbuild bundles it in memory and the module is imported
// from a data: URL, so the build, scripts/diagram.mjs and the page share the one TypeScript model
// without a compiled copy on disk.

import * as esbuild from "esbuild";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

export async function loadDiagram() {
  const r = await esbuild.build({ absWorkingDir: root, entryPoints: ["src/diagram/index.ts"], bundle: true, write: false, format: "esm", platform: "neutral", logLevel: "warning" });
  return import(`data:text/javascript;base64,${Buffer.from(r.outputFiles[0].text, "utf8").toString("base64")}`);
}

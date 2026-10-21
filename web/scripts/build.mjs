// Builds src/ into dist/: content-hashed JS and CSS under dist/lab/assets/, the page with the hashed
// names substituted, and static/ copied in beside it. Everything this image serves lives under the
// /lab/ prefix (dist/lab/...), so it never collides with the landing site on the same origin: the
// Gateway routes /lab/ and /lab/assets/ here. The hashed names let nginx serve /lab/assets/* as
// immutable for a year while the page is revalidated on every visit.
//
//   node scripts/build.mjs                  into dist/
//   node scripts/build.mjs --outdir <dir>   into <dir> instead (relative to the repository root)

import * as esbuild from "esbuild";
import { execFileSync } from "node:child_process";
import { cp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { loadDiagram } from "./diagram-lib.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const i = process.argv.indexOf("--outdir");
const out = resolve(root, i > 0 ? process.argv[i + 1] : "dist");

/** The pages this image serves, under the /lab/ prefix. */
const PAGES = [{ src: "src/lab.html", out: "lab/index.html" }];

/**
 * The diagram's traffic: its dots' routes and timing, drawn from the same layout into a stylesheet that
 * styles.css imports (`@import "diagram-traffic.css"`), so it is bundled into the one hashed CSS file
 * (the CSP allows no inline style, and offset-path needs the route).
 */
const trafficPlugin = {
  name: "diagram-traffic",
  setup(build) {
    build.onResolve({ filter: /^diagram-traffic\.css$/ }, () => ({ path: "diagram-traffic.css", namespace: "diagram" }));
    build.onLoad({ filter: /.*/, namespace: "diagram" }, async () => {
      const { trafficCss } = await loadDiagram();
      return { contents: trafficCss(), loader: "css" };
    });
  },
};

await rm(out, { recursive: true, force: true });
await mkdir(join(out, "lab", "assets"), { recursive: true });

const result = await esbuild.build({
  absWorkingDir: root,
  entryPoints: ["src/lab-page.ts", "src/theme.ts", "src/styles.css"],
  outdir: join(out, "lab", "assets"),
  entryNames: "[name]-[hash]",
  bundle: true,
  minify: true,
  format: "iife",
  target: ["es2022", "chrome110", "firefox110", "safari16"],
  metafile: true,
  legalComments: "none",
  // ASCII mode's font (src/ascii/fonts), emitted beside the CSS with a content hash like the rest.
  loader: { ".woff2": "file" },
  assetNames: "[name]-[hash]",
  logLevel: "warning",
  plugins: [trafficPlugin],
});

// The architecture diagram (src/diagram): its two drawings go into the page as inline SVG, so it is there
// before any script runs and never shifts the layout.
const diagram = await loadDiagram();
const problems = diagram.validate();
if (problems.length) throw new Error(`src/diagram/model.ts: ${problems.join("; ")}`);
const names = { "diagram.wide": diagram.svg(diagram.wide()), "diagram.narrow": diagram.svg(diagram.narrow()) };
for (const [file, meta] of Object.entries(result.metafile.outputs)) {
  if (!meta.entryPoint) continue;
  const ext = file.endsWith(".css") ? "css" : "js";
  names[`${basename(meta.entryPoint).replace(/\.(ts|css)$/, "")}.${ext}`] = basename(file);
}
for (const p of PAGES) {
  const html = (await readFile(join(root, p.src), "utf8")).replace(/\{\{([\w.-]+)\}\}/g, (_, key) => {
    if (!names[key]) throw new Error(`${p.src} references {{${key}}} but no such entry was built`);
    return names[key];
  });
  await mkdir(dirname(join(out, p.out)), { recursive: true });
  await writeFile(join(out, p.out), html);
}
// Served under /lab/ too (favicon at /lab/favicon.svg), so the image is self-contained behind the prefix.
await cp(join(root, "static"), join(out, "lab"), { recursive: true });
// /lab/build.json: the commit this was built from, which the console greeting shows. The image's final
// stage writes it again from CI's own values (the builder stage has no .git); a local build takes git's.
let commit = "";
try {
  commit = execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
} catch {
  // Not a checkout: the greeting goes out without the commit.
}
await writeFile(join(out, "lab", "build.json"), `${JSON.stringify({ commit: /^[0-9a-f]{40}$/.test(commit) ? commit : "", ci_run_id: "" })}\n`);
console.log(`built: ${Object.entries(names).filter(([k]) => !k.startsWith("diagram.")).map(([, v]) => v).join(", ")}`);

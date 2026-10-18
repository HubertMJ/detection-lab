// Serves dist/ on http://127.0.0.1:4173 for local viewing and the e2e tests. Static files only; the
// page lives at /lab/ (dist/lab/index.html). /cluster/* and /api belong to the cluster deployment and
// answer 404 here, which is why the page's fetch of /cluster/api/lab/latest falls back to the bundled
// sample. Every response carries the headers in security-headers.conf, the CSP with Trusted Types
// included, so the e2e tests run under the policy nginx serves.
//
//   node scripts/serve.mjs [--dir dist] [--port 4173] (the e2e tests use 4290)

import { createServer } from "node:http";
import { readFileSync } from "node:fs";
import { readFile, stat } from "node:fs/promises";
import { extname, join, normalize, resolve } from "node:path";

const arg = (n, d) => {
  const i = process.argv.indexOf(n);
  return i > 0 ? process.argv[i + 1] : d;
};
const dir = resolve(arg("--dir", "dist"));
const port = Number(arg("--port", "4173"));
// The cluster API seam the page fetches. Deterministic here: a fast 404 (so the bundled-sample
// fallback is exercised and nothing hangs), or, when --lab-run <file> is given, that file as a 200.
const API = "/cluster/api/lab/latest";
const labRunFile = arg("--lab-run", null);

// Test-only stand-in for the main site (/), which another image serves on this origin. The e2e slide
// tests navigate from /lab/ to / to prove the hand-played "back to home" slide (styles.css, theme.ts);
// with --e2e this server answers / with a minimal page carrying the lab page's real <head> (so its
// theme.js runs and the arrival slide plays) instead of a 404. Never on for `npm run serve`; nginx
// (the image) still 404s it.
const standins = process.argv.includes("--e2e") ? new Set(["/"]) : null;
const standinBody = () => {
  const html = readFileSync(join(dir, "lab", "index.html"), "utf8");
  const head = [...html.matchAll(/<link\s+rel="stylesheet"[^>]*>|<script\s+src="[^"]*"(?![^>]*type="module")[^>]*><\/script>/g)].map((m) => m[0]).join("");
  return `<!DOCTYPE html><html lang="en"><head><title>stand-in</title>${head}</head><body><header class="site-header"><a class="brand" href="/">home</a></header><main class="landing">stand-in</main></body></html>`;
};
const TYPES = { ".html": "text/html; charset=utf-8", ".js": "text/javascript", ".css": "text/css", ".svg": "image/svg+xml", ".txt": "text/plain", ".json": "application/json" };

const HEADERS = Object.fromEntries(
  [...readFileSync(new URL("../security-headers.conf", import.meta.url), "utf8").matchAll(/^add_header\s+(\S+)\s+"([^"]*)"/gm)].map((m) => [m[1], m[2]]),
);

createServer(async (req, res) => {
  let path = normalize(decodeURIComponent(new URL(req.url ?? "/", "http://localhost").pathname));
  // The API seam answers immediately, before any filesystem work: a fixture 200 when configured,
  // otherwise a fast 404. The page never blocks on it either way.
  if (path === API) {
    if (labRunFile) {
      try {
        const body = await readFile(resolve(labRunFile));
        res.writeHead(200, { ...HEADERS, "content-type": TYPES[".json"] });
        res.end(body);
        return;
      } catch {
        // Missing or unreadable fixture: fall through to a 404, the fallback path.
      }
    }
    res.writeHead(404, { ...HEADERS, "content-type": "text/plain" });
    res.end("not found\n");
    return;
  }
  if (path.endsWith("/")) path += "index.html";
  const file = join(dir, path);
  try {
    if (!file.startsWith(dir) || !(await stat(file)).isFile()) throw new Error("not a file");
    res.writeHead(200, { ...HEADERS, "content-type": TYPES[extname(file)] ?? "application/octet-stream" });
    res.end(await readFile(file));
  } catch {
    const base = path.endsWith("/index.html") ? path.slice(0, -"index.html".length) : path;
    if (standins?.has(base)) {
      res.writeHead(200, { ...HEADERS, "content-type": TYPES[".html"] });
      res.end(standinBody());
      return;
    }
    res.writeHead(404, { ...HEADERS, "content-type": "text/plain" });
    res.end("not found\n");
  }
}).listen(port, "127.0.0.1", () => console.log(`serving ${dir} on http://127.0.0.1:${port}`));

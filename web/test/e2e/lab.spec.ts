import { readFileSync } from "node:fs";
import { expect, test } from "@playwright/test";

// The detection lab's preview, served standalone at /lab/. The main site (/) lives in another image
// on the same origin; for the slide tests, scripts/serve.mjs --e2e stands it in with a page carrying
// this page's own <head>, so the cross-document slide runs exactly as it does live (a real served
// page, so it works in Firefox too, where route interception misses top-level navigations).

test.describe("detection lab preview at /lab/", () => {
  // The architecture diagram (src/diagram, inline SVG from the build): the drawing for the width is
  // shown, every word inside its box, no line through a box, nothing wider than the page; it is in
  // the HTML before any script runs, so the page never shifts when the API answers.
  test("the run diagram fits its boxes at this width and never moves the page", async ({ page }, info) => {
    await page.goto("/lab/");
    const shown = info.project.name === "phone" ? "narrow" : "wide";
    await expect(page.locator(`.lab-diagram__svg--${shown}`)).toBeVisible();
    await expect(page.locator(`.lab-diagram__svg--${shown === "wide" ? "narrow" : "wide"}`)).toBeHidden();
    const problems = await page.evaluate((view) => {
      const out: string[] = [];
      const svg = document.querySelector<SVGSVGElement>(`.lab-diagram__svg--${view}`);
      if (!svg) return ["no diagram"];
      const rects = [...svg.querySelectorAll<SVGRectElement>(".ld-node rect")].map((r) => r.getBBox());
      for (const t of svg.querySelectorAll<SVGTextElement>(".ld-node text")) {
        const b = t.getBBox();
        const box = rects.find((r) => b.x + b.width / 2 > r.x && b.x + b.width / 2 < r.x + r.width && b.y + b.height / 2 > r.y && b.y + b.height / 2 < r.y + r.height);
        if (!box || b.x < box.x + 6 || b.x + b.width > box.x + box.width - 6) out.push(`"${t.textContent}" leaves its box`);
      }
      for (const e of svg.querySelectorAll<SVGPathElement>(".ld-line")) {
        for (let l = 0; l <= e.getTotalLength(); l += 2) {
          const p = e.getPointAtLength(l);
          if (rects.some((r) => p.x > r.x + 1 && p.x < r.x + r.width - 1 && p.y > r.y + 1 && p.y < r.y + r.height - 1)) {
            out.push(`a line runs through a box at ${Math.round(p.x)},${Math.round(p.y)}`);
            break;
          }
        }
      }
      // Edge labels clear of each other and of every line.
      const labels = [...svg.querySelectorAll<SVGTextElement>(".ld-edgelabel")].map((t) => [t.textContent, t.getBBox()] as const);
      for (const [i, [a, ba]] of labels.entries()) {
        for (const [b, bb] of labels.slice(i + 1)) if (ba.x < bb.x + bb.width && ba.x + ba.width > bb.x && ba.y < bb.y + bb.height && ba.y + ba.height > bb.y) out.push(`"${a}" overlaps "${b}"`);
        for (const e of svg.querySelectorAll<SVGPathElement>(".ld-line")) {
          for (let l = 0; l <= e.getTotalLength(); l += 2) {
            const p = e.getPointAtLength(l);
            if (p.x > ba.x && p.x < ba.x + ba.width && p.y > ba.y && p.y < ba.y + ba.height) {
              out.push(`"${a}" sits on a line`);
              break;
            }
          }
        }
      }
      // It starts where the landing page's and /cluster/'s diagrams start: the way in, in reading order.
      const at = (id: string) => svg.querySelector<SVGGElement>(`.ld-node[data-node="${id}"] rect`)?.getBBox();
      const path = ["visitor", "edge", "cloudflared", "gateway"].map(at);
      const reads = view === "wide" ? (p: DOMRect, q: DOMRect) => p.x < q.x : (p: DOMRect, q: DOMRect) => p.y < q.y;
      for (let i = 1; i < path.length; i++) if (!path[i - 1] || !path[i] || !reads(path[i - 1] as DOMRect, path[i] as DOMRect)) out.push(`the way in is out of order at ${i}`);
      if (document.documentElement.scrollWidth > document.documentElement.clientWidth) out.push("horizontal scroll");
      return out;
    }, shown);
    await expect(page.locator(".ld-legend")).toBeVisible();
    expect(problems).toEqual([]);
    // Present in the served HTML itself, not drawn by a script.
    const html = await (await page.request.get("/lab/")).text();
    expect(html).toContain('class="lab-diagram__svg lab-diagram__svg--wide"');
    expect(html).toContain('class="lab-diagram__svg lab-diagram__svg--narrow"');
    const before = await page.locator("#lab-diagram").boundingBox();
    await page.waitForLoadState("networkidle");
    await page.waitForTimeout(300);
    const after = await page.locator("#lab-diagram").boundingBox();
    expect(after?.height).toBe(before?.height);
  });

  test("renames every copy by default; picking a copy redraws the panel and never scrolls the page", async ({ page }) => {
    await page.goto("/lab/");
    await expect(page.locator(".lab-rename__box")).not.toBeChecked();
    await page.locator(".lab-picker").scrollIntoViewIfNeeded();
    const y = await page.evaluate(() => scrollY);
    await page.evaluate(() => document.querySelector<HTMLButtonElement>('.lab-picker__btn[data-n="4"]')?.click());
    await expect(page.locator(".lab-incident")).toHaveAttribute("data-open", "true");
    await expect(page.locator(".lab-kv__row[data-changed=true]")).toHaveCount(2);
    expect(await page.evaluate(() => scrollY)).toBe(y);
    await page.evaluate(() => document.querySelector<HTMLInputElement>(".lab-rename__box")?.click());
    await expect(page.locator(".lab-kv__row[data-changed=true]")).toHaveCount(1);
    expect(await page.evaluate(() => scrollY)).toBe(y);
  });

  // The real run comes from /cluster/api/lab/latest; when that answers with a valid run, the panel
  // draws it: no "synthetic sample" label, the mode wording for a generated run, and the run date.
  test("draws the run the cluster API returns", async ({ page }) => {
    await page.route("**/cluster/api/lab/latest", (r) => r.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(REAL_RUN) }));
    await page.goto("/lab/");
    await expect(page.locator(".lab")).toBeVisible();
    await expect(page.locator(".lab-note")).not.toContainText("Synthetic sample");
    await expect(page.locator(".lab-note")).toContainText("events generated, detection real");
    await expect(page.locator(".lab-note time")).toContainText("3 Feb 2026");
    await expect(page.locator(".lab-note time")).toHaveAttribute("datetime", "2026-02-03T10:00:00Z");
    await expect(page.locator(".lab-table tbody tr")).not.toHaveCount(0);
    // The hero follows the data too: "live", and the lead drops the "synthetic sample" disclaimer.
    await expect(page.locator("#lab-eyebrow")).toContainText("live");
    await expect(page.locator("#lab-lead")).toContainText("latest daily run");
    await expect(page.locator("#lab-lead")).not.toContainText("not a run on real machines");
    // The closing line states the SIEM wiring is done, not a next step, and keeps the cluster link.
    await expect(page.locator("#lab-next")).not.toContainText("Next step");
    await expect(page.locator("#lab-next")).toContainText("come from its real rules");
    await expect(page.locator('#lab-next a[href="/cluster/#correlation"]')).toHaveCount(1);
  });

  // A real run on the isolated VM (variant B): the panel draws the machine — the lifecycle timeline,
  // per-copy evidence with raw Sysmon, the status strip and run history — not the copy-picker replay.
  test("draws the isolated-VM (variant B) run with its live layer", async ({ page }) => {
    await page.route("**/cluster/api/lab/latest", (r) => r.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(VM_RUN) }));
    await page.route("**/cluster/api/lab/vm", (r) => r.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ state: "off", last_restore: "2026-10-19T03:00:03Z", next_run: "2026-10-20T03:00:00Z" }) }));
    await page.goto("/lab/");
    // the animated replay: controls, feeds and the copy lanes
    await expect(page.locator(".lab-rp-play")).toBeVisible();
    await expect(page.locator(".lab-rp-lane")).toHaveCount(2);
    await expect(page.locator(".lab-rp-feed").first()).toBeVisible();
    await expect(page.locator(".lab-vm-timeline")).toBeVisible();
    await expect(page.locator(".lab-vm-copy")).toHaveCount(2);
    await expect(page.locator(".lab-vm-status__state")).toContainText("powered off");
    await expect(page.locator(".lab-vm-hist__dot")).toHaveCount(2);
    await expect(page.locator(".lab-vm-raw").first()).toBeVisible();
    // the sample is labelled a sample, never a real run
    await expect(page.locator(".lab-note")).toContainText("Sample");
    await expect(page.locator("#lab-replay-eyebrow")).toContainText("Sample run");
  });

  // A real B run (lab-20261019T191309Z-4e396b, siem01's own answers): the live status line, the
  // replay's event count equal to the run's, feeds that never cut a line, and the raw records.
  test("draws a real isolated-VM run: status line, event count, whole lines, raw records", async ({ page }) => {
    const run = JSON.parse(readFileSync(new URL("./fixtures/vm-run-real.json", import.meta.url), "utf8"));
    const raw = readFileSync(new URL("./fixtures/vm-raw-real.json", import.meta.url), "utf8");
    await page.route("**/cluster/api/lab/latest", (r) => r.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(run) }));
    await page.route("**/cluster/api/lab/vm", (r) => r.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ state: "off", last_restore: "2026-10-20T06:56:24Z", snapshot_clean: true, next_run: "2026-10-21T03:00:00Z" }) }));
    await page.route("**/cluster/api/lab/raw", (r) => r.fulfill({ status: 200, contentType: "application/json", body: raw }));
    await page.emulateMedia({ reducedMotion: "reduce" }); // the finished state at once
    await page.goto("/lab/");
    await expect(page.locator(".lab-note")).toContainText("Live · A real run on an isolated VM · 3:10 on the VM ·");
    await expect(page.locator(".lab-rp-c__n").nth(1)).toHaveText(String(run.counters.events));
    await expect(page.locator(".lab-vm-status__meta")).toContainText("clean snapshot");
    for (const feed of await page.locator(".lab-rp-feed").all()) {
      const fit = await feed.evaluate((el) => {
        const box = el.getBoundingClientRect();
        const lines = [...el.children].map((c) => c.getBoundingClientRect());
        return el.scrollHeight <= el.clientHeight && lines.every((l) => l.top >= box.top && l.bottom <= box.bottom);
      });
      expect(fit, "every line of a feed is whole").toBe(true);
    }
    await page.locator(".lab-vm-raw summary").first().click();
    await expect(page.locator(".lab-vm-raw summary").first()).toContainText("as indexed in sdp-lab");
  });

  // No endpoint (the standalone image): the page falls back to the bundled synthetic sample, labelled
  // as generated, and still renders the whole preview.
  test("falls back to the bundled synthetic sample when the API 404s", async ({ page }) => {
    await page.goto("/lab/");
    await expect(page.locator(".lab-note")).toContainText("Synthetic sample");
    await expect(page.locator(".lab-table tbody tr")).not.toHaveCount(0);
    await expect(page.locator(".lab-meter")).toHaveCount(2);
    // The hero keeps the static "design preview" wording on the sample fallback.
    await expect(page.locator("#lab-eyebrow")).toContainText("design preview");
    await expect(page.locator("#lab-lead")).toContainText("not a run on real machines");
    await expect(page.locator("#lab-next")).toContainText("Next step");
  });

  test("loads where it starts, without a console error, inline style or policy violation; assets under /lab/", async ({ page }) => {
    const errors: string[] = [];
    page.on("console", (m) => m.type() === "error" && errors.push(m.text()));
    page.on("pageerror", (e) => errors.push(String(e)));
    await page.addInitScript(() => {
      addEventListener("securitypolicyviolation", (e) => console.error(`CSP: ${e.violatedDirective} ${e.blockedURI}`));
    });
    // Stand in for the cluster API so the happy path makes no failing request.
    await page.route("**/cluster/api/lab/latest", (r) => r.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(REAL_RUN) }));

    const local: string[] = [];
    page.on("request", (r) => {
      const u = new URL(r.url());
      if (u.origin === "http://127.0.0.1:4290" && r.resourceType() !== "document") local.push(u.pathname);
    });
    const res = await page.goto("/lab/");
    expect(res?.headers()["content-security-policy"]).toContain("require-trusted-types-for 'script'");
    await page.waitForLoadState("networkidle");
    await page.waitForTimeout(1200);
    expect(await page.evaluate(() => scrollY), "/lab/ scrolled by itself").toBe(0);
    // As served (a script may still set a size through the CSSOM, which the CSP allows).
    expect(await res?.text(), "/lab/ inline styles").not.toMatch(/<style|\sstyle=/);
    // Static assets come from /lab/assets/ (and the favicon from /lab/). The one other request is the
    // API seam, /cluster/api/lab/latest, which is same-origin and allowed by connect-src 'self'.
    const outside = local.filter((p) => !p.startsWith("/lab/assets/") && p !== "/lab/favicon.svg" && p !== "/cluster/api/lab/latest");
    expect(outside, "requests outside /lab/assets/").toEqual([]);
    expect(errors).toEqual([]);
  });

  test("moving home slides like switching desktops: going back slides the other way; the header stays", async ({ page }) => {
    await page.addInitScript(() => {
      addEventListener("pagereveal", (e) => {
        const vt = (e as Event & { viewTransition?: { types: Set<string> } | null }).viewTransition;
        setTimeout(() => ((window as unknown as { vt: string }).vt = vt ? [...vt.types].join(",") || "fade" : "none"));
      });
    });
    const vt = () => page.waitForFunction(() => (window as unknown as { vt?: string }).vt).then((h) => h.jsonValue());
    await page.goto("/lab/");
    await Promise.all([page.waitForURL((u) => u.pathname === "/"), page.locator(".site-header a.brand").click()]);
    expect(await vt()).toBe("backward");
    expect(await page.locator(".site-header").evaluate((el) => getComputedStyle(el).viewTransitionName)).toBe("site-header");
  });

  test("@firefox Firefox slides home by hand: the page slides out, then the main site slides in", async ({ page }) => {
    await page.addInitScript(() => {
      const seen: string[] = [];
      (window as unknown as { slides: string[] }).slides = seen;
      new MutationObserver(() => {
        for (const c of document.documentElement.classList) if (c.startsWith("slide-") && !seen.includes(c)) seen.push(c);
      }).observe(document, { attributes: true, subtree: true, attributeFilter: ["class"] });
    });
    const slides = () => page.evaluate(() => (window as unknown as { slides: string[] }).slides);
    await page.goto("/lab/");
    await page.click(".site-header a.brand");
    expect(await slides()).toEqual(["slide-out-backward"]);
    await page.waitForURL((u) => u.pathname === "/");
    await expect.poll(slides).toEqual(["slide-in-backward"]);
  });
});

// A valid run document the API stub returns: a real run (sample: false), so the page labels it as one.
const REAL_RUN = {
  schema: 1,
  sample: false,
  run: { id: "lab-20260203T100000Z-abc123", mode: "generated", started_at: "2026-02-03T09:00:00Z", finished_at: "2026-02-03T10:00:00Z" },
  scenario: { id: "C", title: "stand-in", summary: "stand-in" },
  artefact: { name: "update-helper.exe", path: "C:\\x\\update-helper.exe" },
  beacon: "lab beacon :8443",
  risk_threshold: 100,
  rules: [{ id: "ioc-known-hash", title: "hash", kind: "sigma", technique: "T1204.002", score: 60, logic: "x" }],
  variants: [
    { n: 1, host: "ws1", sha256: "a".repeat(64), renamed: "a.exe", events: [], ground_truth: { "@timestamp": "2026-01-01T00:00:00Z", host: "ws1", techniques: ["T1204.002"], variant_sha256: "a".repeat(64) }, findings: [{ rule: "ioc-known-hash", delay_s: 1 }] },
  ],
} as const;

// A sample isolated-VM run (variant B): sample:true, so the page shows it as a sample, never real.
const VM_RUN = {
  schema: 1,
  sample: true,
  run: { id: "lab-20261019T030045Z-7f3a1c", mode: "isolated-vm", started_at: "2026-10-19T03:00:45Z", finished_at: "2026-10-19T03:11:36Z", duration_s: 651 },
  scenario: { id: "C", title: "stand-in", summary: "stand-in" },
  artefact: { name: "update-helper", path: "/tmp/update-helper" },
  beacon: "lab beacon :8080",
  risk_threshold: 100,
  counters: { processes: 2, unique_hashes: 2, events: 6, findings: 3, incidents: 1 },
  lifecycle: [
    { marker: "rollback", offset_s: 0, label: "Reverted to clean snapshot" },
    { marker: "poweroff_requested", offset_s: 651, label: "Powered off" },
  ],
  history: [
    { id: "lab-20261019T030045Z-7f3a1c", finished_at: "2026-10-19T03:11:36Z", duration_s: 651, ok: true },
    { id: "lab-20261018T030041Z-2b9e04", finished_at: "2026-10-18T03:11:28Z", duration_s: 643, ok: false },
  ],
  incident: { opened_at_variant: 2, delay_s: 41, key: "beacon", at_offset_s: 272 },
  techniques: { expected: ["T1027", "T1204.002"], detected: ["T1204.002"] },
  rules: [{ id: "ioc-lab-known-hash", title: "hash", kind: "sigma", technique: "T1204.002", score: 50, logic: "x" }],
  variants: [
    { n: 1, host: "lab-vm", sha256: "a".repeat(64), renamed: "update-helper", pid: 1487, ppid: 1203, caught_by_hash: true,
      events: [{ "@timestamp": "2026-10-19T03:01:30Z", "event.code": "1", "event.action": "process-create", "host.name": "lab-vm", "process.name": "update-helper", "process.executable": "/tmp/update-helper", "process.hash.sha256": "a".repeat(64), "process.pid": 1487, "process.parent.pid": 1203 }],
      ground_truth: { "@timestamp": "2026-10-19T03:01:30Z", host: "lab-vm", techniques: ["T1204.002"], variant_sha256: "a".repeat(64) },
      findings: [{ rule: "ioc-lab-known-hash", delay_s: 12, at_offset_s: 57 }] },
    { n: 2, host: "lab-vm", sha256: "b".repeat(64), renamed: "svc-d72cfbd3", pid: 1613, ppid: 1203, caught_by_hash: false,
      events: [{ "@timestamp": "2026-10-19T03:04:30Z", "event.code": "3", "event.action": "network-connection", "host.name": "lab-vm", "process.name": "svc-d72cfbd3", "destination.ip": "lab beacon :8080", "destination.port": 8080 }],
      ground_truth: { "@timestamp": "2026-10-19T03:04:30Z", host: "lab-vm", techniques: ["T1204.002", "T1027"], variant_sha256: "b".repeat(64) },
      findings: [] },
  ],
} as const;

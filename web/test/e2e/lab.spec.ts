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

  // "Start run now": the button POSTs a request (the API only queues it), refusals read in plain words,
  // and while the VM runs the page draws the run live from its raw records (no verdict yet).
  test("Start run now: queues a run, explains refusals, follows a run live", async ({ page }) => {
    const run = readFileSync(new URL("./fixtures/vm-run-real.json", import.meta.url), "utf8");
    const partial = readFileSync(new URL("./fixtures/vm-raw-partial-real.json", import.meta.url), "utf8");
    let vmState = "off";
    let posts = 0;
    let postStatus = 202;
    await page.route("**/cluster/api/lab/latest", (r) => r.fulfill({ status: 200, contentType: "application/json", body: run }));
    await page.route("**/cluster/api/lab/vm", (r) => r.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ state: vmState, last_restore: "2026-10-20T06:56:24Z", snapshot_clean: true, next_run: "2026-10-21T03:00:00Z" }) }));
    await page.route("**/cluster/api/lab/raw", (r) => r.fulfill({ status: 200, contentType: "application/json", body: partial }));
    await page.route("**/cluster/api/lab/run", (r) => {
      if (r.request().method() === "POST") {
        posts++;
        return r.fulfill({ status: postStatus, contentType: "application/json", body: JSON.stringify(postStatus === 202 ? { id: "r1", state: "queued" } : { error: "cooldown" }) });
      }
      return r.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(vmState === "running"
        ? { state: "running", can_start: false, runs_today: 3, max_per_day: 12 }
        : { state: "available", can_start: true, runs_today: 2, max_per_day: 12 }) });
    });
    await page.emulateMedia({ reducedMotion: "reduce" });
    await page.goto("/lab/");
    const btn = page.locator(".lab-run__btn");
    await expect(btn).toBeEnabled();
    await expect(page.locator(".lab-run__msg")).toContainText("10 of 12 runs left today");
    await btn.scrollIntoViewIfNeeded(); // Playwright scrolls to what it clicks; measure after that
    // The page scrolls smoothly (scroll-behavior: smooth), so wait for that scroll to come to rest.
    await page.waitForFunction(() => new Promise((ok) => { const a = scrollY; setTimeout(() => ok(scrollY === a), 300); }));
    const y = await page.evaluate(() => window.scrollY);
    // A DOM click: Playwright's own click scrolls the target to the centre first, which is not the
    // page moving; this checks that the page itself never scrolls.
    await btn.evaluate((b) => (b as HTMLButtonElement).click());
    await expect(page.locator(".lab-run__msg")).toContainText("queued");
    expect(posts).toBe(1);
    expect(await page.evaluate(() => window.scrollY)).toBe(y); // clicking never scrolls the page
    // the VM starts: the panel follows the run live from its raw records
    vmState = "running";
    await expect(page.locator(".lab-note")).toContainText("Running now on an isolated VM", { timeout: 15000 });
    await expect(page.locator(".lab-vm-copy")).toHaveCount(4);
    await expect(page.locator(".lab-vm-chips")).toHaveCount(0);
    await expect(page.locator(".lab-run__btn")).toBeDisabled();
  });

  test("Start run now: a refused request says why", async ({ page }) => {
    const run = readFileSync(new URL("./fixtures/vm-run-real.json", import.meta.url), "utf8");
    await page.route("**/cluster/api/lab/latest", (r) => r.fulfill({ status: 200, contentType: "application/json", body: run }));
    await page.route("**/cluster/api/lab/vm", (r) => r.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ state: "off" }) }));
    await page.route("**/cluster/api/lab/run", (r) => r.request().method() === "POST"
      ? r.fulfill({ status: 429, contentType: "application/json", body: JSON.stringify({ error: "daily limit" }) })
      : r.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ state: "available", can_start: true }) }));
    await page.goto("/lab/");
    await page.locator(".lab-run__btn").click();
    await expect(page.locator(".lab-run__msg")).toContainText("Today's runs are used up");
  });

  test("Start run now is hidden without the run endpoint", async ({ page }) => {
    const run = readFileSync(new URL("./fixtures/vm-run-real.json", import.meta.url), "utf8");
    await page.route("**/cluster/api/lab/latest", (r) => r.fulfill({ status: 200, contentType: "application/json", body: run }));
    await page.goto("/lab/");
    await expect(page.locator(".lab-vm-copy").first()).toBeVisible();
    await expect(page.locator(".lab-run")).toBeHidden();
  });

  // The beacon monitor's story as a drawing: four copies converge on one address, the monitor's gauge
  // crosses its threshold at the second distinct hash, one incident; boxes open captions; no overflow.
  test("how four copies became one incident: the drawing, its final state, captions, no overflow", async ({ page }, info) => {
    const run = readFileSync(new URL("./fixtures/vm-run-real-pinned.json", import.meta.url), "utf8");
    await page.route("**/cluster/api/lab/latest", (r) => r.fulfill({ status: 200, contentType: "application/json", body: run }));
    await page.emulateMedia({ reducedMotion: "reduce" });
    await page.goto("/lab/");
    const li = page.locator("section.li");
    await expect(li).toHaveAttribute("data-fired", "true");
    const svgSel = info.project.name === "phone" ? ".li-svg--narrow" : ".li-svg--wide";
    const fig = page.locator(svgSel);
    await expect(fig).toBeVisible();
    // the section's styles apply (a lost brace once swallowed them all, live)
    expect(await fig.evaluate((el) => getComputedStyle(el).display)).toBe("block");
    await expect(fig.locator('[data-node="inc"]')).toHaveAttribute("data-state", "incident");
    await expect(fig.locator('[data-node="hash"]')).toHaveAttribute("data-state", "detect");
    for (const n of [1, 2, 3, 4]) await expect(fig.locator(`[data-node="c${n}"]`)).toHaveAttribute("data-state", "run");
    await expect(fig.locator("[data-count]")).toHaveText("4 ≥ 2");
    await expect(fig.locator('.li-gauge__pip[data-on="true"]')).toHaveCount(4);
    await expect(page.locator(".li-status")).toContainText("One incident");
    // every label sits inside its box, and no line runs through a box it does not touch
    const fit = await fig.evaluate((svg) => {
      const nodes = [...svg.querySelectorAll(".ld-node")].map((g) => ({ r: g.querySelector("rect")!.getBBox(), t: [...g.querySelectorAll("text")].map((t) => (t as SVGTextElement).getBBox()) }));
      const inside = nodes.every(({ r, t }) => t.every((b) => b.x >= r.x - 0.5 && b.x + b.width <= r.x + r.width + 0.5 && b.y >= r.y - 0.5 && b.y + b.height <= r.y + r.height + 0.5));
      return inside;
    });
    expect(fit, "every label inside its box").toBe(true);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
    // a box opens its caption with the rule's source; Escape closes it
    const mon = fig.locator('[data-node="mon"]');
    await mon.focus();
    await page.keyboard.press("Enter");
    await expect(page.locator(".li-caption")).toBeVisible();
    await expect(page.locator('.li-caption a[href$="siem/monitors/lab-polymorphic-beacon.json"]')).toHaveCount(1);
    await page.keyboard.press("Escape");
    await expect(page.locator(".li-caption")).toBeHidden();
    await expect(mon).toHaveAttribute("aria-expanded", "false");
    await expect(page.locator(".li-rule")).toContainText("cardinality(process.hash.sha256) >= 2");
    // replay keeps the section's size: nothing on the page moves
    const h0 = (await li.boundingBox())!.height;
    await page.locator(".li-replay").click();
    expect(Math.abs((await li.boundingBox())!.height - h0)).toBeLessThan(1);
  });

  test("how four copies became one incident: it plays, and its size never changes", async ({ page }) => {
    const run = readFileSync(new URL("./fixtures/vm-run-real-pinned.json", import.meta.url), "utf8");
    await page.route("**/cluster/api/lab/latest", (r) => r.fulfill({ status: 200, contentType: "application/json", body: run }));
    await page.goto("/lab/");
    const li = page.locator("section.li");
    await li.scrollIntoViewIfNeeded();
    const h0 = (await li.boundingBox())!.height;
    await expect(page.locator(".li-status")).toContainText("Copy 2", { timeout: 6000 });
    expect(Math.abs((await li.boundingBox())!.height - h0)).toBeLessThan(1);
    await expect(li).toHaveAttribute("data-fired", "true", { timeout: 9000 });
  });

  // ASCII mode, the hidden terminal look (src/ascii): off by default, on by a link or by typing
  // "ascii"; the diagrams become character drawings that still open their captions, and nothing on
  // the page grows wider than the screen.
  test("ASCII mode: a link turns it on, the drawings work, typing ascii turns it off and it is remembered", async ({ page }, info) => {
    const run = readFileSync(new URL("./fixtures/vm-run-real-pinned.json", import.meta.url), "utf8");
    await page.route("**/cluster/api/lab/latest", (r) => r.fulfill({ status: 200, contentType: "application/json", body: run }));
    // No script error, and nothing of the mode's own fails to load (the API's other endpoints are
    // absent here, as in the standalone image).
    const errors: string[] = [];
    page.on("pageerror", (e) => errors.push(e.message));
    page.on("response", (r) => { if (r.status() >= 400 && !r.url().includes("/cluster/api/")) errors.push(`${r.status()} ${r.url()}`); });
    await page.goto("/lab/");
    await expect(page.locator("html")).not.toHaveClass(/ascii/);
    await expect(page.locator("pre.ascii-dg")).toHaveCount(0);

    await page.goto("/lab/?ascii=1");
    await expect(page.locator("html")).toHaveClass(/ascii/);
    const hero = page.locator("#lab-diagram pre.ascii-dg:not([hidden])");
    await expect(hero).toHaveCount(1);
    await expect(hero).toContainText("Cloudflare edge");
    await expect(page.locator(".ascii-banner")).toBeVisible();
    // The incident's drawing arrives with the run, and plays to its incident.
    const inc = page.locator(".li pre.ascii-dg:not([hidden])");
    await expect(inc).toHaveCount(1);
    await expect(inc).toContainText("lab beacon :8080");
    await inc.scrollIntoViewIfNeeded();
    await expect(page.locator("section.li")).toHaveAttribute("data-fired", "true", { timeout: 12000 });
    await expect(inc).toContainText("4 copies · 4 hashes");
    await page.evaluate(() => scrollTo(0, 0));
    // The SVGs stay for screen readers and keyboards, out of sight.
    expect(await page.locator(".lab-diagram__svg--wide").evaluate((el) => el.getBoundingClientRect().width)).toBeLessThanOrEqual(1);
    // Every drawing fits its column, and the page never scrolls sideways.
    for (const pre of await page.locator("pre.ascii-dg:not([hidden])").all()) {
      expect(await pre.evaluate((el) => el.scrollWidth <= (el.parentElement as HTMLElement).clientWidth + 1)).toBe(true);
    }
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    // A click on a box opens that part's caption, as a click on the SVG does.
    await hero.evaluate((pre) => {
      const lines = (pre.textContent ?? "").split("\n");
      const r = lines.findIndex((l) => l.includes("Cloudflare edge"));
      const rect = pre.getBoundingClientRect();
      scrollTo({ top: scrollY + rect.top + (r / (lines.length - 1)) * rect.height - innerHeight / 2, behavior: "instant" });
    });
    const box = await hero.evaluate((pre) => {
      const lines = (pre.textContent ?? "").split("\n");
      const r = lines.findIndex((l) => l.includes("Cloudflare edge"));
      const c = lines[r].indexOf("Cloudflare edge") + 3;
      const rect = pre.getBoundingClientRect();
      return { x: rect.left + ((c + 0.5) / [...lines[0]].length) * rect.width, y: rect.top + ((r + 0.5) / (lines.length - 1)) * rect.height };
    });
    await page.mouse.click(box.x, box.y);
    await expect(page.locator("#lab-diagram-caption")).toBeVisible();
    await expect(page.locator("#lab-diagram-caption")).toContainText("Cloudflare");
    // Typing "ascii" (outside a field) turns it off, and the choice holds on the next visit.
    await page.locator("body").press("Escape");
    await page.keyboard.type("ascii");
    await expect(page.locator("html")).not.toHaveClass(/ascii/);
    await expect(page.locator("pre.ascii-dg, .ascii-bg, .ascii-banner")).toHaveCount(0);
    await expect(page.locator(".lab-diagram__svg--" + (info.project.name === "phone" ? "narrow" : "wide"))).toBeVisible();
    await page.goto("/lab/");
    await expect(page.locator("html")).not.toHaveClass(/ascii/);
    await page.keyboard.type("ascii");
    await expect(page.locator("html")).toHaveClass(/ascii/);
    await page.reload();
    await expect(page.locator("html")).toHaveClass(/ascii/);
    expect(errors).toEqual([]);
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

// The hero's architecture diagram, as /cluster/'s (src/ui/diagram.ts): nodes open a caption with links to
// the code, the way in carries a dot at rest, a live run lights its path, a validated run replays it,
// and nothing moves under reduced motion.
test.describe("the hero diagram", () => {
  const view = (project: string) => (project === "phone" ? "narrow" : "wide");
  const run = readFileSync(new URL("./fixtures/vm-run-real.json", import.meta.url), "utf8");
  const partial = readFileSync(new URL("./fixtures/vm-raw-partial-real.json", import.meta.url), "utf8");

  test("sits in the hero, above the run panel", async ({ page }) => {
    await page.goto("/lab/");
    const fig = await page.locator("#top #lab-diagram").boundingBox();
    const panel = await page.locator("#lab-panel").boundingBox();
    expect(fig && panel && fig.y + fig.height <= panel.y).toBe(true);
  });

  test("a node opens its caption by click and by keyboard, with links to where it lives; Escape and × close it", async ({ page }, info) => {
    await page.goto("/lab/");
    const svg = page.locator(`.lab-diagram__svg--${view(info.project.name)}`);
    const caption = page.locator("#lab-diagram-caption");
    await expect(caption).toBeHidden();
    const vm = svg.locator('.ld-node[data-node="vm"]');
    await vm.click();
    await expect(caption).toBeVisible();
    await expect(vm).toHaveAttribute("aria-expanded", "true");
    await expect(caption).toContainText("Sysmon for Linux records what the kernel saw");
    const hrefs = await caption.locator("a").evaluateAll((as) => as.map((a) => a.getAttribute("href")));
    expect(hrefs).toEqual([
      "https://github.com/HubertMJ/detection-lab/tree/main/vm/README.md",
      "https://github.com/HubertMJ/detection-lab/tree/main/vm/scenario.c",
      "https://github.com/HubertMJ/detection-lab/tree/main/vm/run_scenario.py",
      "https://github.com/HubertMJ/detection-lab/tree/main/vm/fluent-bit/sysmon_to_lab.lua",
    ]);
    // Keyboard: Enter opens the focused node, Escape closes it, Space opens it again.
    const validator = svg.locator('.ld-node[data-node="validator"]');
    await validator.focus();
    await page.keyboard.press("Enter");
    await expect(caption).toContainText("lines the findings and the alert up against the run's ground truth");
    await expect(caption.locator('a[href="https://github.com/HubertMJ/detection-lab/tree/main/lab/vm_validate.py"]')).toHaveCount(1);
    await expect(vm).toHaveAttribute("aria-expanded", "false");
    await page.keyboard.press("Escape");
    await expect(caption).toBeHidden();
    await page.keyboard.press(" ");
    await expect(caption).toBeVisible();
    await caption.locator(".ld-caption__close").click();
    await expect(caption).toBeHidden();
    await expect(validator).toBeFocused();
    // The trigger points at the provisioning script; the way in at the targets /cluster/'s diagram uses.
    await svg.locator('.ld-node[data-node="trigger"]').click();
    await expect(caption.locator('a[href="https://github.com/HubertMJ/self-defending-portfolio/tree/main/scripts/lab-vm-provision.sh"]')).toHaveCount(1);
    await svg.locator('.ld-node[data-node="cloudflared"]').click();
    await expect(caption.locator('a[href="https://github.com/HubertMJ/self-defending-portfolio/tree/main/cluster/infra/cloudflared/"]')).toHaveCount(1);
  });

  test("at rest a dot runs the way in; under reduced motion nothing moves", async ({ page }, info) => {
    const sel = `.lab-diagram__svg--${view(info.project.name)} .ld-dot--in`;
    await page.goto("/lab/");
    await expect.poll(() => page.locator(sel).evaluate((d) => d.getAnimations().map((a) => a.playState).join())).toBe("running");
    expect(await page.locator(`.lab-diagram__svg--${view(info.project.name)} .ld-glow--in`).count()).toBe(4);
    await page.emulateMedia({ reducedMotion: "reduce" });
    await page.reload();
    const moving = page.locator(".ld-dot, .ld-glow");
    expect(await moving.evaluateAll((els) => els.map((e) => `${getComputedStyle(e).display}:${e.getAnimations().length}`))).toEqual(Array(await moving.count()).fill("none:0"));
  });

  test("a live run lights its path in step with the VM, and its dot runs the run's path", async ({ page }, info) => {
    await page.route("**/cluster/api/lab/latest", (r) => r.fulfill({ status: 200, contentType: "application/json", body: run }));
    await page.route("**/cluster/api/lab/vm", (r) => r.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ state: "running", last_restore: "2026-10-20T06:56:24Z", snapshot_clean: true }) }));
    await page.route("**/cluster/api/lab/raw", (r) => r.fulfill({ status: 200, contentType: "application/json", body: partial }));
    await page.route("**/cluster/api/lab/run", (r) => r.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ state: "running", can_start: false }) }));
    await page.goto("/lab/");
    await expect(page.locator("#lab-diagram")).toHaveAttribute("data-run", "active", { timeout: 15000 });
    const svg = page.locator(`.lab-diagram__svg--${view(info.project.name)}`);
    await expect(svg.locator('.ld-node[data-node="vm"]')).toHaveAttribute("data-state", "run");
    await expect(svg.locator('.ld-node[data-node="stream"]')).toHaveAttribute("data-state", "record");
    await expect(svg.locator('.ld-edge[data-edge="vm-stream"]')).toHaveAttribute("data-lit", "true");
    await expect(svg.locator('.ld-node[data-node="detector"]')).toHaveAttribute("data-state", "idle");
    await expect(page.locator("#lab-diagram-status")).toContainText("Live run: the VM is running the four copies");
    await expect.poll(() => svg.locator(".ld-dot--run").evaluate((d) => d.getAnimations().length)).toBe(1);
    expect(await svg.locator(".ld-dot--in").evaluate((d) => getComputedStyle(d).display)).toBe("none");
  });

  test("a validated run replays its path once, then rests; under reduced motion it is lit at once", async ({ page }, info) => {
    await page.route("**/cluster/api/lab/latest", (r) => r.fulfill({ status: 200, contentType: "application/json", body: run }));
    await page.route("**/cluster/api/lab/vm", (r) => r.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ state: "off" }) }));
    await page.goto("/lab/");
    const svg = page.locator(`.lab-diagram__svg--${view(info.project.name)}`);
    await expect(svg.locator('.ld-node[data-node="vm"]')).toHaveAttribute("data-state", "run");
    await expect(svg.locator('.ld-node[data-node="page"]')).toHaveAttribute("data-state", "deliver");
    await expect(page.locator("#lab-diagram-status")).toContainText("Latest run: validated");
    await expect(svg.locator('.ld-node[data-node="page"]')).toHaveAttribute("data-state", "idle", { timeout: 10000 });
    await page.emulateMedia({ reducedMotion: "reduce" });
    await page.reload();
    await expect(svg.locator('.ld-node[data-node="runs"]')).toHaveAttribute("data-state", "record");
    // All of it at once: no step still to come.
    for (const id of ["vm", "stream", "detector", "validator", "runs", "api", "page"]) await expect(svg.locator(`.ld-node[data-node="${id}"]`)).not.toHaveAttribute("data-state", "idle");
  });
});

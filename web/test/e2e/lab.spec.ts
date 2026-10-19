import { expect, test } from "@playwright/test";

// The detection lab's preview, served standalone at /lab/. The main site (/) lives in another image
// on the same origin; for the slide tests, scripts/serve.mjs --e2e stands it in with a page carrying
// this page's own <head>, so the cross-document slide runs exactly as it does live (a real served
// page, so it works in Firefox too, where route interception misses top-level navigations).

test.describe("detection lab preview at /lab/", () => {
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

// Loaded as a classic, render-blocking script in <head> so a stored theme choice applies before
// first paint. The same "theme" key as the cluster page, so the choice follows the visitor across pages.
document.documentElement.classList.add("js");

try {
  const t = localStorage.getItem("theme");
  if (t === "light" || t === "dark") document.documentElement.dataset.theme = t;
} catch {
  // Storage blocked (private mode, sandboxed preview): the OS preference applies.
}

// Moving between the landing page (/), the cluster and the lab slides like an iPhone app (owner
// decision 2026-10-16): a page opened comes in from the right, and the way back slides the other way,
// the old page out to the right and the one behind it in from the left. Back is going home, by the
// header's logo or a link, and the browser's or mouse's back button (styles.css,
// :active-view-transition-type). Set here, in the render-blocking script, because pagereveal fires
// before the first frame of the new page. Any other move keeps the plain cross-fade.
const DESKTOPS = ["/cluster/", "/", "/lab/"];
const desktop = (url: string | undefined): number => {
  if (!url) return -1;
  try {
    const u = new URL(url, location.href);
    if (u.origin !== location.origin) return -1;
    if (u.pathname === "/" || u.pathname === "/index.html") return DESKTOPS.indexOf("/");
    return DESKTOPS.findIndex((p) => p !== "/" && (u.pathname === p.slice(0, -1) || u.pathname.startsWith(p)));
  } catch {
    return -1;
  }
};
const HOME = DESKTOPS.indexOf("/");
const way = (to: number, back = false): "forward" | "backward" => (back || to === HOME ? "backward" : "forward");
interface Reveal extends Event {
  viewTransition?: { types?: Set<string> } | null;
}
addEventListener("pagereveal", (e) => {
  const types = (e as Reveal).viewTransition?.types;
  if (!types) return;
  // The Navigation API knows where the visitor came from, back/forward included; the referrer only
  // for a link followed.
  type Entry = { url?: string; index?: number } | null;
  const nav = (globalThis as { navigation?: { activation?: { from?: Entry; entry?: Entry; navigationType?: string } } }).navigation;
  const act = nav?.activation;
  const from = desktop(act?.from?.url ?? document.referrer);
  const to = desktop(location.href);
  const back = act?.navigationType === "traverse" && (act.entry?.index ?? 0) < (act.from?.index ?? 0);
  if (from >= 0 && to >= 0 && from !== to) types.add(way(to, back));
});

// Firefox (and older Safari) cannot animate between documents, so there the same slide is played by
// hand: a link to another page first slides the current one out, then navigates, and the new page
// slides in, the same way round as above. The back button only gets the slide in; the previous page
// records on pagehide where the visitor came from. The header stays still: only what follows it in <body> moves.
const nativeSlide = "onpagereveal" in window && "CSSViewTransitionRule" in window;
const calm = typeof matchMedia === "function" ? matchMedia("(prefers-reduced-motion: reduce)") : null;
if (!nativeSlide) {
  const root = document.documentElement;
  const SLIDE = ["slide-in-forward", "slide-in-backward", "slide-out-forward", "slide-out-backward"];
  const play = (cls: string, ms: number, then?: () => void): void => {
    root.classList.remove(...SLIDE);
    void root.offsetWidth; // restart the animation when the same class comes back (bfcache)
    root.classList.add(cls);
    // Removed afterwards: a transform left on <main> would pin its sticky and fixed children to it.
    const done = (): void => {
      setTimeout(() => {
        if (then) then();
        else root.classList.remove(cls);
      }, ms);
    };
    // A page sliding in starts moving when its body is parsed, not when this head script runs.
    if (document.readyState === "loading") addEventListener("DOMContentLoaded", done, { once: true });
    else done();
  };
  const arrive = (): void => {
    if (calm?.matches) return;
    let from = -1;
    try {
      from = desktop(sessionStorage.getItem("desktop-from") ?? undefined);
    } catch {
      // Storage blocked: no slide, the page simply appears.
    }
    const entry = performance.getEntriesByType?.("navigation")[0] as PerformanceNavigationTiming | undefined;
    const followed = desktop(document.referrer) >= 0 || entry?.type === "back_forward";
    const to = desktop(location.href);
    if (followed && from >= 0 && to >= 0 && from !== to) play(`slide-in-${way(to)}`, 400);
  };
  arrive();
  addEventListener("pageshow", (e) => {
    if (e.persisted) {
      root.classList.remove(...SLIDE);
      arrive();
    }
  });
  addEventListener("pagehide", () => {
    try {
      sessionStorage.setItem("desktop-from", location.href);
    } catch {
      // Storage blocked: the next page simply appears.
    }
  });
  addEventListener("click", (e) => {
    if (calm?.matches || e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
    // Attributes, not a.href and a.target: an <a> in an SVG (the landing page's diagram) has them as
    // SVGAnimatedString objects.
    const a = (e.target as Element | null)?.closest?.("a[href]");
    const target = a?.getAttribute("target");
    if (!a || (target && target !== "_self") || a.hasAttribute("download")) return;
    const href = new URL(a.getAttribute("href") ?? "", location.href).href;
    const from = desktop(location.href);
    const to = desktop(href);
    if (from < 0 || to < 0 || from === to) return;
    e.preventDefault();
    play(`slide-out-${way(to)}`, 220, () => location.assign(href));
  });
}

export {};

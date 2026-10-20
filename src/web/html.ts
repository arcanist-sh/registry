// HTML shell for the registry's web pages: escaping, the arcanist.sh header and footer, and the response headers.
// Markup mirrors www.arcanist.sh (partials/header.html, partials/landing-footer.html) so the registry reads as part of
// the same site. All dynamic text goes through esc(); attribute values through attr().

import { WORDMARK } from "./wordmark";

const ESC: Record<string, string> = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };

export function esc(s: unknown): string {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ESC[c]);
}

/** An http(s) URL safe to put in href, or "" if the value is anything else. */
export function safeUrl(u: string): string {
  try {
    const url = new URL(u.trim());
    return url.protocol === "https:" || url.protocol === "http:" ? url.href : "";
  } catch {
    return "";
  }
}

export function date(sec: number): string {
  return new Date(sec * 1000).toISOString().slice(0, 10);
}

const ARCANIST = "https://arcanist.sh";
const EXT = `<svg class="ext" viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3.5 8.5 8.5 3.5M4.5 3.5h4v4"/></svg>`;
const GITHUB = `<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/></svg>`;

// The arcanist.sh menu (www.arcanist.sh config.toml [[extra.nav_links]]), with absolute URLs.
const MENU: { name: string; url?: string; children?: { name: string; url: string }[]; wide?: boolean }[] = [
  { name: "Get started", url: `${ARCANIST}/get-started/`, wide: true },
  {
    name: "Products",
    children: [
      { name: "hx", url: `${ARCANIST}/hx/` },
      { name: "BHC", url: `${ARCANIST}/bhc/` },
      { name: "Registry", url: "/" },
      { name: "hx vs Cabal & Stack", url: `${ARCANIST}/hx-vs-cabal-and-stack/` },
      { name: "BHC vs GHC", url: `${ARCANIST}/bhc-vs-ghc/` },
    ],
  },
  {
    name: "Learn",
    children: [
      { name: "Manifesto", url: `${ARCANIST}/manifesto/` },
      { name: "Use cases", url: `${ARCANIST}/use-cases/` },
      { name: "Glossary", url: `${ARCANIST}/glossary/` },
      { name: "About", url: `${ARCANIST}/about/` },
      { name: "Team", url: `${ARCANIST}/team/` },
    ],
  },
  { name: "Blog", url: `${ARCANIST}/blog/` },
  { name: "Docs", url: "https://docs.arcanist.sh/" },
];

// The arcanist.sh footer link groups (www.arcanist.sh config.toml [[extra.product.footer_links]]).
const FOOTER: { title: string; links: { text: string; url: string; ext?: boolean }[] }[] = [
  {
    title: "Products",
    links: [
      { text: "hx", url: `${ARCANIST}/hx/` },
      { text: "BHC", url: `${ARCANIST}/bhc/` },
      { text: "Registry", url: "/" },
      { text: "hx docs", url: "https://docs.arcanist.sh/hx/", ext: true },
      { text: "BHC docs", url: "https://docs.arcanist.sh/bhc/", ext: true },
    ],
  },
  {
    title: "Learn",
    links: [
      { text: "Get started", url: `${ARCANIST}/get-started/` },
      { text: "Manifesto", url: `${ARCANIST}/manifesto/` },
      { text: "The commons", url: `${ARCANIST}/commons/` },
      { text: "Use cases", url: `${ARCANIST}/use-cases/` },
      { text: "Glossary", url: `${ARCANIST}/glossary/` },
    ],
  },
  {
    title: "Registry",
    links: [
      { text: "Using the registry", url: `${ARCANIST}/registry/` },
      { text: "Publishing with hx", url: "https://docs.arcanist.sh/hx/", ext: true },
      { text: "JSON API", url: "/api/v1/config" },
      { text: "Source", url: "https://github.com/arcanist-sh/registry", ext: true },
    ],
  },
  {
    title: "Writing",
    links: [
      { text: "All posts", url: `${ARCANIST}/blog/` },
      { text: "hx blog", url: `${ARCANIST}/hx/blog/` },
      { text: "Atom feed", url: `${ARCANIST}/blog/atom.xml` },
    ],
  },
  {
    title: "Elsewhere",
    links: [
      { text: "GitHub", url: "https://github.com/arcanist-sh", ext: true },
      { text: "X", url: "https://x.com/raskell_io", ext: true },
      { text: "raskell.io", url: "https://raskell.io", ext: true },
    ],
  },
];

function header(): string {
  const items = MENU.map((m) => {
    if (m.children) {
      return `<details class="nav__group"><summary>${esc(m.name)}</summary><div class="nav__menu">${m.children
        .map((c) => `<a href="${esc(c.url)}">${esc(c.name)}</a>`)
        .join("")}</div></details>`;
    }
    return `<a class="nav__link${m.wide ? " nav__link--wide" : ""}" href="${esc(m.url)}">${esc(m.name)}</a>`;
  }).join("");
  return `<header class="header">
<a class="lockup" href="/" aria-label="arcanist.sh registry home">${WORDMARK}<span class="key">registry</span></a>
<nav class="nav" aria-label="Main navigation">${items}<a class="icon-link" href="https://github.com/arcanist-sh/registry" aria-label="Registry source on GitHub">${GITHUB}</a></nav>
</header>`;
}

function footer(crumbs: { text: string; url?: string }[]): string {
  const here = [{ text: "Home", url: `${ARCANIST}/` }, { text: "Registry", url: "/" }, ...crumbs]
    .map((c, i, all) =>
      i === all.length - 1 && !c.url ? `<span aria-current="page">${esc(c.text)}</span>` : `<a href="${esc(c.url)}">${esc(c.text)}</a>`,
    )
    .join(`<span aria-hidden="true">/</span>`);
  const groups = FOOTER.map(
    (g) =>
      `<nav class="site-footer__group" aria-label="${esc(g.title)}"><span class="site-footer__group-title">${esc(g.title)}</span>${g.links
        .map((l) => `<a href="${esc(l.url)}"><span>${esc(l.text)}</span>${l.ext ? EXT + '<span class="visually-hidden"> (external)</span>' : ""}</a>`)
        .join("")}</nav>`,
  ).join("");
  return `<footer class="site-footer">
<canvas class="site-footer__plasma" data-fx="plasma" aria-hidden="true"></canvas>
<div class="site-footer__grid">
<div class="site-footer__brand">
<a class="site-footer__logo" href="${ARCANIST}/" aria-label="arcanist.sh home">${WORDMARK}</a>
<p class="site-footer__about">arcanist.sh builds Haskell tooling for the age of AI-authored code. The registry serves Haskell packages for the ecosystem in the format cabal already reads, signed with hackage-security, next to <a href="https://hackage.haskell.org">Hackage</a>. <a href="${ARCANIST}/hx/">hx</a> publishes to it, and <a href="${ARCANIST}/bhc/">BHC</a> builds every new version.</p>
<p class="site-footer__here"><span>You are here:</span> ${here}</p>
</div>
<div class="site-footer__groups">${groups}</div>
</div>
<div class="site-footer__meta">
<span>&copy; ${new Date().getUTCFullYear()} arcanist.sh</span>
<span>The registry is open source on <a href="https://github.com/arcanist-sh/registry">GitHub</a></span>
<div class="scheme site-footer__meta-end" role="group" aria-label="Colour scheme" hidden>
<button type="button" data-scheme="auto" aria-pressed="true">System</button><button type="button" data-scheme="light" aria-pressed="false">Light</button><button type="button" data-scheme="dark" aria-pressed="false">Dark</button>
</div>
</div>
</footer>`;
}

export interface PageOptions {
  title: string;
  description: string;
  /** Path of this page, for the canonical link. */
  path: string;
  body: string;
  crumbs?: { text: string; url?: string }[];
  /** JSON alternate for this page. */
  jsonUrl?: string;
  status?: number;
  /** Seconds browsers and the edge may cache the page. */
  maxAge?: number;
}

// Pages load fonts from Google Fonts and the Geist CDN, images in READMEs from any https origin, and scripts and
// styles only from this origin. No inline script or style anywhere.
const CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self' https://fonts.googleapis.com https://cdn.jsdelivr.net",
  "font-src https://fonts.gstatic.com https://cdn.jsdelivr.net",
  "img-src 'self' https: data:",
  "form-action 'self'",
  "base-uri 'none'",
  "frame-ancestors 'none'",
].join("; ");

export function page(env: Env, o: PageOptions): Response {
  const canonical = `${env.PUBLIC_URL}${o.path}`;
  const html = `<!doctype html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(o.title)}</title>
<meta name="description" content="${esc(o.description)}">
<link rel="canonical" href="${esc(canonical)}">
<meta property="og:title" content="${esc(o.title)}">
<meta property="og:description" content="${esc(o.description)}">
<meta property="og:url" content="${esc(canonical)}">
<meta property="og:type" content="website">
<meta property="og:site_name" content="arcanist.sh registry">
<meta name="theme-color" content="#11111b">
<link rel="icon" href="/_assets/favicon.svg" type="image/svg+xml">
${o.jsonUrl ? `<link rel="alternate" type="application/json" href="${esc(o.jsonUrl)}">` : ""}
<link rel="search" type="application/opensearchdescription+xml" title="arcanist.sh registry" href="/_assets/opensearch.xml">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Funnel+Display:wght@500;600;700&amp;family=Geist:wght@400;500;600;700&amp;family=Martian+Mono:wght@500&amp;display=swap">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/geist@1.3.1/dist/fonts/geist-mono/style.min.css">
<link rel="stylesheet" href="/_assets/registry.css">
<script src="/_assets/theme.js"></script>
</head>
<body>
<a class="visually-hidden" href="#main">Skip to content</a>
${header()}
<main id="main">
${o.body}
</main>
${footer(o.crumbs ?? [])}
<script src="/_assets/site.js" defer></script>
<script src="/_assets/bg-effects.js" defer></script>
</body>
</html>
`;
  return new Response(html, {
    status: o.status ?? 200,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Content-Security-Policy": CSP,
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "strict-origin-when-cross-origin",
      "Cache-Control": `public, max-age=${o.maxAge ?? 60}`,
      Vary: "Accept",
    },
  });
}

/** A code block in the arcanist.sh style with a label and a Copy button (shown by site.js when the clipboard works). */
export function codeBlock(id: string, label: string, text: string): string {
  return `<div class="code"><div class="code__bar"><span>${esc(label)}</span><button type="button" class="copy" data-copy="${esc(id)}" hidden>Copy</button></div><pre id="${esc(id)}">${esc(text)}</pre></div>`;
}

/** True when the client asked for HTML (browsers) rather than JSON (hx, curl, scripts). */
export function wantsHtml(req: Request): boolean {
  const accept = req.headers.get("Accept") ?? "";
  return /\btext\/html\b/.test(accept);
}

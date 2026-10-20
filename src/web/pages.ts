// Read-only web pages: home, search, package and version pages, 404. Data comes from the same D1 tables as the JSON
// API; every page links to its JSON equivalent. Nothing here writes except the README cache in R2.

import { PACKAGE_NAME_RE, VERSION_RE, cabalMeta } from "../cabal";
import { compareVersions } from "../publish";
import { ROOT_KEY } from "../repo";
import { codeBlock, date, esc, page, safeUrl } from "./html";
import { loadReadme } from "./readme";

const HACKAGE = "https://hackage.haskell.org/package/";

interface VersionRow {
  version: string;
  yanked: number;
  published_at: number;
}

function latestOf(vs: VersionRow[]): string | null {
  const live = vs.filter((v) => !v.yanked).map((v) => v.version);
  const pool = live.length ? live : vs.map((v) => v.version);
  return [...pool].sort(compareVersions).at(-1) ?? null;
}

/** "^>=" bound on the major version (A.B) of a version, as cabal recommends for build-depends. */
function majorBound(v: string): string {
  return v.split(".").slice(0, 2).join(".");
}

async function rootKeys(env: Env): Promise<{ keys: string[]; threshold: number } | null> {
  const obj = await env.BLOBS.get(ROOT_KEY);
  if (!obj) return null;
  try {
    const doc = JSON.parse(await obj.text()) as { signed: { roles: { root: { keyids: string[]; threshold: number } } } };
    return { keys: doc.signed.roles.root.keyids, threshold: doc.signed.roles.root.threshold };
  } catch {
    return null;
  }
}

function stanza(env: Env, root: { keys: string[]; threshold: number } | null): string {
  const lines = [`repository ${env.REGISTRY_NAME}`, `  url: ${env.PUBLIC_URL}/`];
  if (root) {
    lines.push("  secure: True");
    root.keys.forEach((k, i) => lines.push(i === 0 ? `  root-keys: ${k}` : `             ${k}`));
    lines.push(`  key-threshold: ${root.threshold}`);
  }
  return lines.join("\n");
}

function pkgList(rows: { name: string; synopsis: string; version: string | null; published_at?: number; verified?: boolean }[], empty: string): string {
  if (!rows.length) return `<p class="empty">${esc(empty)}</p>`;
  return `<ul class="pkgs">${rows
    .map(
      (r) => `<li><a href="/package/${esc(r.name)}">
<span class="pkgs__name">${esc(r.name)}</span>
<span class="pkgs__meta">${r.verified ? '<span class="badge badge--bhc">bhc</span>' : ""}${r.version ? `<span>${esc(r.version)}</span>` : ""}${
        r.published_at ? `<time datetime="${date(r.published_at)}">${date(r.published_at)}</time>` : ""
      }</span>
${r.synopsis ? `<span class="pkgs__desc">${esc(r.synopsis)}</span>` : ""}
</a></li>`,
    )
    .join("")}</ul>`;
}

// ---- home -----------------------------------------------------------------------

export async function home(env: Env): Promise<Response> {
  const [counts, recent] = await env.DB.batch([
    env.DB.prepare(
      `SELECT (SELECT count(*) FROM packages) AS packages,
              (SELECT count(*) FROM versions) AS versions,
              (SELECT count(DISTINCT package || '-' || version) FROM attestations WHERE result = 'pass') AS verified`,
    ),
    env.DB.prepare(
      `SELECT v.package AS name, p.synopsis, v.version, v.published_at,
              EXISTS (SELECT 1 FROM attestations a WHERE a.package = v.package AND a.version = v.version AND a.result = 'pass') AS verified
       FROM versions v JOIN packages p ON p.name = v.package
       WHERE v.yanked = 0 ORDER BY v.published_at DESC, v.package LIMIT 12`,
    ),
  ]);
  const c = counts.results[0] as { packages: number; versions: number; verified: number };
  const rows = (recent.results as { name: string; synopsis: string; version: string; published_at: number; verified: number }[]).map((r) => ({
    ...r,
    verified: r.verified === 1,
  }));
  const root = await rootKeys(env);
  const body = `
<section class="hero"><div class="wrap">
<h1>Haskell packages, signed and checked.</h1>
<p class="hero__lead">The arcanist.sh registry serves Haskell packages in the same format as Hackage, signed with hackage-security. Plain cabal reads it next to Hackage, hx publishes to it, and bhc builds every new version and records the result.</p>
<form class="search" action="/search" method="get" role="search">
<label class="visually-hidden" for="q">Search packages</label>
<input id="q" name="q" type="search" placeholder="Search packages" autocomplete="off" maxlength="100">
<button class="btn" type="submit">Search</button>
</form>
<ul class="stats">
<li><strong>${c.packages}</strong><span>${c.packages === 1 ? "package" : "packages"}</span></li>
<li><strong>${c.versions}</strong><span>${c.versions === 1 ? "version" : "versions"}</span></li>
<li><strong>${c.verified}</strong><span>bhc-verified</span></li>
</ul>
</div></section>

<section class="section"><div class="wrap grid">
<div class="rail"><span class="label">Recently published</span></div>
<div class="stack">${pkgList(rows, "Nothing has been published yet.")}</div>
</div></section>

<section class="section"><div class="wrap grid">
<div class="rail"><span class="label">Use it</span></div>
<div class="stack">
<h2 class="h2">One command with hx, one stanza with cabal.</h2>
<p class="p">With hx, <code>hx registry add</code> writes the repository into your <code>cabal.project</code>. With cabal alone, add the stanza below and run <code>cabal update</code>; cabal checks the registry's signed metadata against the root keys and verifies every download from then on.</p>
${codeBlock("cmd-hx", "shell", "hx registry add\ncabal update")}
${codeBlock("cmd-stanza", "cabal.project", stanza(env, root))}
<p class="p">Pin the root keys from <a href="https://arcanist.sh/registry/">arcanist.sh/registry</a>, a separate site, rather than from this one; a client that pins them there does not have to trust the server presenting them.</p>
</div>
</div></section>

<section class="section"><div class="wrap grid">
<div class="rail"><span class="label">Publish</span></div>
<div class="stack">
<h2 class="h2">Publishing is part of hx.</h2>
<p class="p">The registry is in preview, and publishing accounts are issued by invitation while it runs. A package name that exists on Hackage cannot be registered here, so a registry package never shadows a Hackage one. Every upload is checked before it is stored, and published versions are immutable.</p>
${codeBlock("cmd-publish", "shell", "hx registry login --registry arcanist\nhx publish --registry arcanist")}
</div>
</div></section>`;
  return page(env, {
    title: "arcanist.sh registry",
    description: "Haskell packages for the arcanist.sh ecosystem, served in the Hackage format and signed with hackage-security. Plain cabal reads it next to Hackage; bhc verifies every new version.",
    path: "/",
    body,
    jsonUrl: "/api/v1/config",
  });
}

// ---- search -----------------------------------------------------------------------

export async function searchPage(env: Env, url: URL): Promise<Response> {
  const raw = (url.searchParams.get("q") ?? "").trim().slice(0, 100);
  const q = raw.toLowerCase();
  let rows: { name: string; synopsis: string; version: string | null }[] = [];
  if (q) {
    const like = `%${q.replace(/[\\%_]/g, (ch) => "\\" + ch)}%`;
    const res = await env.DB.prepare(
      `SELECT p.name, p.synopsis, (SELECT json_group_array(json_object('version', v.version, 'yanked', v.yanked, 'published_at', v.published_at))
         FROM versions v WHERE v.package = p.name) AS versions
       FROM packages p WHERE p.name_lower LIKE ?1 ESCAPE '\\' OR lower(p.synopsis) LIKE ?1 ESCAPE '\\' LIMIT 200`,
    )
      .bind(like)
      .all<{ name: string; synopsis: string; versions: string }>();
    const score = (n: string) => (n.toLowerCase() === q ? 3 : n.toLowerCase().startsWith(q) ? 2 : n.toLowerCase().includes(q) ? 1 : 0);
    rows = res.results
      .map((r) => ({ name: r.name, synopsis: r.synopsis, version: latestOf(JSON.parse(r.versions) as VersionRow[]) }))
      .sort((a, b) => score(b.name) - score(a.name) || (a.name < b.name ? -1 : 1));
  }
  const body = `
<section class="hero"><div class="wrap">
<h1>${q ? `Results for “${esc(raw)}”` : "Search packages"}</h1>
<form class="search" action="/search" method="get" role="search">
<label class="visually-hidden" for="q">Search packages</label>
<input id="q" name="q" type="search" value="${esc(raw)}" placeholder="Search packages" autocomplete="off" maxlength="100">
<button class="btn" type="submit">Search</button>
</form>
</div></section>
<section class="section"><div class="wrap grid">
<div class="rail"><span class="label">${q ? `${rows.length} ${rows.length === 1 ? "package" : "packages"}` : "Packages"}</span></div>
<div class="stack">${q ? pkgList(rows, "No package matches. Packages not published here are on Hackage.") : '<p class="empty">Search by package name or synopsis.</p>'}
${q ? `<p class="p">Looking for something else? <a href="https://hackage.haskell.org/packages/search?terms=${encodeURIComponent(raw)}">Search Hackage</a>.</p>` : ""}</div>
</div></section>`;
  return page(env, {
    title: q ? `${raw}: search · arcanist.sh registry` : "Search · arcanist.sh registry",
    description: "Search the arcanist.sh Haskell package registry.",
    path: q ? `/search?q=${encodeURIComponent(raw)}` : "/search",
    body,
    crumbs: [{ text: "Search" }],
    jsonUrl: `/api/v1/search?q=${encodeURIComponent(raw)}`,
    maxAge: 30,
  });
}

// ---- package and version -------------------------------------------------------------

interface FullVersion {
  version: string;
  sha256: string;
  size: number;
  cabal_file: string;
  synopsis: string;
  license: string;
  deps: string;
  yanked: number;
  yanked_at: number | null;
  published_at: number;
  publisher: string;
}

interface Attestation {
  verifier: string;
  bhc_version: string;
  profile: string;
  result: string;
  log_url: string | null;
  built_at: string;
}

/** Haddock autolinks (`<https://example.com>`, optionally `<url label>`) in already-escaped description text. */
function haddockLinks(escaped: string): string {
  return escaped.replace(/&lt;(https?:\/\/[^\s&]+(?:&amp;[^\s&]+)*)(?:\s+([^&]+))?&gt;/g, (whole, url: string, label?: string) => {
    const href = safeUrl(url.replace(/&amp;/g, "&"));
    return href ? `<a href="${esc(href)}" rel="nofollow noopener">${label ? label.trim() : url}</a>` : whole;
  });
}

function humanSize(n: number): string {
  return n < 1024 ? `${n} B` : n < 1024 * 1024 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1024 / 1024).toFixed(1)} MB`;
}

/** The package page, for the latest version (`version` = null) or a specific one. */
export async function packagePage(env: Env, name: string, version: string | null): Promise<Response | null> {
  if (!PACKAGE_NAME_RE.test(name) || (version !== null && !VERSION_RE.test(version))) return null;
  const [pkgR, versR, ownersR, verifiedR] = await env.DB.batch([
    env.DB.prepare("SELECT name, synopsis, created_at FROM packages WHERE name = ?").bind(name),
    env.DB.prepare("SELECT version, yanked, published_at FROM versions WHERE package = ?").bind(name),
    env.DB.prepare("SELECT u.login FROM package_owners o JOIN users u ON u.id = o.user_id WHERE o.package = ? ORDER BY u.login").bind(name),
    env.DB.prepare("SELECT DISTINCT version FROM attestations WHERE package = ? AND result = 'pass'").bind(name),
  ]);
  const pkg = pkgR.results[0] as { name: string; synopsis: string; created_at: number } | undefined;
  if (!pkg) return null;
  const versions = (versR.results as unknown as VersionRow[]).sort((a, b) => compareVersions(b.version, a.version));
  const latest = latestOf(versions);
  const selected = version ?? latest;
  if (!selected || !versions.some((v) => v.version === selected)) return null;
  const verified = new Set((verifiedR.results as { version: string }[]).map((r) => r.version));
  const owners = (ownersR.results as { login: string }[]).map((o) => o.login);

  const [vR, attR] = await env.DB.batch([
    env.DB.prepare(
      `SELECT v.version, v.sha256, v.size, v.cabal_file, v.synopsis, v.license, v.deps, v.yanked, v.yanked_at, v.published_at, u.login AS publisher
       FROM versions v JOIN users u ON u.id = v.published_by WHERE v.package = ? AND v.version = ?`,
    ).bind(name, selected),
    env.DB.prepare(
      "SELECT verifier, bhc_version, profile, result, log_url, built_at FROM attestations WHERE package = ? AND version = ? ORDER BY received_at DESC",
    ).bind(name, selected),
  ]);
  const v = vR.results[0] as unknown as FullVersion;
  const atts = attR.results as unknown as Attestation[];
  const meta = cabalMeta(v.cabal_file);
  const deps = JSON.parse(v.deps) as { name: string; range: string }[];
  const local = deps.length
    ? new Set(
        (
          await env.DB.prepare(`SELECT name FROM packages WHERE name IN (${deps.map(() => "?").join(",")})`)
            .bind(...deps.map((d) => d.name))
            .all<{ name: string }>()
        ).results.map((r) => r.name),
      )
    : new Set<string>();
  const readme = await loadReadme(env, v.sha256);

  const isLatest = selected === latest;
  const passed = atts.some((a) => a.result === "pass");
  const failedOnly = atts.length > 0 && !passed;
  const badges = [
    passed ? `<span class="badge badge--bhc">bhc-verified</span>` : failedOnly ? `<span class="badge badge--fail">bhc build failed</span>` : `<span class="badge">Not yet built with bhc</span>`,
    v.yanked ? `<span class="badge badge--yanked">Yanked ${v.yanked_at ? date(v.yanked_at) : ""}</span>` : "",
    v.license ? `<span class="badge badge--plain">${esc(v.license)}</span>` : "",
    !isLatest && latest ? `<a class="badge badge--plain" href="/package/${esc(name)}">Latest is ${esc(latest)}</a>` : "",
  ].join("");

  const facts: [string, string][] = [
    ["Version", esc(v.version)],
    ["Published", `<time datetime="${date(v.published_at)}">${date(v.published_at)}</time> by ${esc(v.publisher)}`],
    ["License", esc(v.license || "unspecified")],
    ["Owners", owners.map(esc).join(", ") || "none"],
    ...(meta.maintainer ? [["Maintainer", esc(meta.maintainer)] as [string, string]] : []),
    ...(meta.category ? [["Category", esc(meta.category)] as [string, string]] : []),
    ...(meta.testedWith ? [["Tested with", esc(meta.testedWith)] as [string, string]] : []),
    ["Size", humanSize(v.size)],
  ];
  const links: [string, string][] = [];
  const home = safeUrl(meta.homepage);
  const repo = safeUrl(meta.repository.replace(/^git\+/, ""));
  const bugs = safeUrl(meta.bugReports);
  if (home) links.push(["Homepage", home]);
  if (repo && repo !== home) links.push(["Source repository", repo]);
  if (bugs) links.push(["Issues", bugs]);

  const id = `${name}-${v.version}`;
  const versionsList = versions
    .map(
      (r) =>
        `<li class="${r.yanked ? "is-yanked" : ""}"><a href="/package/${esc(name)}-${esc(r.version)}"${r.version === selected ? ' aria-current="page"' : ""}><span class="v">${esc(r.version)}${
          verified.has(r.version) ? ' <span class="badge badge--bhc">bhc</span>' : ""
        }</span><time datetime="${date(r.published_at)}">${date(r.published_at)}</time></a></li>`,
    )
    .join("");

  const depsHtml = deps.length
    ? `<ul class="deps">${deps
        .map((d) => {
          const href = local.has(d.name) ? `/package/${esc(d.name)}` : `${HACKAGE}${esc(d.name)}`;
          return `<li><a href="${href}">${esc(d.name)}${d.range !== "any" ? `<span class="r">${esc(d.range)}</span>` : ""}</a></li>`;
        })
        .join("")}</ul>`
    : '<p class="empty">No dependencies.</p>';

  const attHtml = atts.length
    ? `<div class="scroll-x"><table class="att"><thead><tr><th>Result</th><th>bhc</th><th>Profile</th><th>Built</th><th>Verifier</th><th>Log</th></tr></thead><tbody>${atts
        .map((a) => {
          const log = a.log_url ? safeUrl(a.log_url) : "";
          return `<tr><td>${a.result === "pass" ? '<span class="badge badge--bhc">pass</span>' : '<span class="badge badge--fail">fail</span>'}</td><td><code>${esc(a.bhc_version)}</code></td><td>${esc(
            a.profile,
          )}</td><td>${esc(a.built_at.slice(0, 10))}</td><td>${esc(a.verifier)}</td><td>${log ? `<a href="${esc(log)}">Build log</a>` : "<span class=\"muted\">none</span>"}</td></tr>`;
        })
        .join("")}</tbody></table></div><p class="p">Each result is an Ed25519-signed statement from the verifier over the tarball's SHA-256, checked by the registry before it is recorded.</p>`
    : `<p class="p">No bhc build has been recorded for this version yet. The <a href="https://github.com/arcanist-sh/bhc-verifier">verifier</a> picks up new versions on its next run.</p>`;

  const description = meta.description
    ? meta.description
        .split(/\n{2,}/)
        .map((para) => `<p>${haddockLinks(esc(para.replace(/\n/g, " ")))}</p>`)
        .join("")
    : "";

  const body = `
<div class="wrap">
<div class="pkg-head">
<p class="crumbs"><a href="/">registry</a> / ${esc(name)}</p>
<h1>${esc(name)} <span class="ver">${esc(v.version)}</span></h1>
${v.synopsis ? `<p class="p">${esc(v.synopsis)}</p>` : ""}
<div class="pkg-badges">${badges}</div>
</div>
<div class="pkg">
<div class="stack">
${codeBlock("cmd-dep", "your .cabal file", `build-depends: ${name} ^>=${majorBound(v.version)}`)}
${codeBlock("cmd-add", "shell", `hx registry add   # once per project\nhx add ${name}`)}
<section class="stack" aria-labelledby="readme">
<span class="label" id="readme">${readme ? esc(readme.file) : "Description"}</span>
<div class="prose">${readme ? readme.html : description || '<p class="muted">This package has no README or description.</p>'}</div>
</section>
<section class="stack" aria-labelledby="deps">
<span class="label" id="deps">Dependencies</span>
${depsHtml}
</section>
<section class="stack" aria-labelledby="bhc">
<span class="label" id="bhc">bhc verification</span>
${attHtml}
</section>
</div>
<aside aria-label="Package details">
<div><span class="label">Details</span><dl class="facts">${facts.map(([k, val]) => `<div><dt>${k}</dt><dd>${val}</dd></div>`).join("")}</dl></div>
${links.length ? `<div><span class="label">Links</span><ul class="links">${links.map(([k, u]) => `<li><a href="${esc(u)}" rel="nofollow noopener">${k}</a></li>`).join("")}</ul></div>` : ""}
<div><span class="label">Versions</span><ul class="versions">${versionsList}</ul></div>
<div><span class="label">Files</span><ul class="links">
<li><a href="/package/${esc(id)}.tar.gz">${esc(id)}.tar.gz</a></li>
<li><a href="/package/${esc(id)}/${esc(name)}.cabal">${esc(name)}.cabal</a></li>
<li><a href="/api/v1/packages/${esc(name)}/${esc(v.version)}">JSON</a></li>
</ul>
<p class="hash">sha256 ${esc(v.sha256)}</p></div>
</aside>
</div>
</div>`;
  return page(env, {
    title: `${name}${isLatest ? "" : ` ${v.version}`} · arcanist.sh registry`,
    description: v.synopsis || `${name} on the arcanist.sh Haskell package registry.`,
    path: version ? `/package/${id}` : `/package/${name}`,
    body,
    crumbs: [{ text: name, url: isLatest && !version ? undefined : `/package/${name}` }, ...(version ? [{ text: v.version }] : [])],
    jsonUrl: version ? `/api/v1/packages/${name}/${v.version}` : `/api/v1/packages/${name}`,
    maxAge: 60,
  });
}

// ---- errors -------------------------------------------------------------------------

export function notFoundPage(env: Env, path: string): Response {
  const body = `<div class="wrap error">
<span class="label">404</span>
<h1>Nothing here.</h1>
<p class="p">There is no page at <code>${esc(path)}</code>. If you were looking for a package, it may not be published on this registry; packages from Hackage are on <a href="https://hackage.haskell.org">hackage.haskell.org</a>.</p>
<form class="search" action="/search" method="get" role="search"><label class="visually-hidden" for="q">Search packages</label><input id="q" name="q" type="search" placeholder="Search packages" maxlength="100"><button class="btn" type="submit">Search</button></form>
</div>`;
  return page(env, { title: "Not found · arcanist.sh registry", description: "Page not found.", path, body, status: 404, crumbs: [{ text: "Not found" }], maxAge: 30 });
}

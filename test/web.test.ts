import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { cabalMeta } from "../src/cabal";
import { tarEntry } from "../src/tar";
import { readmeKey, sanitize } from "../src/web/readme";
import { call, cabalText, jsonOf, newUser, publish, sdistEntries, tarGz, uniq } from "./helpers";

const enc = new TextEncoder();
const HTML = { Accept: "text/html,application/xhtml+xml" };

async function publishWithReadme(name: string, version: string, readme: string, cabalExtra = ""): Promise<string> {
  const u = await newUser();
  const top = `${name}-${version}`;
  const entries = [...sdistEntries(name, version, cabalText(name, version, cabalExtra)), tarEntry(`${top}/README.md`, enc.encode(readme), 1700000000)];
  const res = await publish(u.token, await tarGz(entries));
  expect(res.status).toBe(201);
  return u.login;
}

describe("web pages", () => {
  it("serves HTML to browsers at / and keeps the JSON document for everything else", async () => {
    const page = await call("GET", "/", { headers: HTML });
    expect(page.status).toBe(200);
    expect(page.headers.get("Content-Type")).toContain("text/html");
    expect(page.headers.get("Content-Security-Policy")).toContain("script-src 'self'");
    expect(page.headers.get("Vary")).toBe("Accept");
    const html = await page.text();
    expect(html).toContain("Haskell packages, signed and checked.");
    expect(html).toContain('action="/search"');
    expect(html).toContain("repository registry.arcanist.sh");

    const doc = await call("GET", "/");
    expect(doc.headers.get("Content-Type")).toContain("application/json");
    expect((await jsonOf(doc)).name).toBe("registry.arcanist.sh");
  });

  it("renders a package page with its README, dependencies, versions and verification state", async () => {
    const name = uniq("webpkg");
    const owner = await publishWithReadme(
      name,
      "1.0.0",
      "# Hello\n\nA *readme* with `code`.\n\n<script>alert(1)</script>\n\n[bad](javascript:alert(1)) [good](https://example.com)\n\n<img src=x onerror=alert(1)>\n",
      "homepage: https://example.com/home\ndescription:\n  First line.\n  .\n  Second paragraph.\n",
    );
    const res = await call("GET", `/package/${name}`, { headers: HTML });
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain(`<h1>${name} <span class="ver">1.0.0</span></h1>`);
    expect(html).toContain("<h1>Hello</h1>");
    expect(html).toContain("<em>readme</em>");
    expect(html).not.toContain("<script>alert");
    expect(html).not.toContain("javascript:");
    expect(html).not.toContain("onerror");
    expect(html).toContain('href="https://example.com/"');
    expect(html).toContain(`build-depends: ${name} ^&gt;=1.0`);
    expect(html).toContain("https://hackage.haskell.org/package/containers");
    expect(html).toContain("Not yet built with BHC");
    expect(html).toContain(owner);
    expect(html).toContain('href="https://example.com/home"');

    // The rendering is cached next to the content-addressed tarball.
    const info = await jsonOf(await call("GET", `/api/v1/packages/${name}`));
    expect(await env.BLOBS.head(readmeKey(info.versions[0].sha256))).not.toBeNull();
  });

  it("serves version pages and marks the selected version", async () => {
    const name = uniq("webver");
    const u = await newUser();
    expect((await publish(u.token, await tarGz(sdistEntries(name, "0.1.0")))).status).toBe(201);
    expect((await publish(u.token, await tarGz(sdistEntries(name, "0.2.0")))).status).toBe(201);
    const latest = await (await call("GET", `/package/${name}`, { headers: HTML })).text();
    expect(latest).toContain('<span class="ver">0.2.0</span>');
    const old = await call("GET", `/package/${name}-0.1.0`, { headers: HTML });
    expect(old.status).toBe(200);
    const html = await old.text();
    expect(html).toContain('<span class="ver">0.1.0</span>');
    expect(html).toContain(`href="/package/${name}-0.1.0" aria-current="page"`);
    expect(html).toContain("Latest is 0.2.0");
    // no README: the cabal synopsis and the description fallback
    expect(html).toContain(`Test package ${name}`);
  });

  it("returns an HTML 404 for unknown packages and paths in a browser, JSON otherwise", async () => {
    const missing = await call("GET", "/package/no-such-package-here", { headers: HTML });
    expect(missing.status).toBe(404);
    expect(await missing.text()).toContain("Nothing here.");
    const unknown = await call("GET", "/nowhere", { headers: HTML });
    expect(unknown.status).toBe(404);
    expect(unknown.headers.get("Content-Type")).toContain("text/html");
    const api = await call("GET", "/nowhere");
    expect(api.status).toBe(404);
    expect((await jsonOf(api)).error.code).toBe("not_found");
  });

  it("searches by name and escapes the query", async () => {
    const name = uniq("findme");
    const u = await newUser();
    expect((await publish(u.token, await tarGz(sdistEntries(name, "1.0")))).status).toBe(201);
    const hit = await (await call("GET", `/search?q=${name}`, { headers: HTML })).text();
    expect(hit).toContain(`href="/package/${name}"`);
    const xss = await (await call("GET", `/search?q=${encodeURIComponent('"><script>x</script>')}`, { headers: HTML })).text();
    expect(xss).not.toContain("<script>x");
    expect(xss).toContain("&lt;script&gt;x");
  });

  it("leaves the cabal repository paths alone", async () => {
    const name = uniq("cabalpath");
    const u = await newUser();
    expect((await publish(u.token, await tarGz(sdistEntries(name, "1.0")))).status).toBe(201);
    const tar = await call("GET", `/package/${name}-1.0.tar.gz`, { headers: HTML });
    expect(tar.headers.get("Content-Type")).toBe("application/gzip");
    const cabal = await call("GET", `/package/${name}-1.0/${name}.cabal`, { headers: HTML });
    expect(await cabal.text()).toContain(`name:          ${name}`);
  });
});

describe("README sanitiser", () => {
  it("keeps allowed markup and drops everything else", () => {
    expect(sanitize('<p onclick="x()">hi</p>')).toBe("<p>hi</p>");
    expect(sanitize('<a href="javascript:alert(1)">x</a>')).toBe("<a>x</a>");
    expect(sanitize('<a href="https://a.example/">x</a>')).toBe('<a href="https://a.example/" rel="nofollow noopener ugc">x</a>');
    expect(sanitize('<a href="#usage">x</a>')).toBe('<a href="#usage">x</a>');
    expect(sanitize('<img src="http://insecure.example/i.png">')).toBe('<img loading="lazy" referrerpolicy="no-referrer">');
    expect(sanitize("<script>alert(1)</script>after")).toBe("after");
    expect(sanitize("<style>*{}</style><iframe src=x></iframe>ok")).toBe("ok");
    expect(sanitize("<!-- hidden -->text")).toBe("text");
    expect(sanitize("a < b")).toBe("a &lt; b");
    expect(sanitize('<code class="language-haskell">x</code>')).toBe('<code class="language-haskell">x</code>');
    expect(sanitize('<code class="evil">x</code>')).toBe("<code>x</code>");
    expect(sanitize('<a href="&#x6a;avascript:alert(1)">x</a>')).toBe("<a>x</a>");
  });
});

describe("cabalMeta", () => {
  it("reads descriptive fields and the head source repository", () => {
    const m = cabalMeta(`cabal-version: 3.0
name: demo
version: 1.0
homepage: https://example.com
bug-reports: https://example.com/issues
maintainer: someone@example.com
category: Development
description:
  First paragraph
  continues here.
  .
  Second paragraph.

source-repository head
  type: git
  location: https://github.com/example/demo
`);
    expect(m.homepage).toBe("https://example.com");
    expect(m.bugReports).toBe("https://example.com/issues");
    expect(m.category).toBe("Development");
    expect(m.repository).toBe("https://github.com/example/demo");
    expect(m.description).toBe("First paragraph\ncontinues here.\n\nSecond paragraph.");
  });
});

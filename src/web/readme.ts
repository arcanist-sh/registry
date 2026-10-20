// README for a package version: found in the sdist tarball, rendered from Markdown, sanitised, and cached in R2
// next to the content-addressed tarball (versions are immutable, so the rendering never goes stale).

import { Marked } from "marked";
import { gunzipLimited } from "../gzip";
import { LIMITS, blobKey } from "../publish";
import { readTar } from "../tar";
import { esc, safeUrl } from "./html";

const README_BYTES = 512 * 1024;
// Larger tarballs fall back to the .cabal description: decompressing them can exceed a request's CPU budget.
const MAX_TARBALL = 4 * 1024 * 1024;
const NAMES = ["readme.md", "readme.markdown", "readme", "readme.txt"];
// Bump when the renderer or sanitiser changes so cached renderings are rebuilt.
const RENDER_VERSION = 1;

export interface Readme {
  html: string;
  file: string;
}

export function readmeKey(sha256: string): string {
  return `readme/v${RENDER_VERSION}/${sha256}.json`;
}

/** Pick the README in the tarball's top-level directory, preferring Markdown. */
export function findReadme(files: { path: string; type: string; data: Uint8Array }[]): { path: string; data: Uint8Array } | null {
  const top = files.filter((f) => f.type === "file" && f.path.split("/").length === 2);
  for (const n of NAMES) {
    const hit = top.find((f) => f.path.split("/")[1].toLowerCase() === n);
    if (hit) return hit;
  }
  return null;
}

// ---- sanitising ---------------------------------------------------------------
// marked passes raw HTML through, so its output is filtered here: an allow-list of tags and attributes, http(s) and
// in-page links only, images over https only. Anything else is dropped (tags) or escaped (text).

const ALLOWED: Record<string, string[]> = {
  a: ["href", "title"],
  img: ["src", "alt", "title", "width", "height"],
  p: [], br: [], hr: [], blockquote: [], pre: [], code: ["class"], kbd: [], samp: [],
  h1: ["id"], h2: ["id"], h3: ["id"], h4: ["id"], h5: ["id"], h6: ["id"],
  ul: [], ol: ["start"], li: [], dl: [], dt: [], dd: [],
  strong: [], b: [], em: [], i: [], del: [], s: [], sub: [], sup: [], mark: [],
  table: [], thead: [], tbody: [], tr: [], th: ["align"], td: ["align"],
  details: [], summary: [], span: [], div: [],
};

const ENTITY = /&(?:#\d+|#x[0-9a-f]+|[a-z][a-z0-9]*);/gi;

function cleanAttr(tag: string, name: string, value: string): string | null {
  if (!ALLOWED[tag]?.includes(name)) return null;
  const decoded = value.replace(ENTITY, (e) => (e === "&amp;" ? "&" : e === "&quot;" ? '"' : e === "&#39;" ? "'" : e));
  if (name === "href") {
    if (decoded.startsWith("#")) return decoded;
    return safeUrl(decoded) || null;
  }
  if (name === "src") {
    const u = safeUrl(decoded);
    return u.startsWith("https:") ? u : null;
  }
  if (name === "class") return /^language-[A-Za-z0-9_+-]+$/.test(decoded) ? decoded : null;
  if (name === "width" || name === "height" || name === "start") return /^\d{1,4}$/.test(decoded) ? decoded : null;
  if (name === "align") return /^(left|right|center)$/.test(decoded) ? decoded : null;
  if (name === "id") return /^[A-Za-z0-9_-]{1,100}$/.test(decoded) ? decoded : null;
  return decoded;
}

/** Keep allow-listed tags and attributes; escape everything that is not a well-formed allowed tag. */
export function sanitize(html: string): string {
  let out = "";
  let i = 0;
  // Content of these elements is dropped entirely, not just the tags.
  const DROP = /^(script|style|iframe|object|embed|svg|math|template|noscript|textarea|select|form)$/i;
  while (i < html.length) {
    const lt = html.indexOf("<", i);
    if (lt < 0) {
      out += html.slice(i);
      break;
    }
    out += html.slice(i, lt);
    const m = /^<(\/?)([A-Za-z][A-Za-z0-9]*)((?:\s+[^\s"'>\/=]+(?:\s*=\s*(?:"[^"]*"|'[^']*'|[^\s"'=<>`]+))?)*)\s*(\/?)>/.exec(html.slice(lt));
    if (!m) {
      // Comments, doctypes and malformed markup become text.
      const end = html.startsWith("<!--", lt) ? html.indexOf("-->", lt) : -1;
      if (end >= 0) {
        i = end + 3;
        continue;
      }
      out += "&lt;";
      i = lt + 1;
      continue;
    }
    const [whole, closing, rawTag, rawAttrs] = m;
    const tag = rawTag.toLowerCase();
    i = lt + whole.length;
    if (DROP.test(tag)) {
      if (!closing) {
        const close = html.toLowerCase().indexOf(`</${tag}`, i);
        i = close < 0 ? html.length : html.indexOf(">", close) + 1 || html.length;
      }
      continue;
    }
    if (!(tag in ALLOWED)) continue;
    if (closing) {
      out += `</${tag}>`;
      continue;
    }
    let attrs = "";
    const re = /([^\s"'>\/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g;
    let a: RegExpExecArray | null;
    while ((a = re.exec(rawAttrs))) {
      const name = a[1].toLowerCase();
      const v = cleanAttr(tag, name, a[2] ?? a[3] ?? a[4] ?? "");
      if (v !== null) attrs += ` ${name}="${esc(v)}"`;
    }
    if (tag === "a" && attrs.includes('href="http')) attrs += ' rel="nofollow noopener ugc"';
    if (tag === "img") attrs += ' loading="lazy" referrerpolicy="no-referrer"';
    out += `<${tag}${attrs}>`;
  }
  return out;
}

const md = new Marked({ gfm: true, breaks: false });

export function renderMarkdown(text: string): string {
  return sanitize(md.parse(text, { async: false }) as string);
}

function renderPlain(text: string): string {
  return `<pre>${esc(text)}</pre>`;
}

/** The rendered README for a version, from the R2 cache or the tarball. Null when the tarball has no README. */
export async function loadReadme(env: Env, sha256: string): Promise<Readme | null> {
  const key = readmeKey(sha256);
  const cached = await env.BLOBS.get(key);
  if (cached) {
    const j = (await cached.json()) as { readme: Readme | null };
    return j.readme;
  }
  const head = await env.BLOBS.head(blobKey(sha256));
  if (!head || head.size > MAX_TARBALL) return null;
  const obj = await env.BLOBS.get(blobKey(sha256));
  if (!obj) return null;
  let readme: Readme | null = null;
  try {
    const files = readTar(await gunzipLimited(new Uint8Array(await obj.arrayBuffer()), LIMITS.unpackedBytes), { maxEntries: LIMITS.entries });
    const hit = findReadme(files);
    if (hit) {
      const text = new TextDecoder().decode(hit.data.subarray(0, README_BYTES));
      const name = hit.path.split("/")[1];
      readme = { file: name, html: /\.(md|markdown)$/i.test(name) ? renderMarkdown(text) : renderPlain(text) };
    }
  } catch (e) {
    console.error(JSON.stringify({ msg: "readme extraction failed", sha256, error: String(e) }));
    return null; // do not cache failures
  }
  await env.BLOBS.put(key, JSON.stringify({ readme }), { httpMetadata: { contentType: "application/json" } });
  return readme;
}

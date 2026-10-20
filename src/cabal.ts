// Minimal .cabal reader: top-level descriptive fields and a best-effort union of
// build-depends. cabal itself reads the real file from the index; this is only
// for validation (name/version must match the tarball) and the JSON API.

export interface CabalInfo {
  name: string;
  version: string;
  synopsis: string;
  license: string;
  deps: { name: string; range: string }[];
}

export const PACKAGE_NAME_RE = /^[A-Za-z0-9]*[A-Za-z][A-Za-z0-9]*(-[A-Za-z0-9]*[A-Za-z][A-Za-z0-9]*)*$/;
export const VERSION_RE = /^[0-9]{1,9}(\.[0-9]{1,9}){0,7}$/;

interface Field {
  indent: number;
  name: string;
  value: string;
}

function fields(text: string): Field[] {
  const lines = text.replace(/\r\n?/g, "\n").split("\n");
  const out: Field[] = [];
  let cur: Field | undefined;
  for (const raw of lines) {
    if (/^\s*--/.test(raw)) continue;
    if (raw.trim() === "") {
      continue;
    }
    const indent = raw.length - raw.trimStart().length;
    const m = /^(\s*)([A-Za-z][A-Za-z0-9_-]*)\s*:(.*)$/.exec(raw);
    if (m && (!cur || indent <= cur.indent)) {
      cur = { indent, name: m[2].toLowerCase(), value: m[3].trim() };
      out.push(cur);
    } else if (cur && indent > cur.indent) {
      cur.value += "\n" + raw.trim();
    } else {
      cur = undefined; // section header such as "library" or "if flag(x)"
    }
  }
  return out;
}

export function parseCabal(text: string): CabalInfo {
  const fs = fields(text);
  const top = (n: string) => fs.find((f) => f.indent === 0 && f.name === n)?.value.trim() ?? "";
  const deps = new Map<string, Set<string>>();
  for (const f of fs) {
    if (f.name !== "build-depends") continue;
    for (const part of f.value.replace(/--[^\n]*/g, "").split(",")) {
      const d = part.replace(/\s+/g, " ").trim();
      if (!d) continue;
      const m = /^([A-Za-z0-9-]+)(?::\{?[A-Za-z0-9, -]*\}?)?\s*(.*)$/.exec(d);
      if (!m) continue;
      const set = deps.get(m[1]) ?? new Set<string>();
      if (m[2]) set.add(m[2].trim());
      deps.set(m[1], set);
    }
  }
  return {
    name: top("name"),
    version: top("version"),
    synopsis: top("synopsis").replace(/\s+/g, " ").slice(0, 300),
    license: top("license"),
    deps: [...deps.entries()]
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([name, ranges]) => ({ name, range: [...ranges].join(" || ") || "any" })),
  };
}

/** Descriptive fields for the package web page (top-level fields plus the head source repository). */
export interface CabalMeta {
  description: string;
  homepage: string;
  bugReports: string;
  author: string;
  maintainer: string;
  category: string;
  copyright: string;
  testedWith: string;
  repository: string;
}

export function cabalMeta(text: string): CabalMeta {
  const fs = fields(text);
  const top = (n: string) => fs.find((f) => f.indent === 0 && f.name === n)?.value.trim() ?? "";
  // cabal descriptions mark blank lines with a lone "."
  const description = top("description")
    .split("\n")
    .map((l) => (l.trim() === "." ? "" : l))
    .join("\n")
    .trim();
  return {
    description,
    homepage: top("homepage"),
    bugReports: top("bug-reports"),
    author: top("author").replace(/\s+/g, " "),
    maintainer: top("maintainer").replace(/\s+/g, " "),
    category: top("category").replace(/\s+/g, " "),
    copyright: top("copyright").replace(/\s+/g, " "),
    testedWith: top("tested-with").replace(/\s+/g, " "),
    repository: fs.find((f) => f.indent > 0 && f.name === "location")?.value.trim() ?? "",
  };
}

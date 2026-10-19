// Canonical JSON as defined by hackage-security (Text.JSON.Canonical):
// object keys sorted by code point, no whitespace, integers only, and only
// '"' and '\' escaped inside strings. hackage-security packs the rendering as
// Latin-1, so we refuse anything outside printable ASCII rather than produce
// bytes the client would render differently.

export type Json = null | boolean | number | string | Json[] | { [k: string]: Json };

function str(s: string): string {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x20 || c > 0x7e) throw new Error(`canonical JSON: non-printable-ASCII character in ${JSON.stringify(s)}`);
  }
  return `"${s.replace(/[\\"]/g, (c) => "\\" + c)}"`;
}

export function canonical(v: Json): string {
  if (v === null) return "null";
  if (v === true) return "true";
  if (v === false) return "false";
  if (typeof v === "number") {
    if (!Number.isSafeInteger(v)) throw new Error(`canonical JSON: non-integer number ${v}`);
    return String(v);
  }
  if (typeof v === "string") return str(v);
  if (Array.isArray(v)) return `[${v.map(canonical).join(",")}]`;
  const keys = Object.keys(v).sort();
  return `{${keys.map((k) => `${str(k)}:${canonical(v[k])}`).join(",")}}`;
}

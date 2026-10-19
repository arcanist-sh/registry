// Minimal, defensive tar reader (ustar + GNU long names + pax) and ustar writer.

export interface TarFile {
  path: string;
  type: "file" | "dir";
  data: Uint8Array; // empty for directories
}

export class TarError extends Error {}

const BLOCK = 512;
const dec = new TextDecoder();
const enc = new TextEncoder();

function cstr(b: Uint8Array, off: number, len: number): string {
  let end = off;
  while (end < off + len && b[end] !== 0) end++;
  return dec.decode(b.subarray(off, end));
}

function octal(b: Uint8Array, off: number, len: number): number {
  // GNU base-256 encoding for large numbers.
  if (b[off] & 0x80) {
    let n = b[off] & 0x7f;
    for (let i = 1; i < len; i++) n = n * 256 + b[off + i];
    return n;
  }
  const s = cstr(b, off, len).trim();
  if (s === "") return 0;
  if (!/^[0-7]+$/.test(s)) throw new TarError(`malformed numeric tar field "${s}"`);
  return parseInt(s, 8);
}

function checksumOk(h: Uint8Array): boolean {
  const stored = octal(h, 148, 8);
  let sum = 0;
  for (let i = 0; i < BLOCK; i++) sum += i >= 148 && i < 156 ? 0x20 : h[i];
  return sum === stored;
}

function parsePax(data: Uint8Array): Record<string, string> {
  const out: Record<string, string> = {};
  const text = dec.decode(data);
  let i = 0;
  while (i < text.length) {
    const sp = text.indexOf(" ", i);
    if (sp < 0) break;
    const len = parseInt(text.slice(i, sp), 10);
    if (!Number.isFinite(len) || len <= 0) throw new TarError("malformed pax header");
    const rec = text.slice(sp + 1, i + len - 1);
    const eq = rec.indexOf("=");
    if (eq > 0) out[rec.slice(0, eq)] = rec.slice(eq + 1);
    i += len;
  }
  return out;
}

export interface ReadLimits {
  maxEntries: number;
}

/** Parse an uncompressed tar. Rejects links, devices and malformed headers. */
export function readTar(buf: Uint8Array, limits: ReadLimits): TarFile[] {
  const files: TarFile[] = [];
  let off = 0;
  let longName: string | undefined;
  let paxPath: string | undefined;
  let entries = 0;
  while (off + BLOCK <= buf.length) {
    const h = buf.subarray(off, off + BLOCK);
    if (h.every((x) => x === 0)) break; // end of archive
    if (!checksumOk(h)) throw new TarError("tar header checksum mismatch");
    if (++entries > limits.maxEntries) throw new TarError(`tarball has more than ${limits.maxEntries} entries`);
    const size = octal(h, 124, 12);
    const type = String.fromCharCode(h[156] || 0x30);
    const dataStart = off + BLOCK;
    const dataEnd = dataStart + size;
    if (dataEnd > buf.length) throw new TarError("tar entry extends past end of archive");
    const data = buf.subarray(dataStart, dataEnd);
    off = dataStart + Math.ceil(size / BLOCK) * BLOCK;

    if (type === "L") {
      longName = cstr(data, 0, data.length);
      continue;
    }
    if (type === "x") {
      paxPath = parsePax(data).path;
      continue;
    }
    if (type === "g") continue; // global pax header: ignore

    const magic = cstr(h, 257, 6);
    const prefix = magic.startsWith("ustar") ? cstr(h, 345, 155) : "";
    let path = paxPath ?? longName ?? (prefix ? `${prefix}/${cstr(h, 0, 100)}` : cstr(h, 0, 100));
    longName = undefined;
    paxPath = undefined;

    if (type === "0" || type === "7") {
      files.push({ path, type: "file", data });
    } else if (type === "5") {
      if (path.endsWith("/")) path = path.slice(0, -1);
      files.push({ path, type: "dir", data: new Uint8Array(0) });
    } else {
      const kind: Record<string, string> = { "1": "hard link", "2": "symlink", "3": "character device", "4": "block device", "6": "FIFO" };
      throw new TarError(`tarball contains a ${kind[type] ?? `type '${type}' entry`} at ${path}; only regular files and directories are allowed`);
    }
  }
  return files;
}

function writeOctal(h: Uint8Array, off: number, len: number, n: number) {
  const s = n.toString(8).padStart(len - 1, "0");
  h.set(enc.encode(s), off);
  h[off + len - 1] = 0;
}

/** Encode one ustar entry (header + padded data). */
export function tarEntry(path: string, data: Uint8Array, mtime: number): Uint8Array {
  const h = new Uint8Array(BLOCK);
  let name = path;
  let prefix = "";
  if (enc.encode(name).length > 100) {
    const cut = path.lastIndexOf("/", 155);
    if (cut <= 0 || enc.encode(path.slice(cut + 1)).length > 100) throw new TarError(`path too long for ustar: ${path}`);
    prefix = path.slice(0, cut);
    name = path.slice(cut + 1);
  }
  h.set(enc.encode(name), 0);
  writeOctal(h, 100, 8, 0o644);
  writeOctal(h, 108, 8, 0);
  writeOctal(h, 116, 8, 0);
  writeOctal(h, 124, 12, data.length);
  writeOctal(h, 136, 12, Math.floor(mtime));
  h[156] = 0x30; // regular file
  h.set(enc.encode("ustar\u000000"), 257);
  h.set(enc.encode("arcanist"), 265);
  h.set(enc.encode("arcanist"), 297);
  if (prefix) h.set(enc.encode(prefix), 345);
  h.fill(0x20, 148, 156);
  let sum = 0;
  for (const b of h) sum += b;
  writeOctal(h, 148, 7, sum);
  h[155] = 0x20;
  const padded = Math.ceil(data.length / BLOCK) * BLOCK;
  const out = new Uint8Array(BLOCK + padded);
  out.set(h, 0);
  out.set(data, BLOCK);
  return out;
}

export const TAR_TRAILER = new Uint8Array(2 * BLOCK);

export function concat(parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

// The cabal-facing repository: index files, package tarballs and the
// hackage-security metadata (root/mirrors from R2, snapshot/timestamp signed
// online by the Worker).

import type { Json } from "./canonical";
import { type IndexKind, type IndexView, finalInfo, readState, streamIndex, viewSize } from "./index-store";
import { sha256Hex } from "./sha256";
import { type SigningKey, fileInfo, importOnlineKey, signDoc, tufTime } from "./tuf";
import { HttpError, nowSec, withSecurityHeaders } from "./util";

const DAY = 86400;
export const SNAPSHOT_DAYS = 14;
export const TIMESTAMP_DAYS = 3;
const REFRESH_MARGIN = DAY;

export const ROOT_KEY = "tuf/root.json";
export const MIRRORS_KEY = "tuf/mirrors.json";

export async function onlineKey(env: Env): Promise<SigningKey | null> {
  if (!env.TUF_ONLINE_KEY) return null;
  return importOnlineKey(env.TUF_ONLINE_KEY);
}

interface MetaRow {
  version: number;
  expires_at: number;
  body: string;
  index_seq: number;
  tar_length: number;
  gz_length: number;
}

async function metaRow(env: Env, file: string): Promise<MetaRow | null> {
  return env.DB.prepare("SELECT version, expires_at, body, index_seq, tar_length, gz_length FROM tuf_meta WHERE file = ?")
    .bind(file)
    .first<MetaRow>();
}

/** Whether this deployment serves hackage-security metadata. */
export async function tufEnabled(env: Env): Promise<boolean> {
  if (!env.TUF_ONLINE_KEY) return false;
  return (await env.BLOBS.head(ROOT_KEY)) !== null && (await env.BLOBS.head(MIRRORS_KEY)) !== null;
}

/**
 * Re-sign snapshot.json and timestamp.json if the index moved, root/mirrors
 * changed, or either is within a day of expiry. Returns false when TUF is not
 * configured.
 */
export async function refreshTuf(env: Env, force = false): Promise<boolean> {
  const key = await onlineKey(env);
  if (!key) return false;
  const [root, mirrors] = await Promise.all([env.BLOBS.get(ROOT_KEY), env.BLOBS.get(MIRRORS_KEY)]);
  if (!root || !mirrors) return false;
  const rootBytes = new Uint8Array(await root.arrayBuffer());
  const mirrorsBytes = new Uint8Array(await mirrors.arrayBuffer());
  const now = nowSec();
  const [snap, ts, st] = await Promise.all([metaRow(env, "snapshot.json"), metaRow(env, "timestamp.json"), readState(env.DB)]);

  const info = finalInfo(st);
  const meta: { [k: string]: Json } = {
    "<repo>/01-index.tar": fileInfo(info.tar.sha256, info.tar.length),
    "<repo>/01-index.tar.gz": fileInfo(info.gz.sha256, info.gz.length),
    "<repo>/root.json": fileInfo(await sha256Hex(rootBytes), rootBytes.length),
    "<repo>/mirrors.json": fileInfo(await sha256Hex(mirrorsBytes), mirrorsBytes.length),
  };
  const sameMeta = snap !== null && JSON.stringify((JSON.parse(snap.body) as { signed: { meta: Json } }).signed.meta) === JSON.stringify(sortKeys(meta));
  const needSnap = force || !snap || !sameMeta || snap.expires_at - now < REFRESH_MARGIN;
  let snapBody = snap?.body ?? "";
  const stmts: D1PreparedStatement[] = [];
  if (needSnap) {
    const version = (snap?.version ?? 0) + 1;
    const expires = now + SNAPSHOT_DAYS * DAY;
    snapBody = await signDoc({ _type: "Snapshot", expires: tufTime(expires * 1000), meta, version }, [key]);
    stmts.push(
      env.DB.prepare(
        `INSERT INTO tuf_meta (file, version, expires_at, body, index_seq, tar_length, gz_length)
         VALUES ('snapshot.json', ?, ?, ?, ?, ?, ?)
         ON CONFLICT (file) DO UPDATE SET version = excluded.version, expires_at = excluded.expires_at,
           body = excluded.body, index_seq = excluded.index_seq, tar_length = excluded.tar_length,
           gz_length = excluded.gz_length
         WHERE excluded.version > tuf_meta.version`,
      ).bind(version, expires, snapBody, st.seq, st.tarLength, st.gzLength),
    );
  }
  if (needSnap || !ts || ts.expires_at - now < REFRESH_MARGIN) {
    const version = (ts?.version ?? 0) + 1;
    const expires = now + TIMESTAMP_DAYS * DAY;
    const snapBytes = new TextEncoder().encode(snapBody);
    const tsBody = await signDoc(
      {
        _type: "Timestamp",
        expires: tufTime(expires * 1000),
        meta: { "<repo>/snapshot.json": fileInfo(await sha256Hex(snapBytes), snapBytes.length) },
        version,
      },
      [key],
    );
    // Only lands if the snapshot it describes is the one stored (a concurrent
    // refresh may have won the snapshot race).
    stmts.push(
      env.DB.prepare(
        `INSERT INTO tuf_meta (file, version, expires_at, body)
         SELECT 'timestamp.json', ?, ?, ? WHERE (SELECT body FROM tuf_meta WHERE file = 'snapshot.json') = ?
         ON CONFLICT (file) DO UPDATE SET version = excluded.version, expires_at = excluded.expires_at,
           body = excluded.body
         WHERE excluded.version > tuf_meta.version`,
      ).bind(version, expires, tsBody, snapBody),
    );
  }
  if (stmts.length) await env.DB.batch(stmts);
  return true;
}

function sortKeys(v: Json): Json {
  if (Array.isArray(v)) return v.map(sortKeys);
  if (v && typeof v === "object") {
    const o: { [k: string]: Json } = {};
    for (const k of Object.keys(v).sort()) o[k] = sortKeys(v[k]);
    return o;
  }
  return v;
}

/** The index prefix clients should see: the signed snapshot's, else the live state. */
export async function servedView(env: Env): Promise<IndexView> {
  if (await tufEnabled(env)) {
    let snap = await metaRow(env, "snapshot.json");
    if (!snap) {
      await refreshTuf(env);
      snap = await metaRow(env, "snapshot.json");
    }
    if (snap) return { seq: snap.index_seq, tarLength: snap.tar_length, gzLength: snap.gz_length };
  }
  const st = await readState(env.DB);
  return { seq: st.seq, tarLength: st.tarLength, gzLength: st.gzLength };
}

function parseRange(header: string | null, size: number): [number, number] | null {
  if (!header) return null;
  const m = /^bytes=(\d*)-(\d*)$/.exec(header.trim());
  if (!m || (m[1] === "" && m[2] === "")) {
    throw new HttpError(416, "bad_range", "only a single byte range is supported", undefined, { "Content-Range": `bytes */${size}` });
  }
  let start: number;
  let end: number; // exclusive
  if (m[1] === "") {
    start = Math.max(0, size - Number(m[2]));
    end = size;
  } else {
    start = Number(m[1]);
    end = m[2] === "" ? size : Math.min(size, Number(m[2]) + 1);
  }
  if (start >= size || start >= end) {
    throw new HttpError(416, "bad_range", "requested range is outside the file", undefined, { "Content-Range": `bytes */${size}` });
  }
  return [start, end];
}

export async function serveIndex(env: Env, req: Request, kind: IndexKind): Promise<Response> {
  const view = await servedView(env);
  const size = viewSize(kind, view);
  const range = parseRange(req.headers.get("Range"), size);
  const [from, to] = range ?? [0, size];
  const headers: Record<string, string> = withSecurityHeaders({
    "Content-Type": kind === "tar" ? "application/x-tar" : "application/gzip",
    "Accept-Ranges": "bytes",
    "Content-Length": String(to - from),
    "Cache-Control": "public, max-age=60",
    ETag: `"${kind}-${view.seq}"`,
  });
  if (range) headers["Content-Range"] = `bytes ${from}-${to - 1}/${size}`;
  let body: ReadableStream | null = null;
  if (req.method !== "HEAD") {
    // FixedLengthStream keeps Content-Length (and so Range handling) intact.
    const fixed = new FixedLengthStream(to - from);
    void (await streamIndex(env, kind, view, from, to)).pipeTo(fixed.writable).catch((e: unknown) => {
      console.error(JSON.stringify({ msg: "index stream failed", error: String(e) }));
    });
    body = fixed.readable;
  }
  return new Response(body, { status: range ? 206 : 200, headers });
}

export async function serveTufFile(env: Env, file: string): Promise<Response> {
  const headers = (maxAge: number) =>
    withSecurityHeaders({ "Content-Type": "application/json; charset=utf-8", "Cache-Control": `public, max-age=${maxAge}` });
  if (file === "root.json" || file === "mirrors.json") {
    const obj = await env.BLOBS.get(file === "root.json" ? ROOT_KEY : MIRRORS_KEY);
    if (!obj) throw notConfigured();
    return new Response(obj.body, { headers: headers(300) });
  }
  if (!(await tufEnabled(env))) throw notConfigured();
  let row = await metaRow(env, file);
  if (!row || row.expires_at - nowSec() < REFRESH_MARGIN) {
    await refreshTuf(env);
    row = await metaRow(env, file);
  }
  if (!row) throw notConfigured();
  return new Response(row.body, { headers: headers(file === "timestamp.json" ? 30 : 60) });
}

function notConfigured(): HttpError {
  return new HttpError(
    404,
    "tuf_not_configured",
    "this registry does not serve hackage-security metadata yet",
    "use `secure: False` in the cabal repository stanza, or ask the operator to upload root.json/mirrors.json and set TUF_ONLINE_KEY",
  );
}

export async function servePackageTarball(env: Env, name: string, version: string, method: string): Promise<Response> {
  const pkgid = `${name}-${version}`;
  const row = await env.DB.prepare("SELECT sha256 FROM versions WHERE package = ? AND version = ?").bind(name, version).first<{ sha256: string }>();
  const key = row ? `blobs/${row.sha256}.tar.gz` : null;
  const obj = key ? (method === "HEAD" ? await env.BLOBS.head(key) : await env.BLOBS.get(key)) : null;
  if (!obj) throw new HttpError(404, "not_found", `package ${pkgid} not found`);
  return new Response("body" in obj ? (obj as R2ObjectBody).body : null, {
    headers: withSecurityHeaders({
      "Content-Type": "application/gzip",
      "Content-Length": String(obj.size),
      "Content-Disposition": `attachment; filename="${pkgid}.tar.gz"`,
      "Cache-Control": "public, max-age=31536000, immutable",
      ETag: obj.httpEtag,
    }),
  });
}

export type { IndexKind };

// The append-only package index (01-index.tar / 01-index.tar.gz).
//
// Layout: [sealed R2 segments...] [D1 tail chunks...] [trailer]
// A view (seq, tarLength, gzLength) names a prefix of the index; snapshot.json
// pins the view clients must see, so a publish that lands mid-request never
// produces a file whose hash disagrees with the signed snapshot.

import { GZ_TRAILER, gzip } from "./gzip";
import { Sha256 } from "./sha256";
import { TAR_TRAILER, concat, tarEntry } from "./tar";
import { nowSec } from "./util";

export interface IndexEntry {
  path: string;
  data: Uint8Array;
}

export interface IndexState {
  seq: number;
  tarLength: number; // without trailer
  gzLength: number; // without trailer member
  tarSha: Sha256; // over the bytes without trailer
  gzSha: Sha256;
}

export interface IndexView {
  seq: number;
  tarLength: number;
  gzLength: number;
}

export type IndexKind = "tar" | "gz";

/** Seal the D1 tail into an R2 segment once it holds this many tar bytes. */
export const SEAL_THRESHOLD = 1024 * 1024;

const trailerFor = (k: IndexKind) => (k === "tar" ? TAR_TRAILER : GZ_TRAILER);

export async function readState(db: D1Database): Promise<IndexState> {
  const row = await db
    .prepare("SELECT seq, tar_length, gz_length, tar_sha, gz_sha FROM index_state WHERE id = 1")
    .first<{ seq: number; tar_length: number; gz_length: number; tar_sha: ArrayBuffer; gz_sha: ArrayBuffer }>();
  if (!row) return { seq: 0, tarLength: 0, gzLength: 0, tarSha: new Sha256(), gzSha: new Sha256() };
  return {
    seq: row.seq,
    tarLength: row.tar_length,
    gzLength: row.gz_length,
    tarSha: Sha256.fromState(new Uint8Array(row.tar_sha)),
    gzSha: Sha256.fromState(new Uint8Array(row.gz_sha)),
  };
}

/** Final file hashes and lengths for a state (trailer included). */
export function finalInfo(st: IndexState) {
  return {
    tar: { sha256: st.tarSha.clone().update(TAR_TRAILER).hex(), length: st.tarLength + TAR_TRAILER.length },
    gz: { sha256: st.gzSha.clone().update(GZ_TRAILER).hex(), length: st.gzLength + GZ_TRAILER.length },
  };
}

/** Path of the entry a fresh index starts with. */
export const SEED_ENTRY_PATH = "README";

const SEED_TEXT = `This is the package index of a Haskell package repository.
Packages appear below as <name>/<version>/<name>.cabal entries.
`;

/**
 * Give a fresh index its first entry. cabal cannot read an index tarball that
 * contains no entries at all ("short tar trailer"), and Hackage's index is
 * never empty, so neither should ours be. The README is not a package path,
 * so cabal and hackage-security skip it. A concurrent first call can add a
 * second README, which is equally harmless.
 */
export async function ensureIndexSeeded(db: D1Database): Promise<void> {
  if ((await readState(db)).tarLength > 0) return;
  await appendChunk(db, [{ path: SEED_ENTRY_PATH, data: new TextEncoder().encode(SEED_TEXT) }]);
}

export class AppendConflict extends Error {}

/**
 * Append one chunk of entries, atomically with `extra` statements (the
 * version row, ownership, ...). D1 batches are transactions: if another
 * writer appended first, the chunk's primary key collides, everything rolls
 * back, and we retry with fresh state.
 */
export async function appendChunk(
  db: D1Database,
  entries: IndexEntry[],
  extra: D1PreparedStatement[] = [],
  mtime = nowSec(),
): Promise<IndexState> {
  const tar = concat(entries.map((e) => tarEntry(e.path, e.data, mtime)));
  const gz = await gzip(tar);
  for (let attempt = 0; attempt < 5; attempt++) {
    const st = await readState(db);
    const next: IndexState = {
      seq: st.seq + 1,
      tarLength: st.tarLength + tar.length,
      gzLength: st.gzLength + gz.length,
      tarSha: st.tarSha.update(tar),
      gzSha: st.gzSha.update(gz),
    };
    const stmts = [
      db
        .prepare("INSERT INTO index_chunks (seq, tar_offset, tar_bytes, gz_offset, gz_bytes) VALUES (?, ?, ?, ?, ?)")
        .bind(next.seq, st.tarLength, tar, st.gzLength, gz),
      db
        .prepare(
          `INSERT INTO index_state (id, seq, tar_length, gz_length, tar_sha, gz_sha, updated_at)
           VALUES (1, ?, ?, ?, ?, ?, ?)
           ON CONFLICT (id) DO UPDATE SET seq = excluded.seq, tar_length = excluded.tar_length,
             gz_length = excluded.gz_length, tar_sha = excluded.tar_sha, gz_sha = excluded.gz_sha,
             updated_at = excluded.updated_at`,
        )
        .bind(next.seq, next.tarLength, next.gzLength, next.tarSha.state(), next.gzSha.state(), nowSec()),
      ...extra,
    ];
    try {
      await db.batch(stmts);
      return next;
    } catch (e) {
      const msg = String((e as Error).message ?? e);
      if (/UNIQUE constraint failed: index_chunks\.seq/.test(msg)) continue;
      throw e;
    }
  }
  throw new AppendConflict("index is busy; retry the request");
}

interface Piece {
  start: number; // absolute offset in the file
  length: number;
  read(from: number, to: number): Promise<Uint8Array>; // relative to piece
}

/**
 * Build the list of byte pieces forming the view of `kind`.
 * Segments and tail rows are read in one D1 batch (a consistent snapshot).
 */
async function pieces(env: Env, kind: IndexKind, view: IndexView, range?: [number, number]): Promise<Piece[]> {
  const off = kind === "tar" ? "tar_offset" : "gz_offset";
  const bytes = kind === "tar" ? "tar_bytes" : "gz_bytes";
  const lo = range ? range[0] : 0;
  const hi = range ? range[1] : Number.MAX_SAFE_INTEGER;
  const [segs, rows] = await env.DB.batch([
    env.DB.prepare(
      `SELECT id, ${off} AS o, ${kind === "tar" ? "tar_length" : "gz_length"} AS n FROM index_segments
       WHERE first_seq <= ? ORDER BY first_seq`,
    ).bind(view.seq),
    env.DB.prepare(
      `SELECT ${off} AS o, ${bytes} AS b FROM index_chunks
       WHERE seq <= ? AND ${off} < ? AND ${off} + length(${bytes}) > ? ORDER BY seq`,
    ).bind(view.seq, hi, lo),
  ]);
  const len = kind === "tar" ? view.tarLength : view.gzLength;
  const out: Piece[] = [];
  // A segment sealed after the view was pinned may extend past it; clamp.
  for (const s of segs.results as { id: number; o: number; n: number }[]) {
    if (s.o + s.n <= lo || s.o >= hi) continue;
    const key = `index/segments/${s.id}.${kind === "tar" ? "tar" : "tar.gz"}`;
    out.push({
      start: s.o,
      length: Math.min(s.n, len - s.o),
      async read(from, to) {
        const obj = await env.BLOBS.get(key, { range: { offset: from, length: to - from } });
        if (!obj) throw new Error(`index segment ${key} is missing`);
        return new Uint8Array(await obj.arrayBuffer());
      },
    });
  }
  for (const r of rows.results as { o: number; b: ArrayBuffer }[]) {
    const b = new Uint8Array(r.b);
    out.push({ start: r.o, length: b.length, read: async (from, to) => b.subarray(from, to) });
  }
  const trailer = trailerFor(kind);
  out.push({ start: len, length: trailer.length, read: async (from, to) => trailer.subarray(from, to) });
  out.sort((a, b) => a.start - b.start);
  return out;
}

export function viewSize(kind: IndexKind, view: IndexView): number {
  return kind === "tar" ? view.tarLength + TAR_TRAILER.length : view.gzLength + GZ_TRAILER.length;
}

/** Stream bytes [from, to) of the view. */
export async function streamIndex(env: Env, kind: IndexKind, view: IndexView, from: number, to: number): Promise<ReadableStream<Uint8Array>> {
  const ps = await pieces(env, kind, view, [from, to]);
  let i = 0;
  return new ReadableStream<Uint8Array>({
    async pull(controller) {
      while (i < ps.length) {
        const p = ps[i++];
        const a = Math.max(from, p.start);
        const b = Math.min(to, p.start + p.length);
        if (a >= b) continue;
        controller.enqueue(await p.read(a - p.start, b - p.start));
        return;
      }
      controller.close();
    },
  });
}

/**
 * Move all tail chunks into one immutable R2 segment pair when the tail is
 * large enough (or `force`). The segment objects are written before rows are
 * deleted, so readers always find the bytes somewhere.
 */
export async function sealIndex(env: Env, force = false): Promise<{ sealed: number }> {
  const rows = (
    await env.DB.prepare("SELECT seq, tar_offset, tar_bytes, gz_offset, gz_bytes FROM index_chunks ORDER BY seq").all<{
      seq: number;
      tar_offset: number;
      tar_bytes: ArrayBuffer;
      gz_offset: number;
      gz_bytes: ArrayBuffer;
    }>()
  ).results;
  if (rows.length === 0) return { sealed: 0 };
  const tar = concat(rows.map((r) => new Uint8Array(r.tar_bytes)));
  if (!force && tar.length < SEAL_THRESHOLD) return { sealed: 0 };
  const gz = concat(rows.map((r) => new Uint8Array(r.gz_bytes)));
  const first = rows[0].seq;
  const last = rows[rows.length - 1].seq;
  await env.BLOBS.put(`index/segments/${first}.tar`, tar);
  await env.BLOBS.put(`index/segments/${first}.tar.gz`, gz);
  await env.DB.batch([
    env.DB.prepare(
      "INSERT INTO index_segments (id, first_seq, last_seq, tar_offset, tar_length, gz_offset, gz_length) VALUES (?, ?, ?, ?, ?, ?, ?)",
    ).bind(first, first, last, rows[0].tar_offset, tar.length, rows[0].gz_offset, gz.length),
    env.DB.prepare("DELETE FROM index_chunks WHERE seq BETWEEN ? AND ?").bind(first, last),
  ]);
  return { sealed: rows.length };
}

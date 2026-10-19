// Upload validation and publishing.

import { type Caller, requireScope } from "./auth";
import { PACKAGE_NAME_RE, VERSION_RE, parseCabal } from "./cabal";
import { canonical } from "./canonical";
import { SizeLimitError, gunzipLimited } from "./gzip";
import { type IndexEntry, appendChunk } from "./index-store";
import { checkNewName } from "./policy";
import { refreshTuf } from "./repo";
import { sha256Hex } from "./sha256";
import { TarError, readTar } from "./tar";
import { HttpError, nowSec, readBodyLimited } from "./util";

export const LIMITS = {
  tarballBytes: 16 * 1024 * 1024,
  unpackedBytes: 64 * 1024 * 1024,
  entries: 10_000,
  cabalBytes: 1024 * 1024,
};

const enc = new TextEncoder();

export function compareVersions(a: string, b: string): number {
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] ?? -1) - (pb[i] ?? -1);
    if (d) return d;
  }
  return 0;
}

export function blobKey(sha256: string): string {
  return `blobs/${sha256}.tar.gz`;
}

function checkPath(p: string, top: string): void {
  if (p.includes("\0") || p.includes("\\")) throw new HttpError(400, "bad_tarball", `tarball path ${JSON.stringify(p)} contains NUL or backslash`);
  if (p.startsWith("/")) throw new HttpError(400, "bad_tarball", `tarball path ${p} is absolute`);
  const parts = p.split("/");
  if (parts.some((x) => x === ".." || x === ".")) throw new HttpError(400, "bad_tarball", `tarball path ${p} contains "." or ".." components`);
  if (parts[0] !== top) throw new HttpError(400, "bad_tarball", `tarball path ${p} is outside the top-level directory ${top}/`);
}

export interface ValidatedUpload {
  name: string;
  version: string;
  sha256: string;
  size: number;
  cabal: string;
  synopsis: string;
  license: string;
  deps: { name: string; range: string }[];
}

/** Validate an sdist tarball entirely in memory, before anything is stored. */
export async function validateTarball(body: Uint8Array): Promise<ValidatedUpload> {
  let files;
  try {
    files = readTar(await gunzipLimited(body, LIMITS.unpackedBytes), { maxEntries: LIMITS.entries });
  } catch (e) {
    if (e instanceof SizeLimitError) throw new HttpError(413, "too_large", e.message);
    if (e instanceof TarError) throw new HttpError(400, "bad_tarball", e.message);
    throw new HttpError(400, "bad_tarball", "upload is not a gzip-compressed tar archive", "upload the file produced by `cabal sdist`");
  }
  if (files.length === 0) throw new HttpError(400, "bad_tarball", "tarball is empty");
  const top = files[0].path.split("/")[0];
  for (const f of files) checkPath(f.path, top);
  const m = /^(.+)-([0-9][0-9.]*)$/.exec(top);
  if (!m || !PACKAGE_NAME_RE.test(m[1]) || !VERSION_RE.test(m[2])) {
    throw new HttpError(400, "bad_tarball", `top-level directory "${top}" is not <name>-<version>`);
  }
  const [, name, version] = m;
  const cabalPath = `${top}/${name}.cabal`;
  const cabalFile = files.find((f) => f.type === "file" && f.path === cabalPath);
  if (!cabalFile) throw new HttpError(400, "bad_tarball", `tarball does not contain ${cabalPath}`);
  if (cabalFile.data.length > LIMITS.cabalBytes) throw new HttpError(413, "too_large", `${cabalPath} is larger than ${LIMITS.cabalBytes} bytes`);
  const cabal = new TextDecoder().decode(cabalFile.data);
  const info = parseCabal(cabal);
  if (info.name !== name) {
    throw new HttpError(400, "name_mismatch", `${name}.cabal declares name "${info.name}", but the tarball is ${top}`);
  }
  if (info.version !== version) {
    throw new HttpError(400, "version_mismatch", `${name}.cabal declares version "${info.version}", but the tarball is ${top}`);
  }
  return {
    name,
    version,
    sha256: await sha256Hex(body),
    size: body.length,
    cabal,
    synopsis: info.synopsis,
    license: info.license,
    deps: info.deps,
  };
}

/** Hackage-format per-version target metadata (unsigned; covered by the snapshot). */
export function packageJson(name: string, version: string, sha256: string, length: number): string {
  return canonical({
    signatures: [],
    signed: {
      _type: "Targets",
      expires: null,
      targets: { [`<repo>/package/${name}-${version}.tar.gz`]: { hashes: { sha256 }, length } },
      version: 0,
    },
  });
}

export async function handlePublish(env: Env, req: Request, caller: Caller): Promise<Response> {
  requireScope(caller, "publish");
  const { success } = await env.PUBLISH_LIMITER.limit({ key: `publish:${caller.userId}` });
  if (!success) throw new HttpError(429, "rate_limited", "too many publishes; wait a minute", undefined, { "Retry-After": "60" });

  const body = await readBodyLimited(req, LIMITS.tarballBytes);
  const up = await validateTarball(body);
  requireScope(caller, "publish", up.name);

  const pkg = await env.DB.prepare("SELECT name FROM packages WHERE name = ?").bind(up.name).first();
  const now = nowSec();
  const extra: D1PreparedStatement[] = [];
  if (pkg) {
    const owner = await env.DB.prepare("SELECT 1 FROM package_owners WHERE package = ? AND user_id = ?").bind(up.name, caller.userId).first();
    if (!owner) throw new HttpError(403, "not_owner", `you are not an owner of ${up.name}`, `ask an owner to run \`hx registry owner add ${up.name} ${caller.login}\``);
    const exists = await env.DB.prepare("SELECT yanked FROM versions WHERE package = ? AND version = ?").bind(up.name, up.version).first();
    if (exists) {
      throw new HttpError(409, "version_exists", `${up.name}-${up.version} already exists and versions are immutable`, "bump the version in your .cabal file");
    }
    extra.push(env.DB.prepare("UPDATE packages SET synopsis = ? WHERE name = ?").bind(up.synopsis, up.name));
  } else {
    await checkNewName(env, up.name, caller.userId);
    extra.push(
      env.DB.prepare("INSERT INTO packages (name, name_lower, synopsis, created_at) VALUES (?, ?, ?, ?)").bind(up.name, up.name.toLowerCase(), up.synopsis, now),
      env.DB.prepare("INSERT INTO package_owners (package, user_id, added_at) VALUES (?, ?, ?)").bind(up.name, caller.userId, now),
    );
  }
  extra.push(
    env.DB.prepare(
      `INSERT INTO versions (package, version, sha256, size, cabal_file, synopsis, license, deps, published_by, published_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).bind(up.name, up.version, up.sha256, up.size, up.cabal, up.synopsis, up.license, JSON.stringify(up.deps), caller.userId, now),
    env.DB.prepare("INSERT INTO audit_log (at, user_id, action, subject, detail) VALUES (?, ?, 'publish', ?, ?)").bind(
      now,
      caller.userId,
      `${up.name}-${up.version}`,
      up.sha256,
    ),
  );

  // Content-addressed blob: a racing duplicate upload can never replace the
  // bytes of a version that won the D1 insert.
  await env.BLOBS.put(blobKey(up.sha256), body, {
    httpMetadata: { contentType: "application/gzip" },
    sha256: up.sha256,
  });

  const entries: IndexEntry[] = [
    { path: `${up.name}/${up.version}/package.json`, data: enc.encode(packageJson(up.name, up.version, up.sha256, up.size)) },
    { path: `${up.name}/${up.version}/${up.name}.cabal`, data: enc.encode(up.cabal) },
  ];
  try {
    await appendChunk(env.DB, entries, extra, now);
  } catch (e) {
    const msg = String((e as Error).message ?? e);
    if (/UNIQUE constraint failed: (versions|packages)/.test(msg)) {
      throw new HttpError(409, "version_exists", `${up.name}-${up.version} was published concurrently`);
    }
    throw e;
  }
  await refreshTuf(env);
  return new Response(
    JSON.stringify({ name: up.name, version: up.version, sha256: up.sha256, size: up.size, url: `${env.PUBLIC_URL}/package/${up.name}-${up.version}` }, null, 2) + "\n",
    { status: 201, headers: { "Content-Type": "application/json; charset=utf-8" } },
  );
}

/** preferred-versions body excluding all yanked versions. */
export function preferredVersions(name: string, yanked: string[]): string {
  if (yanked.length === 0) return `${name} >=0\n`;
  const sorted = [...yanked].sort(compareVersions);
  return `${name} ${sorted.map((v) => `(<${v} || >${v})`).join(" && ")}\n`;
}

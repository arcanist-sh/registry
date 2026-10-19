// JSON API handlers (everything under /api/v1 except publish).

import { type Caller, mintToken, parseScopes, requireAdmin, requireScope } from "./auth";
import { PACKAGE_NAME_RE, VERSION_RE } from "./cabal";
import { canonical, type Json } from "./canonical";
import { appendChunk, sealIndex } from "./index-store";
import { LIMITS, compareVersions, preferredVersions } from "./publish";
import { MIRRORS_KEY, ROOT_KEY, onlineKey, refreshTuf, tufEnabled } from "./repo";
import { TufError, checkMirrors, checkRoot, verifyEd25519 } from "./tuf";
import { HttpError, b64decode, json, nowSec, readBodyLimited, readJson } from "./util";

const enc = new TextEncoder();

function assertName(name: string) {
  if (!PACKAGE_NAME_RE.test(name)) throw new HttpError(400, "bad_name", `"${name}" is not a valid package name`);
}

function assertVersion(v: string) {
  if (!VERSION_RE.test(v)) throw new HttpError(400, "bad_version", `"${v}" is not a valid version`);
}

async function requireOwner(env: Env, c: Caller, pkg: string) {
  const exists = await env.DB.prepare("SELECT 1 FROM packages WHERE name = ?").bind(pkg).first();
  if (!exists) throw new HttpError(404, "not_found", `package ${pkg} not found`);
  const row = await env.DB.prepare("SELECT 1 FROM package_owners WHERE package = ? AND user_id = ?").bind(pkg, c.userId).first();
  if (!row && !c.isAdmin) throw new HttpError(403, "not_owner", `you are not an owner of ${pkg}`);
}

// ---- config ---------------------------------------------------------------

export async function getConfig(env: Env): Promise<Response> {
  let tuf: Json = { enabled: false };
  if (await tufEnabled(env)) {
    const root = await env.BLOBS.get(ROOT_KEY);
    if (root) {
      const doc = JSON.parse(await root.text()) as { signed: { roles: { root: { keyids: string[]; threshold: number } } } };
      tuf = { enabled: true, root_keys: doc.signed.roles.root.keyids, key_threshold: doc.signed.roles.root.threshold };
    }
  }
  return json({
    name: env.REGISTRY_NAME,
    url: env.PUBLIC_URL,
    api_version: 1,
    tuf,
    limits: { tarball_bytes: LIMITS.tarballBytes, unpacked_bytes: LIMITS.unpackedBytes, entries: LIMITS.entries },
  });
}

// ---- search / info ----------------------------------------------------------

interface VersionRow {
  version: string;
  yanked: number;
  published_at: number;
  sha256: string;
  size: number;
}

function latestOf(versions: VersionRow[]): string | null {
  const live = versions.filter((v) => !v.yanked).map((v) => v.version);
  const pool = live.length ? live : versions.map((v) => v.version);
  return pool.sort(compareVersions).at(-1) ?? null;
}

export async function search(env: Env, url: URL): Promise<Response> {
  const q = (url.searchParams.get("q") ?? "").trim().toLowerCase();
  const limit = Math.min(Math.max(Number(url.searchParams.get("limit") ?? 20) || 20, 1), 100);
  if (q.length > 100) throw new HttpError(400, "bad_query", "query too long");
  const like = `%${q.replace(/[\\%_]/g, (c) => "\\" + c)}%`;
  const rows = (
    await env.DB.prepare(
      `SELECT p.name, p.synopsis, (SELECT json_group_array(json_object('version', v.version, 'yanked', v.yanked))
         FROM versions v WHERE v.package = p.name) AS versions
       FROM packages p WHERE p.name_lower LIKE ?1 ESCAPE '\\' OR lower(p.synopsis) LIKE ?1 ESCAPE '\\' LIMIT 500`,
    )
      .bind(like)
      .all<{ name: string; synopsis: string; versions: string }>()
  ).results;
  const score = (n: string) => {
    const l = n.toLowerCase();
    if (l === q) return 100;
    if (l.startsWith(q)) return 80;
    if (l.includes(q)) return 60;
    return 20; // synopsis match
  };
  const results = rows
    .map((r) => {
      const vs = JSON.parse(r.versions) as VersionRow[];
      return { name: r.name, synopsis: r.synopsis, latest: latestOf(vs), score: score(r.name) };
    })
    .sort((a, b) => b.score - a.score || (a.name < b.name ? -1 : 1))
    .slice(0, limit)
    .map(({ score: _s, ...r }) => r);
  return json({ query: q, results }, 200, { "Cache-Control": "public, max-age=30" });
}

export async function packageInfo(env: Env, name: string): Promise<Response> {
  assertName(name);
  const [pkg, versions, owners, verified] = await env.DB.batch([
    env.DB.prepare("SELECT name, synopsis, created_at FROM packages WHERE name = ?").bind(name),
    env.DB.prepare("SELECT version, yanked, published_at, sha256, size FROM versions WHERE package = ?").bind(name),
    env.DB.prepare("SELECT u.login FROM package_owners o JOIN users u ON u.id = o.user_id WHERE o.package = ? ORDER BY u.login").bind(name),
    env.DB.prepare("SELECT DISTINCT version FROM attestations WHERE package = ? AND result = 'pass'").bind(name),
  ]);
  const p = pkg.results[0] as { name: string; synopsis: string; created_at: number } | undefined;
  if (!p) throw new HttpError(404, "not_found", `package ${name} not found`, "check the spelling, or search with `hx search --registry`");
  const vs = (versions.results as unknown as VersionRow[]).sort((a, b) => compareVersions(b.version, a.version));
  const ok = new Set((verified.results as { version: string }[]).map((r) => r.version));
  return json({
    name: p.name,
    synopsis: p.synopsis,
    created_at: p.created_at,
    latest: latestOf(vs),
    owners: (owners.results as { login: string }[]).map((o) => o.login),
    versions: vs.map((v) => ({
      version: v.version,
      yanked: v.yanked === 1,
      published_at: v.published_at,
      sha256: v.sha256,
      size: v.size,
      bhc_verified: ok.has(v.version),
    })),
  });
}

export async function versionInfo(env: Env, name: string, version: string): Promise<Response> {
  assertName(name);
  assertVersion(version);
  const [vr, att] = await env.DB.batch([
    env.DB.prepare(
      `SELECT v.*, u.login AS publisher FROM versions v JOIN users u ON u.id = v.published_by
       WHERE v.package = ? AND v.version = ?`,
    ).bind(name, version),
    env.DB.prepare(
      "SELECT verifier, bhc_version, profile, result, log_url, built_at, received_at FROM attestations WHERE package = ? AND version = ? ORDER BY received_at DESC",
    ).bind(name, version),
  ]);
  const v = vr.results[0] as Record<string, unknown> | undefined;
  if (!v) throw new HttpError(404, "not_found", `${name}-${version} not found`);
  const attestations = att.results as { result: string }[];
  return json({
    name,
    version,
    synopsis: v.synopsis,
    license: v.license,
    sha256: v.sha256,
    size: v.size,
    yanked: v.yanked === 1,
    yanked_at: v.yanked_at,
    published_at: v.published_at,
    published_by: v.publisher,
    deps: JSON.parse(String(v.deps)),
    tarball_url: `${env.PUBLIC_URL}/package/${name}-${version}.tar.gz`,
    cabal_url: `${env.PUBLIC_URL}/package/${name}-${version}/${name}.cabal`,
    bhc_verified: attestations.some((a) => a.result === "pass"),
    attestations,
  });
}

export async function cabalFile(env: Env, name: string, version: string): Promise<Response> {
  const row = await env.DB.prepare("SELECT cabal_file FROM versions WHERE package = ? AND version = ?").bind(name, version).first<{ cabal_file: string }>();
  if (!row) throw new HttpError(404, "not_found", `${name}-${version} not found`);
  return new Response(row.cabal_file, {
    headers: { "Content-Type": "text/plain; charset=utf-8", "X-Content-Type-Options": "nosniff", "Cache-Control": "public, max-age=300" },
  });
}

// ---- yank -----------------------------------------------------------------

export async function setYanked(env: Env, c: Caller, name: string, version: string, yanked: boolean): Promise<Response> {
  assertName(name);
  assertVersion(version);
  requireScope(c, "yank", name);
  await requireOwner(env, c, name);
  const row = await env.DB.prepare("SELECT yanked FROM versions WHERE package = ? AND version = ?").bind(name, version).first<{ yanked: number }>();
  if (!row) throw new HttpError(404, "not_found", `${name}-${version} not found`);
  if ((row.yanked === 1) === yanked) return json({ name, version, yanked, changed: false });
  const others = (
    await env.DB.prepare("SELECT version FROM versions WHERE package = ? AND yanked = 1 AND version != ?").bind(name, version).all<{ version: string }>()
  ).results.map((r) => r.version);
  const nowYanked = yanked ? [...others, version] : others;
  const now = nowSec();
  await appendChunk(
    env.DB,
    [{ path: `${name}/preferred-versions`, data: enc.encode(preferredVersions(name, nowYanked)) }],
    [
      env.DB.prepare("UPDATE versions SET yanked = ?, yanked_at = ? WHERE package = ? AND version = ?").bind(yanked ? 1 : 0, yanked ? now : null, name, version),
      env.DB.prepare("INSERT INTO audit_log (at, user_id, action, subject) VALUES (?, ?, ?, ?)").bind(now, c.userId, yanked ? "yank" : "unyank", `${name}-${version}`),
    ],
    now,
  );
  await refreshTuf(env);
  return json({ name, version, yanked, changed: true });
}

// ---- owners ---------------------------------------------------------------

export async function listOwners(env: Env, name: string): Promise<Response> {
  assertName(name);
  const rows = (
    await env.DB.prepare("SELECT u.login, o.added_at FROM package_owners o JOIN users u ON u.id = o.user_id WHERE o.package = ? ORDER BY u.login")
      .bind(name)
      .all()
  ).results;
  return json({ name, owners: rows });
}

export async function changeOwner(env: Env, c: Caller, name: string, login: string, add: boolean): Promise<Response> {
  assertName(name);
  requireScope(c, "owners", name);
  await requireOwner(env, c, name);
  const user = await env.DB.prepare("SELECT id FROM users WHERE login = ?").bind(login).first<{ id: number }>();
  if (!user) throw new HttpError(404, "no_such_user", `no user named ${login}`);
  const now = nowSec();
  if (add) {
    await env.DB.prepare("INSERT OR IGNORE INTO package_owners (package, user_id, added_at) VALUES (?, ?, ?)").bind(name, user.id, now).run();
  } else {
    const count = await env.DB.prepare("SELECT count(*) AS n FROM package_owners WHERE package = ?").bind(name).first<{ n: number }>();
    if ((count?.n ?? 0) <= 1) throw new HttpError(409, "last_owner", `cannot remove the last owner of ${name}`, "add another owner first");
    await env.DB.prepare("DELETE FROM package_owners WHERE package = ? AND user_id = ?").bind(name, user.id).run();
  }
  await env.DB.prepare("INSERT INTO audit_log (at, user_id, action, subject, detail) VALUES (?, ?, ?, ?, ?)")
    .bind(now, c.userId, add ? "owner_add" : "owner_remove", name, login)
    .run();
  return listOwners(env, name);
}

// ---- tokens ---------------------------------------------------------------

export function me(c: Caller): Response {
  return json({ login: c.login, admin: c.isAdmin, token: { id: c.tokenId, scopes: [...c.scopes], packages: c.packages } });
}

export async function listTokens(env: Env, c: Caller): Promise<Response> {
  const rows = (
    await env.DB.prepare(
      "SELECT id, name, scopes, packages, created_at, expires_at, last_used_at FROM tokens WHERE user_id = ? AND revoked_at IS NULL ORDER BY created_at",
    )
      .bind(c.userId)
      .all<{ id: string; name: string; scopes: string; packages: string | null; created_at: number; expires_at: number | null; last_used_at: number | null }>()
  ).results;
  return json({
    tokens: rows.map((r) => ({ ...r, scopes: r.scopes.split(" "), packages: r.packages ? JSON.parse(r.packages) : null })),
  });
}

interface TokenRequest {
  name?: string;
  scopes?: string[];
  packages?: string[];
  expires_in_days?: number;
}

function tokenParams(body: TokenRequest) {
  const name = (body.name ?? "").trim();
  if (!name || name.length > 64) throw new HttpError(400, "bad_name", "token name must be 1-64 characters");
  const scopes = parseScopes(body.scopes);
  let packages: string[] | null = null;
  if (body.packages !== undefined) {
    if (!Array.isArray(body.packages) || body.packages.length > 100) throw new HttpError(400, "bad_packages", "packages must be an array of at most 100 names");
    body.packages.forEach(assertName);
    packages = body.packages;
  }
  let expires: number | null = null;
  if (body.expires_in_days !== undefined) {
    if (!Number.isInteger(body.expires_in_days) || body.expires_in_days < 1 || body.expires_in_days > 3650) {
      throw new HttpError(400, "bad_expiry", "expires_in_days must be an integer between 1 and 3650");
    }
    expires = nowSec() + body.expires_in_days * 86400;
  }
  return { name, scopes, packages, expires };
}

export async function createToken(env: Env, req: Request, c: Caller): Promise<Response> {
  requireScope(c, "tokens");
  const p = tokenParams(await readJson<TokenRequest>(req));
  // A token can only mint tokens within its own package restriction.
  if (c.packages && (!p.packages || p.packages.some((x) => !c.packages!.includes(x)))) {
    throw new HttpError(403, "package_not_allowed", "a package-restricted token can only create tokens for the same packages");
  }
  const { created, stmt } = await mintToken(env, c.userId, p.name, p.scopes, p.packages, p.expires);
  await stmt.run();
  return json(created, 201);
}

export async function revokeToken(env: Env, c: Caller, id: string): Promise<Response> {
  if (id !== c.tokenId) requireScope(c, "tokens");
  const res = await env.DB.prepare("UPDATE tokens SET revoked_at = ? WHERE id = ? AND user_id = ? AND revoked_at IS NULL").bind(nowSec(), id, c.userId).run();
  if (!res.meta.changes) throw new HttpError(404, "not_found", `no active token ${id}`);
  return json({ id, revoked: true });
}

// ---- attestations (BHC verification) ----------------------------------------

interface AttestationBody {
  attestation: Record<string, Json>;
  verifier: string;
  signature: string;
}

const ATT_FIELDS = ["package", "version", "sha256", "bhc_version", "profile", "result", "log_url", "built_at"] as const;

export async function submitAttestation(env: Env, req: Request, name: string, version: string): Promise<Response> {
  assertName(name);
  assertVersion(version);
  const body = JSON.parse(new TextDecoder().decode(await readBodyLimited(req, 16 * 1024))) as AttestationBody;
  if (!body || typeof body.verifier !== "string" || typeof body.signature !== "string" || typeof body.attestation !== "object") {
    throw new HttpError(400, "bad_attestation", "body must be {attestation, verifier, signature}");
  }
  const { success } = await env.ATTEST_LIMITER.limit({ key: `attest:${body.verifier}` });
  if (!success) throw new HttpError(429, "rate_limited", "too many attestations", undefined, { "Retry-After": "60" });
  const a = body.attestation;
  for (const f of ATT_FIELDS) {
    if (f === "log_url" && (a[f] === undefined || a[f] === null)) continue;
    if (typeof a[f] !== "string" || (a[f] as string).length > 512) throw new HttpError(400, "bad_attestation", `attestation.${f} must be a string`);
  }
  if (a.package !== name || a.version !== version) throw new HttpError(400, "bad_attestation", "attestation is for a different package/version");
  if (a.result !== "pass" && a.result !== "fail") throw new HttpError(400, "bad_attestation", 'attestation.result must be "pass" or "fail"');
  if (a.log_url && !/^https:\/\//.test(String(a.log_url))) throw new HttpError(400, "bad_attestation", "attestation.log_url must be https");
  const ver = await env.DB.prepare("SELECT public_key FROM verifiers WHERE name = ? AND revoked_at IS NULL").bind(body.verifier).first<{ public_key: string }>();
  if (!ver) throw new HttpError(403, "unknown_verifier", `verifier ${body.verifier} is not registered`);
  const statement = canonical(a);
  if (!(await verifyEd25519(ver.public_key, enc.encode(statement), body.signature))) {
    throw new HttpError(403, "bad_signature", "attestation signature does not verify");
  }
  const v = await env.DB.prepare("SELECT sha256 FROM versions WHERE package = ? AND version = ?").bind(name, version).first<{ sha256: string }>();
  if (!v) throw new HttpError(404, "not_found", `${name}-${version} not found`);
  if (v.sha256 !== a.sha256) throw new HttpError(409, "sha_mismatch", "attestation sha256 does not match the published tarball");
  await env.DB.prepare(
    `INSERT INTO attestations (package, version, verifier, bhc_version, profile, result, log_url, built_at, statement, signature, received_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT (package, version, verifier, bhc_version, profile) DO UPDATE SET result = excluded.result,
       log_url = excluded.log_url, built_at = excluded.built_at, statement = excluded.statement,
       signature = excluded.signature, received_at = excluded.received_at`,
  )
    .bind(name, version, body.verifier, a.bhc_version, a.profile, a.result, a.log_url ?? null, a.built_at, statement, body.signature, nowSec())
    .run();
  return json({ name, version, verifier: body.verifier, result: a.result, recorded: true }, 201);
}

export async function unverified(env: Env, url: URL): Promise<Response> {
  const limit = Math.min(Number(url.searchParams.get("limit") ?? 50) || 50, 200);
  const rows = (
    await env.DB.prepare(
      `SELECT v.package AS name, v.version, v.sha256 FROM versions v
       WHERE v.yanked = 0 AND NOT EXISTS (SELECT 1 FROM attestations a WHERE a.package = v.package AND a.version = v.version)
       ORDER BY v.published_at LIMIT ?`,
    )
      .bind(limit)
      .all()
  ).results;
  return json({
    versions: rows.map((r) => ({ ...r, tarball_url: `${env.PUBLIC_URL}/package/${String(r.name)}-${String(r.version)}.tar.gz` })),
  });
}

// ---- admin ----------------------------------------------------------------

export async function admin(env: Env, req: Request, rest: string[]): Promise<Response> {
  await requireAdmin(env, req);
  const [what, arg] = rest;
  const now = nowSec();
  if (what === "users" && req.method === "POST" && !arg) {
    const body = await readJson<{ login?: string; email?: string; admin?: boolean }>(req);
    const login = (body.login ?? "").trim();
    if (!/^[A-Za-z0-9][A-Za-z0-9-]{0,38}$/.test(login)) throw new HttpError(400, "bad_login", "login must be 1-39 letters, digits or '-'");
    const res = await env.DB.prepare("INSERT INTO users (login, email, is_admin, created_at) VALUES (?, ?, ?, ?) ON CONFLICT (login) DO NOTHING RETURNING id")
      .bind(login, body.email ?? null, body.admin ? 1 : 0, now)
      .first<{ id: number }>();
    if (!res) throw new HttpError(409, "user_exists", `user ${login} already exists`);
    const { created, stmt } = await mintToken(env, res.id, "initial", ["publish", "yank", "owners", "tokens"], null, null);
    await stmt.run();
    return json({ login, id: res.id, token: created }, 201);
  }
  if (what === "verifiers" && req.method === "POST" && !arg) {
    const body = await readJson<{ name?: string; public_key?: string }>(req);
    if (!body.name || !/^[A-Za-z0-9._-]{1,64}$/.test(body.name)) throw new HttpError(400, "bad_name", "verifier name must be 1-64 of [A-Za-z0-9._-]");
    let raw: Uint8Array;
    try {
      raw = b64decode(body.public_key ?? "");
    } catch {
      raw = new Uint8Array(0);
    }
    if (raw.length !== 32) throw new HttpError(400, "bad_key", "public_key must be a base64 raw 32-byte Ed25519 public key");
    await env.DB.prepare(
      "INSERT INTO verifiers (name, public_key, created_at) VALUES (?, ?, ?) ON CONFLICT (name) DO UPDATE SET public_key = excluded.public_key, revoked_at = NULL",
    )
      .bind(body.name, body.public_key, now)
      .run();
    return json({ name: body.name, registered: true }, 201);
  }
  if (what === "verifiers" && req.method === "DELETE" && arg) {
    await env.DB.prepare("UPDATE verifiers SET revoked_at = ? WHERE name = ?").bind(now, arg).run();
    return json({ name: arg, revoked: true });
  }
  if (what === "reservations" && req.method === "PUT" && arg) {
    assertName(arg);
    const body = await readJson<{ login?: string }>(req);
    const user = await env.DB.prepare("SELECT id FROM users WHERE login = ?").bind(body.login ?? "").first<{ id: number }>();
    if (!user) throw new HttpError(404, "no_such_user", `no user named ${body.login}`);
    await env.DB.prepare(
      `INSERT INTO name_reservations (name_lower, on_hackage, checked_at, granted_to) VALUES (?, 1, ?, ?)
       ON CONFLICT (name_lower) DO UPDATE SET granted_to = excluded.granted_to`,
    )
      .bind(arg.toLowerCase(), now, user.id)
      .run();
    return json({ name: arg, granted_to: body.login });
  }
  if (what === "tuf" && req.method === "PUT" && (arg === "root.json" || arg === "mirrors.json")) {
    const text = new TextDecoder().decode(await readBodyLimited(req, 64 * 1024));
    const key = await onlineKey(env);
    try {
      if (arg === "root.json") {
        await checkRoot(text, key?.keyid);
      } else {
        const root = await env.BLOBS.get(ROOT_KEY);
        if (!root) throw new TufError("upload root.json first");
        await checkMirrors(text, await checkRoot(await root.text()));
      }
    } catch (e) {
      if (e instanceof TufError || e instanceof SyntaxError) throw new HttpError(400, "bad_tuf", e.message);
      throw e;
    }
    await env.BLOBS.put(arg === "root.json" ? ROOT_KEY : MIRRORS_KEY, text, { httpMetadata: { contentType: "application/json" } });
    const refreshed = await refreshTuf(env);
    return json({ file: arg, stored: true, tuf_active: refreshed });
  }
  if (what === "seal" && req.method === "POST") {
    return json(await sealIndex(env, true));
  }
  throw new HttpError(404, "not_found", "unknown admin endpoint");
}

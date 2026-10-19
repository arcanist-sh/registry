// API tokens and the admin secret.

import { sha256Hex } from "./sha256";
import { HttpError, b64url, nowSec } from "./util";

export const SCOPES = ["publish", "yank", "owners", "tokens"] as const;
export type Scope = (typeof SCOPES)[number];

export interface Caller {
  kind: "user";
  userId: number;
  login: string;
  isAdmin: boolean;
  tokenId: string;
  scopes: Set<Scope>;
  packages: string[] | null; // null = any package
}

export const TOKEN_PREFIX = "hxr_";

export function newTokenSecret(): string {
  return TOKEN_PREFIX + b64url(crypto.getRandomValues(new Uint8Array(32)));
}

export function newTokenId(): string {
  return "tok_" + b64url(crypto.getRandomValues(new Uint8Array(9)));
}

function bearer(req: Request): string | null {
  const h = req.headers.get("Authorization");
  if (!h) return null;
  const m = /^Bearer\s+(\S+)$/i.exec(h);
  if (!m) throw new HttpError(401, "bad_auth", "Authorization header must be `Bearer <token>`");
  return m[1];
}

async function throttle(env: Env, req: Request) {
  const ip = req.headers.get("CF-Connecting-IP") ?? "local";
  const { success } = await env.AUTH_LIMITER.limit({ key: `auth:${ip}` });
  if (!success) throw new HttpError(429, "rate_limited", "too many authenticated requests; slow down", undefined, { "Retry-After": "60" });
}

/** Constant-time comparison via fixed-length digests. */
async function secretEquals(a: string, b: string): Promise<boolean> {
  const enc = new TextEncoder();
  const [da, db] = await Promise.all([
    crypto.subtle.digest("SHA-256", enc.encode(a)),
    crypto.subtle.digest("SHA-256", enc.encode(b)),
  ]);
  return crypto.subtle.timingSafeEqual(da, db);
}

export async function requireAdmin(env: Env, req: Request): Promise<void> {
  const tok = bearer(req);
  if (!tok) throw new HttpError(401, "unauthenticated", "admin token required");
  await throttle(env, req);
  if (!env.ADMIN_TOKEN || !(await secretEquals(tok, env.ADMIN_TOKEN))) {
    throw new HttpError(403, "forbidden", "invalid admin token");
  }
}

export async function authenticate(env: Env, req: Request, ctx: ExecutionContext): Promise<Caller> {
  const tok = bearer(req);
  if (!tok) {
    throw new HttpError(401, "unauthenticated", "this endpoint needs an API token", "run `hx registry login` and retry");
  }
  await throttle(env, req);
  const row = await env.DB.prepare(
    `SELECT t.id, t.scopes, t.packages, t.expires_at, t.revoked_at, u.id AS user_id, u.login, u.is_admin
     FROM tokens t JOIN users u ON u.id = t.user_id WHERE t.token_hash = ?`,
  )
    .bind(await sha256Hex(tok))
    .first<{
      id: string;
      scopes: string;
      packages: string | null;
      expires_at: number | null;
      revoked_at: number | null;
      user_id: number;
      login: string;
      is_admin: number;
    }>();
  const now = nowSec();
  if (!row || row.revoked_at !== null || (row.expires_at !== null && row.expires_at <= now)) {
    throw new HttpError(401, "invalid_token", "API token is invalid, expired or revoked", "create a new token and run `hx registry login`");
  }
  ctx.waitUntil(env.DB.prepare("UPDATE tokens SET last_used_at = ? WHERE id = ?").bind(now, row.id).run());
  return {
    kind: "user",
    userId: row.user_id,
    login: row.login,
    isAdmin: row.is_admin === 1,
    tokenId: row.id,
    scopes: new Set(row.scopes.split(" ").filter(Boolean) as Scope[]),
    packages: row.packages ? (JSON.parse(row.packages) as string[]) : null,
  };
}

export function requireScope(c: Caller, scope: Scope, pkg?: string): void {
  if (!c.scopes.has(scope)) {
    throw new HttpError(403, "missing_scope", `this token lacks the "${scope}" scope`, `create a token with --scope ${scope}`);
  }
  if (pkg && c.packages && !c.packages.includes(pkg)) {
    throw new HttpError(403, "package_not_allowed", `this token is not allowed to act on package ${pkg}`);
  }
}

export interface CreatedToken {
  id: string;
  token: string;
  name: string;
  scopes: Scope[];
  packages: string[] | null;
  expires_at: number | null;
}

export function parseScopes(input: unknown): Scope[] {
  const list = input === undefined ? ["publish", "yank", "owners"] : input;
  if (!Array.isArray(list) || list.length === 0) throw new HttpError(400, "bad_scopes", "scopes must be a non-empty array");
  for (const s of list) {
    if (!SCOPES.includes(s as Scope)) throw new HttpError(400, "bad_scopes", `unknown scope "${String(s)}"`, `valid scopes: ${SCOPES.join(", ")}`);
  }
  return [...new Set(list as Scope[])];
}

function tokenInsert(
  env: Env,
  userId: number,
  name: string,
  scopes: Scope[],
  packages: string[] | null,
  expiresAt: number | null,
  hash: string,
  id: string,
): D1PreparedStatement {
  return env.DB.prepare(
    "INSERT INTO tokens (id, user_id, name, token_hash, scopes, packages, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
  ).bind(id, userId, name, hash, scopes.join(" "), packages ? JSON.stringify(packages) : null, nowSec(), expiresAt);
}

export async function mintToken(
  env: Env,
  userId: number,
  name: string,
  scopes: Scope[],
  packages: string[] | null,
  expiresAt: number | null,
): Promise<{ created: CreatedToken; stmt: D1PreparedStatement }> {
  const token = newTokenSecret();
  const id = newTokenId();
  const stmt = tokenInsert(env, userId, name, scopes, packages, expiresAt, await sha256Hex(token), id);
  return { created: { id, token, name, scopes, packages, expires_at: expiresAt }, stmt };
}

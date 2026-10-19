import { exports } from "cloudflare:workers";
import { gzip } from "../src/gzip";
import { concat, tarEntry, TAR_TRAILER } from "../src/tar";

export const ADMIN = "test-admin-token";
const enc = new TextEncoder();

export async function call(
  method: string,
  path: string,
  opts: { token?: string; body?: BodyInit | object; headers?: Record<string, string> } = {},
): Promise<Response> {
  const headers: Record<string, string> = { ...(opts.headers ?? {}) };
  if (opts.token) headers.Authorization = `Bearer ${opts.token}`;
  // Distinct client IP per call so the auth rate limiter does not trip across tests.
  headers["CF-Connecting-IP"] ??= `10.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
  let body: BodyInit | undefined;
  if (opts.body instanceof Uint8Array || typeof opts.body === "string" || opts.body instanceof ArrayBuffer) {
    body = opts.body as BodyInit;
  } else if (opts.body !== undefined) {
    body = JSON.stringify(opts.body);
    headers["Content-Type"] = "application/json";
  }
  return exports.default.fetch(new Request(`https://registry.test${path}`, { method, headers, body }));
}

export async function jsonOf<T = any>(res: Response): Promise<T> {
  return (await res.json()) as T;
}

let userSeq = 0;
/** Create a user through the admin API and return its first (all-scope) token. */
export async function newUser(login = `user${++userSeq}-${crypto.randomUUID().slice(0, 6)}`): Promise<{ login: string; token: string }> {
  const res = await call("POST", "/api/v1/admin/users", { token: ADMIN, body: { login } });
  if (res.status !== 201) throw new Error(`newUser failed: ${res.status} ${await res.text()}`);
  const j = await jsonOf(res);
  return { login, token: j.token.token };
}

export function cabalText(name: string, version: string, extra = ""): string {
  return `cabal-version: 3.0
name:          ${name}
version:       ${version}
synopsis:      Test package ${name}
license:       MIT
build-type:    Simple

library
  exposed-modules: Lib
  build-depends:   base >=4 && <5,
                   containers ^>=0.6
  hs-source-dirs:  src
  default-language: Haskell2010
${extra}`;
}

/** Raw tar entries for an sdist-like tarball (no trailer). */
export function sdistEntries(name: string, version: string, cabal = cabalText(name, version)): Uint8Array[] {
  const top = `${name}-${version}`;
  return [
    tarEntry(`${top}/${name}.cabal`, enc.encode(cabal), 1700000000),
    tarEntry(`${top}/src/Lib.hs`, enc.encode("module Lib where\n"), 1700000000),
  ];
}

export async function tarGz(entries: Uint8Array[]): Promise<Uint8Array> {
  return gzip(concat([...entries, TAR_TRAILER]));
}

export async function sdist(name: string, version: string, cabal?: string): Promise<Uint8Array> {
  return tarGz(sdistEntries(name, version, cabal));
}

export async function publish(token: string, body: Uint8Array): Promise<Response> {
  return call("PUT", "/api/v1/packages/upload", { token, body, headers: { "Content-Type": "application/gzip" } });
}

/** Tar header with an arbitrary type flag (for symlink/hardlink tests). */
export function rawHeader(path: string, type: string, linkname = ""): Uint8Array {
  const e = tarEntry(path, new Uint8Array(0), 1700000000);
  e[156] = type.charCodeAt(0);
  e.set(enc.encode(linkname), 157);
  // recompute checksum
  e.fill(0x20, 148, 156);
  let sum = 0;
  for (let i = 0; i < 512; i++) sum += e[i];
  e.set(enc.encode(sum.toString(8).padStart(6, "0")), 148);
  e[154] = 0;
  e[155] = 0x20;
  return e;
}

export async function bytes(res: Response): Promise<Uint8Array> {
  return new Uint8Array(await res.arrayBuffer());
}

export const uniq = (p: string) => `${p}-${crypto.randomUUID().replace(/[^a-f]/g, "").slice(0, 8) || "x"}`;

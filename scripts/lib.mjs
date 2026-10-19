// Shared helpers for the offline scripts (Node 20+, no dependencies).
import { webcrypto as crypto } from "node:crypto";

/** hackage-security canonical JSON (see src/canonical.ts). */
export function canonical(v) {
  if (v === null) return "null";
  if (v === true) return "true";
  if (v === false) return "false";
  if (typeof v === "number") {
    if (!Number.isSafeInteger(v)) throw new Error(`non-integer ${v}`);
    return String(v);
  }
  if (typeof v === "string") {
    if (/[^\x20-\x7e]/.test(v)) throw new Error(`non-ASCII string ${JSON.stringify(v)}`);
    return `"${v.replace(/[\\"]/g, (c) => "\\" + c)}"`;
  }
  if (Array.isArray(v)) return `[${v.map(canonical).join(",")}]`;
  return `{${Object.keys(v).sort().map((k) => `${canonical(k)}:${canonical(v[k])}`).join(",")}}`;
}

export const b64 = (bytes) => Buffer.from(bytes).toString("base64");
export const fromB64url = (s) => Buffer.from(s, "base64url");

export async function sha256Hex(s) {
  return Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s))).toString("hex");
}

export async function keyIdFor(publicB64) {
  return sha256Hex(canonical({ keytype: "ed25519", keyval: { public: publicB64 } }));
}

/** Load a private Ed25519 JWK and return {keyid, publicB64, key}. */
export async function loadJwk(jwk) {
  const key = await crypto.subtle.importKey("jwk", jwk, { name: "Ed25519" }, false, ["sign"]);
  const publicB64 = b64(fromB64url(jwk.x));
  return { keyid: await keyIdFor(publicB64), publicB64, key };
}

export async function generate() {
  const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const jwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
  return { jwk, ...(await loadJwk(jwk)) };
}

export async function signWith(keys, signed) {
  const msg = new TextEncoder().encode(canonical(signed));
  const signatures = [];
  for (const k of keys) {
    const sig = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, k.key, msg));
    signatures.push({ keyid: k.keyid, method: "ed25519", sig: b64(sig) });
  }
  return canonical({ signatures, signed });
}

export const tufTime = (d) => new Date(Math.floor(d.getTime() / 1000) * 1000).toISOString().replace(".000Z", "Z");

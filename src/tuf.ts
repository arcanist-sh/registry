// hackage-security (TUF) metadata: key ids, signing, verification, and the
// online-signed snapshot.json / timestamp.json.

import { canonical, type Json } from "./canonical";
import { sha256Hex } from "./sha256";
import { b64decode, b64encode, b64urlToB64 } from "./util";

export interface SigningKey {
  keyid: string;
  key: CryptoKey;
}

export interface Signature {
  keyid: string;
  method: string;
  sig: string;
}

export interface SignedDoc {
  signed: { [k: string]: Json };
  signatures: Signature[];
}

/** hackage-security key id: hex sha256 of the canonical public key object. */
export async function keyIdFor(publicKeyB64: string): Promise<string> {
  return sha256Hex(canonical({ keytype: "ed25519", keyval: { public: publicKeyB64 } }));
}

/** Import the online key from its JWK text (Worker secret TUF_ONLINE_KEY). */
export async function importOnlineKey(jwkText: string): Promise<SigningKey> {
  const jwk = JSON.parse(jwkText) as JsonWebKey;
  if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || !jwk.d || !jwk.x) {
    throw new Error("TUF_ONLINE_KEY must be an Ed25519 private JWK (kty OKP, crv Ed25519, with d and x)");
  }
  // Node exports alg "Ed25519", workerd expects "EdDSA"; only the key material matters.
  const material: JsonWebKey = { kty: "OKP", crv: "Ed25519", d: jwk.d, x: jwk.x };
  const key = await crypto.subtle.importKey("jwk", material, { name: "Ed25519" }, false, ["sign"]);
  return { keyid: await keyIdFor(b64urlToB64(jwk.x)), key };
}

/** Sign `signed` and render the envelope (canonical JSON is valid JSON). */
export async function signDoc(signed: { [k: string]: Json }, keys: SigningKey[]): Promise<string> {
  const msg = new TextEncoder().encode(canonical(signed));
  const signatures: Json[] = [];
  for (const k of keys) {
    const sig = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, k.key, msg));
    signatures.push({ keyid: k.keyid, method: "ed25519", sig: b64encode(sig) });
  }
  return canonical({ signatures, signed });
}

export async function verifyEd25519(publicKeyB64: string, message: Uint8Array, sigB64: string): Promise<boolean> {
  try {
    const key = await crypto.subtle.importKey("raw", b64decode(publicKeyB64), { name: "Ed25519" }, false, ["verify"]);
    return await crypto.subtle.verify({ name: "Ed25519" }, key, b64decode(sigB64), message);
  } catch {
    return false;
  }
}

interface RoleSpec {
  keyids: string[];
  threshold: number;
}

export interface RootInfo {
  version: number;
  expires: string;
  keys: Record<string, string>; // keyid -> base64 public key
  roles: Record<string, RoleSpec>;
}

export class TufError extends Error {}

function asObject(v: unknown, what: string): Record<string, unknown> {
  if (!v || typeof v !== "object" || Array.isArray(v)) throw new TufError(`${what} must be an object`);
  return v as Record<string, unknown>;
}

/** Count distinct valid signatures from `role` keys over the canonical `signed` part. */
async function validSignatures(doc: SignedDoc, keys: Record<string, string>, role: RoleSpec): Promise<number> {
  const msg = new TextEncoder().encode(canonical(doc.signed));
  const seen = new Set<string>();
  for (const s of doc.signatures ?? []) {
    if (s.method !== "ed25519" || seen.has(s.keyid) || !role.keyids.includes(s.keyid)) continue;
    const pub = keys[s.keyid];
    if (pub && (await verifyEd25519(pub, msg, s.sig))) seen.add(s.keyid);
  }
  return seen.size;
}

/**
 * Parse and check a root.json: self-signed by the root threshold, and the
 * online key must be the (only) snapshot and timestamp key.
 */
export async function checkRoot(text: string, onlineKeyId?: string): Promise<RootInfo> {
  const doc = JSON.parse(text) as SignedDoc;
  const signed = asObject(doc.signed, "root.json signed");
  if (signed._type !== "Root") throw new TufError("root.json _type must be Root");
  const keysObj = asObject(signed.keys, "root.json keys");
  const keys: Record<string, string> = {};
  for (const [id, k] of Object.entries(keysObj)) {
    const ko = asObject(k, `key ${id}`);
    const pub = asObject(ko.keyval, `key ${id} keyval`).public;
    if (ko.keytype !== "ed25519" || typeof pub !== "string") throw new TufError(`key ${id} must be ed25519`);
    if ((await keyIdFor(pub)) !== id) throw new TufError(`key id ${id} does not match its public key`);
    keys[id] = pub;
  }
  const rolesObj = asObject(signed.roles, "root.json roles");
  const roles: Record<string, RoleSpec> = {};
  for (const r of ["root", "snapshot", "targets", "timestamp", "mirrors"]) {
    const spec = asObject(rolesObj[r], `role ${r}`) as unknown as RoleSpec;
    if (!Array.isArray(spec.keyids) || typeof spec.threshold !== "number") throw new TufError(`role ${r} is malformed`);
    roles[r] = spec;
  }
  const n = await validSignatures(doc, keys, roles.root);
  if (n < roles.root.threshold) throw new TufError(`root.json has ${n} valid root signatures, needs ${roles.root.threshold}`);
  if (onlineKeyId) {
    for (const r of ["snapshot", "timestamp"]) {
      if (!roles[r].keyids.includes(onlineKeyId)) {
        throw new TufError(`root.json ${r} role does not list the Worker's online key ${onlineKeyId}`);
      }
    }
  }
  return { version: Number(signed.version), expires: String(signed.expires), keys, roles };
}

export async function checkMirrors(text: string, root: RootInfo): Promise<void> {
  const doc = JSON.parse(text) as SignedDoc;
  const signed = asObject(doc.signed, "mirrors.json signed");
  if (signed._type !== "Mirrorlist") throw new TufError("mirrors.json _type must be Mirrorlist");
  const n = await validSignatures(doc, root.keys, root.roles.mirrors);
  if (n < root.roles.mirrors.threshold) throw new TufError("mirrors.json is not signed by the mirrors role");
}

export function tufTime(ms: number): string {
  return new Date(Math.floor(ms / 1000) * 1000).toISOString().replace(".000Z", "Z");
}

export function fileInfo(sha256: string, length: number): Json {
  return { hashes: { sha256 }, length };
}

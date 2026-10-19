import { env } from "cloudflare:workers";
import { beforeAll, describe, expect, it } from "vitest";
import { canonical, type Json } from "../src/canonical";
import { gunzipLimited } from "../src/gzip";
import { readState } from "../src/index-store";
import { sha256Hex } from "../src/sha256";
import { readTar } from "../src/tar";
import { keyIdFor, verifyEd25519 } from "../src/tuf";
import { b64encode, b64urlToB64 } from "../src/util";
import { ADMIN, bytes, call, jsonOf, newUser, publish, sdist, uniq } from "./helpers";

const enc = new TextEncoder();

interface Key {
  keyid: string;
  pub: string;
  priv: CryptoKey;
}

async function newKey(): Promise<Key> {
  const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const pub = b64encode(new Uint8Array((await crypto.subtle.exportKey("raw", pair.publicKey)) as ArrayBuffer));
  return { keyid: await keyIdFor(pub), pub, priv: pair.privateKey };
}

async function sign(keys: Key[], signed: { [k: string]: Json }): Promise<string> {
  const msg = enc.encode(canonical(signed));
  const signatures: Json[] = [];
  for (const k of keys) {
    signatures.push({ keyid: k.keyid, method: "ed25519", sig: b64encode(new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, k.priv, msg))) });
  }
  return canonical({ signatures, signed });
}

const online = JSON.parse(env.TUF_ONLINE_KEY!) as { x: string };
const onlinePub = b64urlToB64(online.x);

async function rootDoc(rootKeys: Key[], signers: Key[], mirrors: Key, onlineId: string, threshold = 2): Promise<string> {
  const keys: { [k: string]: Json } = {};
  for (const k of [...rootKeys, mirrors]) keys[k.keyid] = { keytype: "ed25519", keyval: { public: k.pub } };
  keys[onlineId] = { keytype: "ed25519", keyval: { public: onlinePub } };
  return sign(signers, {
    _type: "Root",
    expires: "2030-01-01T00:00:00Z",
    keys,
    roles: {
      root: { keyids: rootKeys.map((k) => k.keyid), threshold },
      mirrors: { keyids: [mirrors.keyid], threshold: 1 },
      targets: { keyids: [], threshold: 1 },
      snapshot: { keyids: [onlineId], threshold: 1 },
      timestamp: { keyids: [onlineId], threshold: 1 },
    },
    version: 1,
  });
}

/** Decode the multi-member index.tar.gz chunk by chunk (workerd stops after one member). */
async function gunzipIndexFromRows(): Promise<Uint8Array> {
  const rows = (await env.DB.prepare("SELECT gz_bytes FROM index_chunks ORDER BY seq").all<{ gz_bytes: ArrayBuffer }>()).results;
  const parts = await Promise.all(rows.map((r) => gunzipLimited(new Uint8Array(r.gz_bytes), 1 << 24)));
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

describe("legacy repository (no TUF metadata uploaded)", () => {
  it("serves 404 for TUF files with a hint, but serves the index", async () => {
    const res = await call("GET", "/timestamp.json");
    expect(res.status).toBe(404);
    expect((await jsonOf(res)).error.hint).toContain("secure: False");
    const idx = await call("GET", "/00-index.tar.gz");
    expect(idx.status).toBe(200);
    expect(idx.headers.get("Accept-Ranges")).toBe("bytes");
  });
});

describe("a fresh index", () => {
  it("starts with a README entry, so cabal can read it before any publish", async () => {
    const tar = await bytes(await call("GET", "/01-index.tar"));
    const files = readTar(tar, { maxEntries: 100 });
    expect(files.length).toBeGreaterThan(0);
    expect(files[0].path).toBe("README");
    // More than the bare 1024-byte trailer cabal rejects as "short tar trailer".
    expect(tar.length).toBeGreaterThan(1024);
  });
});

describe("hackage-security repository", () => {
  let rootKeys: Key[];
  let mirrorsKey: Key;
  let onlineId: string;
  let user: { token: string };
  const names: string[] = [];

  beforeAll(async () => {
    rootKeys = [await newKey(), await newKey(), await newKey()];
    mirrorsKey = await newKey();
    onlineId = await keyIdFor(onlinePub);
    user = await newUser();
    for (let i = 0; i < 3; i++) {
      const n = uniq("idx");
      names.push(n);
      expect((await publish(user.token, await sdist(n, "1.0"))).status).toBe(201);
    }
  });

  it("rejects a root.json without enough root signatures or without the online key", async () => {
    const under = await rootDoc(rootKeys, [rootKeys[0]], mirrorsKey, onlineId);
    let res = await call("PUT", "/api/v1/admin/tuf/root.json", { token: ADMIN, body: under });
    expect(res.status).toBe(400);
    expect((await jsonOf(res)).error.message).toContain("needs 2");
    const otherOnline = (await newKey()).keyid;
    res = await call("PUT", "/api/v1/admin/tuf/root.json", { token: ADMIN, body: await rootDoc(rootKeys, rootKeys.slice(0, 2), mirrorsKey, otherOnline) });
    expect(res.status).toBe(400);
  });

  it("signs snapshot and timestamp whose hashes match the served files", async () => {
    const root = await rootDoc(rootKeys, rootKeys.slice(0, 2), mirrorsKey, onlineId);
    expect((await call("PUT", "/api/v1/admin/tuf/root.json", { token: ADMIN, body: root })).status).toBe(200);
    const mirrors = await sign([mirrorsKey], { _type: "Mirrorlist", expires: "2030-01-01T00:00:00Z", mirrors: [], version: 1 });
    const up = await jsonOf(await call("PUT", "/api/v1/admin/tuf/mirrors.json", { token: ADMIN, body: mirrors }));
    expect(up.tuf_active).toBe(true);

    const cfg = await jsonOf(await call("GET", "/api/v1/config"));
    expect(cfg.tuf).toEqual({ enabled: true, root_keys: rootKeys.map((k) => k.keyid), key_threshold: 2 });

    const tsText = await (await call("GET", "/timestamp.json")).text();
    const ts = JSON.parse(tsText);
    expect(ts.signed._type).toBe("Timestamp");
    expect(ts.signatures[0].keyid).toBe(onlineId);
    expect(await verifyEd25519(onlinePub, enc.encode(canonical(ts.signed)), ts.signatures[0].sig)).toBe(true);
    expect(tsText).toBe(canonical(ts)); // served bytes are canonical

    const snapBytes = await bytes(await call("GET", "/snapshot.json"));
    expect(ts.signed.meta["<repo>/snapshot.json"]).toEqual({ hashes: { sha256: await sha256Hex(snapBytes) }, length: snapBytes.length });
    const snap = JSON.parse(new TextDecoder().decode(snapBytes));
    expect(await verifyEd25519(onlinePub, enc.encode(canonical(snap.signed)), snap.signatures[0].sig)).toBe(true);

    for (const [file, path] of [
      ["<repo>/01-index.tar", "/01-index.tar"],
      ["<repo>/01-index.tar.gz", "/01-index.tar.gz"],
      ["<repo>/root.json", "/root.json"],
      ["<repo>/mirrors.json", "/mirrors.json"],
    ]) {
      const b = await bytes(await call("GET", path));
      expect(snap.signed.meta[file], file).toEqual({ hashes: { sha256: await sha256Hex(b) }, length: b.length });
    }
  });

  it("contains Hackage-layout entries whose package.json matches the tarball", async () => {
    const tar = await bytes(await call("GET", "/01-index.tar"));
    expect(tar.subarray(tar.length - 1024).every((b) => b === 0)).toBe(true);
    const files = readTar(tar, { maxEntries: 10_000 });
    const n = names[0];
    const pj = files.find((f) => f.path === `${n}/1.0/package.json`)!;
    const meta = JSON.parse(new TextDecoder().decode(pj.data));
    expect(meta.signatures).toEqual([]);
    const tb = await bytes(await call("GET", `/package/${n}-1.0.tar.gz`));
    expect(meta.signed.targets[`<repo>/package/${n}-1.0.tar.gz`]).toEqual({ hashes: { sha256: await sha256Hex(tb) }, length: tb.length });
    expect(files.some((f) => f.path === `${n}/1.0/${n}.cabal`)).toBe(true);
    // the gzip view decodes to the same bytes
    expect(await gunzipIndexFromRows()).toEqual(tar.subarray(0, tar.length - 1024));
  });

  it("answers byte ranges like an append-only file", async () => {
    const full = await bytes(await call("GET", "/01-index.tar"));
    const r = await call("GET", "/01-index.tar", { headers: { Range: "bytes=600-2047" } });
    expect(r.status).toBe(206);
    expect(r.headers.get("Content-Range")).toBe(`bytes 600-2047/${full.length}`);
    expect(await bytes(r)).toEqual(full.subarray(600, 2048));
    const tail = await call("GET", "/01-index.tar", { headers: { Range: "bytes=-1024" } });
    expect(await bytes(tail)).toEqual(full.subarray(full.length - 1024));
    expect((await call("GET", "/01-index.tar", { headers: { Range: `bytes=${full.length}-` } })).status).toBe(416);
  });

  it("only extends the index on publish (old bytes are a prefix of new)", async () => {
    const before = await bytes(await call("GET", "/01-index.tar"));
    const tsBefore = JSON.parse(await (await call("GET", "/timestamp.json")).text());
    const n = uniq("grow");
    await publish(user.token, await sdist(n, "2.0"));
    const after = await bytes(await call("GET", "/01-index.tar"));
    expect(after.length).toBeGreaterThan(before.length);
    expect(after.subarray(0, before.length - 1024)).toEqual(before.subarray(0, before.length - 1024));
    const tsAfter = JSON.parse(await (await call("GET", "/timestamp.json")).text());
    expect(tsAfter.signed.version).toBe(tsBefore.signed.version + 1);
  });

  it("seals the D1 tail into R2 segments without changing a byte", async () => {
    const tarBefore = await bytes(await call("GET", "/01-index.tar"));
    const gzBefore = await bytes(await call("GET", "/01-index.tar.gz"));
    const sealed = await jsonOf(await call("POST", "/api/v1/admin/seal", { token: ADMIN }));
    expect(sealed.sealed).toBeGreaterThan(0);
    expect((await env.DB.prepare("SELECT count(*) AS n FROM index_chunks").first<{ n: number }>())!.n).toBe(0);
    expect(await bytes(await call("GET", "/01-index.tar"))).toEqual(tarBefore);
    expect(await bytes(await call("GET", "/01-index.tar.gz"))).toEqual(gzBefore);

    // a publish after sealing appends to the tail; a range spanning segment and tail still works
    const n = uniq("post");
    await publish(user.token, await sdist(n, "1.0"));
    const full = await bytes(await call("GET", "/01-index.tar"));
    const from = tarBefore.length - 1024 - 100;
    const r = await call("GET", "/01-index.tar", { headers: { Range: `bytes=${from}-${from + 799}` } });
    expect(await bytes(r)).toEqual(full.subarray(from, from + 800));
    const snap = JSON.parse(await (await call("GET", "/snapshot.json")).text());
    expect(snap.signed.meta["<repo>/01-index.tar"].hashes.sha256).toBe(await sha256Hex(full));
    const st = await readState(env.DB);
    expect(st.tarLength + 1024).toBe(full.length);
  });

  it("serves the scheduled handler without errors", async () => {
    const { createScheduledController, createExecutionContext, waitOnExecutionContext } = await import("cloudflare:test");
    const worker = (await import("../src/index")).default;
    const ctx = createExecutionContext();
    await worker.scheduled(createScheduledController(), env, ctx);
    await waitOnExecutionContext(ctx);
  });
});

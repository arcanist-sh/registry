import { env } from "cloudflare:workers";
import { afterEach, describe, expect, it, vi } from "vitest";
import { canonical } from "../src/canonical";
import { checkNewName } from "../src/policy";
import { sha256Hex } from "../src/sha256";
import { tarEntry } from "../src/tar";
import { b64encode, HttpError } from "../src/util";
import { ADMIN, bytes, cabalText, call, jsonOf, newUser, publish, rawHeader, sdist, sdistEntries, tarGz, uniq } from "./helpers";

const enc = new TextEncoder();

describe("auth", () => {
  it("rejects missing, malformed and unknown tokens", async () => {
    expect((await call("GET", "/api/v1/me")).status).toBe(401);
    expect((await call("GET", "/api/v1/me", { headers: { Authorization: "Basic xyz" } })).status).toBe(401);
    const res = await call("GET", "/api/v1/me", { token: "hxr_nope" });
    expect(res.status).toBe(401);
    expect((await jsonOf(res)).error.code).toBe("invalid_token");
  });

  it("requires the admin secret for admin endpoints", async () => {
    const res = await call("POST", "/api/v1/admin/users", { token: "wrong", body: { login: "x" } });
    expect(res.status).toBe(403);
  });

  it("creates scoped tokens, lists them without secrets, and revokes them", async () => {
    const u = await newUser();
    const me = await jsonOf(await call("GET", "/api/v1/me", { token: u.token }));
    expect(me.login).toBe(u.login);
    const created = await call("POST", "/api/v1/tokens", { token: u.token, body: { name: "ci", scopes: ["publish"], packages: ["only-this"], expires_in_days: 30 } });
    expect(created.status).toBe(201);
    const t = await jsonOf(created);
    expect(t.token).toMatch(/^hxr_[A-Za-z0-9_-]{43}$/);
    const list = await jsonOf(await call("GET", "/api/v1/tokens", { token: u.token }));
    expect(list.tokens.map((x: any) => x.name)).toEqual(["initial", "ci"]);
    expect(JSON.stringify(list)).not.toContain(t.token);
    // the stored value is a hash, never the token
    const row = await env.DB.prepare("SELECT token_hash FROM tokens WHERE id = ?").bind(t.id).first<{ token_hash: string }>();
    expect(row!.token_hash).toBe(await sha256Hex(t.token));

    // restricted token cannot publish other packages or mint tokens
    const other = await publish(t.token, await sdist(uniq("other"), "1.0"));
    expect(other.status).toBe(403);
    expect((await jsonOf(other)).error.code).toBe("package_not_allowed");
    expect((await call("POST", "/api/v1/tokens", { token: t.token, body: { name: "x" } })).status).toBe(403);

    // a token may always revoke itself
    expect((await call("DELETE", `/api/v1/tokens/${t.id}`, { token: t.token })).status).toBe(200);
    expect((await call("GET", "/api/v1/me", { token: t.token })).status).toBe(401);
  });

  it("rate-limits authenticated requests per client IP", async () => {
    const statuses: number[] = [];
    for (let i = 0; i < 35; i++) {
      statuses.push((await call("GET", "/api/v1/me", { token: "hxr_guess", headers: { "CF-Connecting-IP": "192.0.2.77" } })).status);
    }
    expect(statuses.slice(0, 30).every((s) => s === 401)).toBe(true);
    expect(statuses.at(-1)).toBe(429);
  });

  it("validates token requests", async () => {
    const u = await newUser();
    const bad = await call("POST", "/api/v1/tokens", { token: u.token, body: { name: "x", scopes: ["root"] } });
    expect(bad.status).toBe(400);
    expect((await jsonOf(bad)).error.hint).toContain("publish");
  });
});

describe("publish", () => {
  it("publishes, then serves info, search, version details, cabal file and tarball", async () => {
    const u = await newUser();
    const name = uniq("hello");
    const body = await sdist(name, "1.0.0");
    const res = await publish(u.token, body);
    expect(res.status).toBe(201);
    const pub = await jsonOf(res);
    expect(pub.sha256).toBe(await sha256Hex(body));

    const info = await jsonOf(await call("GET", `/api/v1/packages/${name}`));
    expect(info.owners).toEqual([u.login]);
    expect(info.latest).toBe("1.0.0");
    expect(info.versions[0]).toMatchObject({ version: "1.0.0", yanked: false, bhc_verified: false });

    const v = await jsonOf(await call("GET", `/api/v1/packages/${name}/1.0.0`));
    expect(v.deps).toEqual([
      { name: "base", range: ">=4 && <5" },
      { name: "containers", range: "^>=0.6" },
    ]);
    expect(v.published_by).toBe(u.login);
    expect(v.tarball_url).toBe(`https://registry.test/package/${name}-1.0.0.tar.gz`);

    const search = await jsonOf(await call("GET", `/api/v1/search?q=${name.slice(0, 7)}`));
    expect(search.results.map((r: any) => r.name)).toContain(name);

    const tb = await call("GET", `/package/${name}-1.0.0.tar.gz`);
    expect(tb.status).toBe(200);
    expect(tb.headers.get("Content-Type")).toBe("application/gzip");
    expect(tb.headers.get("X-Content-Type-Options")).toBe("nosniff");
    expect(await bytes(tb)).toEqual(body);

    const cf = await call("GET", `/package/${name}-1.0.0/${name}.cabal`);
    expect(await cf.text()).toBe(cabalText(name, "1.0.0"));
  });

  it("never overwrites a version and only lets owners publish", async () => {
    const [a, b] = [await newUser(), await newUser()];
    const name = uniq("immut");
    expect((await publish(a.token, await sdist(name, "1.0"))).status).toBe(201);
    const dup = await publish(a.token, await sdist(name, "1.0", cabalText(name, "1.0", "-- changed\n")));
    expect(dup.status).toBe(409);
    expect((await jsonOf(dup)).error.code).toBe("version_exists");
    const notOwner = await publish(b.token, await sdist(name, "1.1"));
    expect(notOwner.status).toBe(403);
    expect((await jsonOf(notOwner)).error.code).toBe("not_owner");
  });

  it("enforces case-insensitive uniqueness and boot package names", async () => {
    const u = await newUser();
    const name = uniq("Casey");
    expect((await publish(u.token, await sdist(name, "1.0"))).status).toBe(201);
    const clash = await publish(u.token, await sdist(name.toLowerCase(), "1.0"));
    expect(clash.status).toBe(409);
    expect((await jsonOf(clash)).error.code).toBe("name_taken");
    const boot = await publish(u.token, await sdist("base", "9.0"));
    expect(boot.status).toBe(403);
    expect((await jsonOf(boot)).error.code).toBe("name_reserved");
  });

  it("serializes concurrent publishes into one consistent index", async () => {
    const u = await newUser();
    const names = Array.from({ length: 6 }, () => uniq("par"));
    const results = await Promise.all(names.map(async (n) => publish(u.token, await sdist(n, "0.1"))));
    expect(results.map((r) => r.status)).toEqual(names.map(() => 201));
    const rows = (await env.DB.prepare("SELECT seq, tar_offset, length(tar_bytes) AS n FROM index_chunks ORDER BY seq").all<{ seq: number; tar_offset: number; n: number }>()).results;
    for (let i = 1; i < rows.length; i++) {
      expect(rows[i].seq).toBe(rows[i - 1].seq + 1);
      expect(rows[i].tar_offset).toBe(rows[i - 1].tar_offset + rows[i - 1].n);
    }
  });
});

describe("tarball validation", () => {
  const cases: [string, () => Promise<Uint8Array>, number, string][] = [
    ["symlink", async () => tarGz([...sdistEntries("evil", "1.0"), rawHeader("evil-1.0/link", "2", "/etc/passwd")]), 400, "symlink"],
    ["hard link", async () => tarGz([...sdistEntries("evil", "1.0"), rawHeader("evil-1.0/hl", "1", "evil-1.0/evil.cabal")]), 400, "hard link"],
    ["path traversal", async () => tarGz([...sdistEntries("evil", "1.0"), tarEntry("evil-1.0/../../x", enc.encode("x"), 1)]), 400, '".."'],
    ["second top-level dir", async () => tarGz([...sdistEntries("evil", "1.0"), tarEntry("other-1.0/x", enc.encode("x"), 1)]), 400, "outside"],
    ["absolute path", async () => tarGz([tarEntry("/evil-1.0/evil.cabal", enc.encode(cabalText("evil", "1.0")), 1)]), 400, ""],
    ["missing .cabal", async () => tarGz([tarEntry("evil-1.0/README", enc.encode("x"), 1)]), 400, "does not contain"],
    ["name mismatch", async () => sdist("evil", "1.0", cabalText("good", "1.0")), 400, "declares name"],
    ["version mismatch", async () => sdist("evil", "1.0", cabalText("evil", "2.0")), 400, "declares version"],
    ["not gzip", async () => enc.encode("definitely not a tarball"), 400, "gzip"],
    ["bad top dir", async () => tarGz([tarEntry("evil/evil.cabal", enc.encode(cabalText("evil", "1.0")), 1)]), 400, "<name>-<version>"],
  ];
  for (const [label, make, status, msg] of cases) {
    it(`rejects ${label}`, async () => {
      const u = await newUser();
      const res = await publish(u.token, await make());
      expect(res.status).toBe(status);
      expect((await jsonOf(res)).error.message).toContain(msg);
      const stored = await env.DB.prepare("SELECT count(*) AS n FROM versions WHERE package = 'evil'").first<{ n: number }>();
      expect(stored!.n).toBe(0);
    });
  }

  it("rejects oversized uploads by Content-Length before reading", async () => {
    const u = await newUser();
    const res = await call("PUT", "/api/v1/packages/upload", {
      token: u.token,
      body: new Uint8Array(16),
      headers: { "Content-Length": String(17 * 1024 * 1024) },
    });
    expect(res.status).toBe(413);
  });
});

describe("yank, owners", () => {
  it("yanks and unyanks, appending preferred-versions to the index", async () => {
    const u = await newUser();
    const name = uniq("yank");
    await publish(u.token, await sdist(name, "1.0"));
    await publish(u.token, await sdist(name, "1.1"));
    const y = await call("PUT", `/api/v1/packages/${name}/1.1/yank`, { token: u.token });
    expect((await jsonOf(y)).changed).toBe(true);
    const info = await jsonOf(await call("GET", `/api/v1/packages/${name}`));
    expect(info.latest).toBe("1.0");
    expect(info.versions.find((v: any) => v.version === "1.1").yanked).toBe(true);
    const chunk = await env.DB.prepare("SELECT tar_bytes FROM index_chunks ORDER BY seq DESC LIMIT 1").first<{ tar_bytes: ArrayBuffer }>();
    const text = new TextDecoder().decode(new Uint8Array(chunk!.tar_bytes));
    expect(text).toContain(`${name}/preferred-versions`);
    expect(text).toContain(`${name} (<1.1 || >1.1)`);
    // yanked tarballs stay downloadable (existing freeze files keep working)
    expect((await call("GET", `/package/${name}-1.1.tar.gz`)).status).toBe(200);
    await call("DELETE", `/api/v1/packages/${name}/1.1/yank`, { token: u.token });
    expect((await jsonOf(await call("GET", `/api/v1/packages/${name}`))).latest).toBe("1.1");
  });

  it("adds and removes owners but never the last one", async () => {
    const [a, b, c] = [await newUser(), await newUser(), await newUser()];
    const name = uniq("own");
    await publish(a.token, await sdist(name, "1.0"));
    expect((await call("PUT", `/api/v1/packages/${name}/owners/${b.login}`, { token: c.token })).status).toBe(403);
    const added = await jsonOf(await call("PUT", `/api/v1/packages/${name}/owners/${b.login}`, { token: a.token }));
    expect(added.owners.map((o: any) => o.login).sort()).toEqual([a.login, b.login].sort());
    expect((await publish(b.token, await sdist(name, "1.1"))).status).toBe(201);
    await call("DELETE", `/api/v1/packages/${name}/owners/${a.login}`, { token: b.token });
    const last = await call("DELETE", `/api/v1/packages/${name}/owners/${b.login}`, { token: b.token });
    expect(last.status).toBe(409);
  });
});

describe("BHC attestations", () => {
  it("records only correctly signed attestations for the exact tarball", async () => {
    const u = await newUser();
    const name = uniq("verified");
    const body = await sdist(name, "1.0");
    await publish(u.token, body);
    const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
    const pub = b64encode(new Uint8Array((await crypto.subtle.exportKey("raw", pair.publicKey)) as ArrayBuffer));
    expect((await call("POST", "/api/v1/admin/verifiers", { token: ADMIN, body: { name: "ci-bhc", public_key: pub } })).status).toBe(201);

    const attestation = {
      package: name,
      version: "1.0",
      sha256: await sha256Hex(body),
      bhc_version: "0.2.17",
      profile: "default",
      result: "pass",
      log_url: "https://github.com/arcanist-sh/registry/actions/runs/1",
      built_at: "2026-10-19T12:00:00Z",
    };
    const sign = async (a: object) =>
      b64encode(new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, pair.privateKey, enc.encode(canonical(a as never)))));
    const post = (a: object, signature: string) =>
      call("POST", `/api/v1/packages/${name}/1.0/attestations`, { body: { attestation: a, verifier: "ci-bhc", signature } });

    expect((await post(attestation, await sign({ ...attestation, result: "fail" }))).status).toBe(403);
    const wrongSha = { ...attestation, sha256: "0".repeat(64) };
    expect((await post(wrongSha, await sign(wrongSha))).status).toBe(409);
    expect((await call("POST", `/api/v1/packages/${name}/1.0/attestations`, { body: { attestation, verifier: "nobody", signature: await sign(attestation) } })).status).toBe(403);
    const ok = await post(attestation, await sign(attestation));
    expect(ok.status).toBe(201);

    const v = await jsonOf(await call("GET", `/api/v1/packages/${name}/1.0`));
    expect(v.bhc_verified).toBe(true);
    expect(v.attestations[0]).toMatchObject({ verifier: "ci-bhc", bhc_version: "0.2.17", profile: "default", result: "pass" });
    expect((await jsonOf(await call("GET", `/api/v1/packages/${name}`))).versions[0].bhc_verified).toBe(true);
    const unverified = await jsonOf(await call("GET", "/api/v1/unverified?limit=200"));
    expect(unverified.versions.map((x: any) => x.name)).not.toContain(name);
  });
});

describe("Hackage name reservation", () => {
  afterEach(() => vi.restoreAllMocks());
  const hackageEnv = () => ({ ...env, HACKAGE_RESERVATION: "on", HACKAGE_URL: "https://hackage.mock" }) as Env;

  it("reserves names that exist on Hackage, caches the answer, and honours admin grants", async () => {
    const u = await newUser();
    const spy = vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      const url = String(input instanceof Request ? input.url : input);
      return new Response("{}", { status: url.includes("/package/taken-on-hackage/") ? 200 : 404 });
    });
    await expect(checkNewName(hackageEnv(), "taken-on-hackage", 1)).rejects.toMatchObject({ code: "name_reserved" });
    await expect(checkNewName(hackageEnv(), "Taken-On-Hackage", 1)).rejects.toBeInstanceOf(HttpError);
    expect(spy).toHaveBeenCalledTimes(1); // second lookup came from the D1 cache
    await expect(checkNewName(hackageEnv(), "free-name-xyz", 1)).resolves.toBeUndefined();

    expect((await call("PUT", "/api/v1/admin/reservations/taken-on-hackage", { token: ADMIN, body: { login: u.login } })).status).toBe(200);
    const uid = (await env.DB.prepare("SELECT id FROM users WHERE login = ?").bind(u.login).first<{ id: number }>())!.id;
    await expect(checkNewName(hackageEnv(), "taken-on-hackage", uid)).resolves.toBeUndefined();
    await expect(checkNewName(hackageEnv(), "taken-on-hackage", uid + 1000)).rejects.toMatchObject({ code: "name_reserved" });
  });

  it("fails closed when Hackage cannot be reached", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("oops", { status: 502 }));
    await expect(checkNewName(hackageEnv(), "unknown-name-abc", 1)).rejects.toMatchObject({ status: 503 });
  });
});

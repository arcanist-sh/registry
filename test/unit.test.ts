import { describe, expect, it } from "vitest";
import { parseCabal, PACKAGE_NAME_RE, VERSION_RE } from "../src/cabal";
import { canonical } from "../src/canonical";
import { GZ_TRAILER, gunzipLimited, gzip, SizeLimitError } from "../src/gzip";
import { compareVersions, preferredVersions } from "../src/publish";
import { Sha256, sha256Hex, toHex } from "../src/sha256";
import { concat, readTar, TAR_TRAILER, tarEntry } from "../src/tar";
import { keyIdFor } from "../src/tuf";

const enc = new TextEncoder();

describe("resumable sha256", () => {
  it("matches WebCrypto across arbitrary chunking and state round-trips", async () => {
    for (const size of [0, 1, 55, 56, 63, 64, 65, 119, 120, 1000, 70_000]) {
      const data = new Uint8Array(size);
      for (let o = 0; o < size; o += 65536) crypto.getRandomValues(data.subarray(o, Math.min(size, o + 65536)));
      let h = new Sha256();
      let off = 0;
      while (off < size) {
        const n = Math.min(size - off, 1 + Math.floor(Math.random() * 200));
        h.update(data.subarray(off, off + n));
        h = Sha256.fromState(h.state()); // persist and resume after every chunk
        off += n;
      }
      expect(h.hex()).toBe(await sha256Hex(data));
      expect(h.length).toBe(size);
    }
  });

  it("digest does not disturb the running state", async () => {
    const h = new Sha256().update(enc.encode("abc"));
    expect(h.hex()).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    h.update(enc.encode("def"));
    expect(h.hex()).toBe(await sha256Hex("abcdef"));
  });
});

describe("canonical JSON (hackage-security)", () => {
  it("sorts keys, drops whitespace, escapes only quote and backslash", () => {
    expect(canonical({ b: 1, a: [true, null, "x\"y\\z/"], c: {} })).toBe('{"a":[true,null,"x\\"y\\\\z/"],"b":1,"c":{}}');
  });
  it("rejects non-integers and non-ASCII", () => {
    expect(() => canonical(1.5)).toThrow();
    expect(() => canonical("é")).toThrow();
  });
  it("computes Hackage's real root key id", async () => {
    // From https://hackage.haskell.org/root.json
    expect(await keyIdFor("zazm5w480r+zPO6Z0+8fjGuxZtb9pAuoVmQ+VkuCvgU=")).toBe(
      "0a5c7ea47cd1b15f01f5f51a33adda7e655bc0f0b0615baa8e271f4c3351e21d",
    );
  });
});

describe("tar", () => {
  it("round-trips ustar entries, including long paths via prefix", () => {
    const long = `${"d".repeat(80)}/${"e".repeat(60)}/file.txt`;
    const tar = concat([tarEntry("a/b.txt", enc.encode("hello"), 1), tarEntry(long, enc.encode("x"), 2), TAR_TRAILER]);
    const files = readTar(tar, { maxEntries: 10 });
    expect(files.map((f) => f.path)).toEqual(["a/b.txt", long]);
    expect(new TextDecoder().decode(files[0].data)).toBe("hello");
  });
  it("enforces the entry limit", () => {
    const tar = concat([tarEntry("a", new Uint8Array(0), 1), tarEntry("b", new Uint8Array(0), 1), TAR_TRAILER]);
    expect(() => readTar(tar, { maxEntries: 1 })).toThrow(/more than 1 entries/);
  });
  it("detects corrupt headers", () => {
    const e = tarEntry("a", enc.encode("x"), 1);
    e[0] = "b".charCodeAt(0);
    expect(() => readTar(concat([e, TAR_TRAILER]), { maxEntries: 10 })).toThrow(/checksum/);
  });
});

describe("gzip", () => {
  it("hand-built trailer member decodes to the 1024-byte tar trailer", async () => {
    expect(await gunzipLimited(GZ_TRAILER, 4096)).toEqual(TAR_TRAILER);
  });
  it("members are independent gzip streams (clients decode them as one multi-member file)", async () => {
    // workerd's DecompressionStream stops after one member; cabal's zlib does
    // not (verified end-to-end), so here each member is checked on its own.
    const a = await gzip(enc.encode("one "));
    expect(new TextDecoder().decode(await gunzipLimited(a, 4096))).toBe("one ");
    expect(a[0]).toBe(0x1f);
    expect(GZ_TRAILER[0]).toBe(0x1f);
  });
  it("stops at the unpacked size limit", async () => {
    const bomb = await gzip(new Uint8Array(1 << 20));
    await expect(gunzipLimited(bomb, 1000)).rejects.toBeInstanceOf(SizeLimitError);
  });
});

describe("cabal parsing", () => {
  it("reads top-level fields case-insensitively and unions build-depends", () => {
    const info = parseCabal(`cabal-version: 3.0
Name: foo-bar
VERSION: 1.2.3
synopsis: A thing
  spanning lines
license: BSD-3-Clause

-- a comment
library
  build-depends: base >=4 && <5, text
               , containers ^>=0.6
executable foo
  build-depends:
    base,
    foo-bar:{internal} -any
  if flag(x)
    build-depends: aeson >=2
`);
    expect(info.name).toBe("foo-bar");
    expect(info.version).toBe("1.2.3");
    expect(info.synopsis).toBe("A thing spanning lines");
    expect(info.deps).toEqual([
      { name: "aeson", range: ">=2" },
      { name: "base", range: ">=4 && <5" },
      { name: "containers", range: "^>=0.6" },
      { name: "foo-bar", range: "-any" },
      { name: "text", range: "any" },
    ]);
  });
  it("validates package names and versions like cabal", () => {
    for (const ok of ["foo", "foo-bar", "a1", "x-2d"]) expect(PACKAGE_NAME_RE.test(ok)).toBe(true);
    for (const bad of ["", "-foo", "foo-", "foo--bar", "123", "foo-1", "foo_bar", "../x"]) expect(PACKAGE_NAME_RE.test(bad)).toBe(false);
    expect(VERSION_RE.test("1.0.2")).toBe(true);
    expect(VERSION_RE.test("1.0-rc1")).toBe(false);
  });
});

describe("versions", () => {
  it("compares numerically", () => {
    expect(["1.10", "1.2", "1.2.0", "0.9"].sort(compareVersions)).toEqual(["0.9", "1.2", "1.2.0", "1.10"]);
  });
  it("builds preferred-versions that exclude yanked versions", () => {
    expect(preferredVersions("foo", [])).toBe("foo >=0\n");
    expect(preferredVersions("foo", ["1.2", "1.0"])).toBe("foo (<1.0 || >1.0) && (<1.2 || >1.2)\n");
  });
});

it("toHex", () => expect(toHex(new Uint8Array([0, 255, 16]))).toBe("00ff10"));

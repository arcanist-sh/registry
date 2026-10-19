#!/usr/bin/env node
// Offline TUF key ceremony for the registry.
//
//   node scripts/tuf-keygen.mjs <out-dir> [--root-keys 3] [--threshold 2] [--years 1]
//
// Writes, into <out-dir> (created with mode 0700):
//   keys/root-<n>.jwk, keys/mirrors.jwk   offline private keys: keep them OFF the server
//   keys/online.jwk                       the Worker secret TUF_ONLINE_KEY (snapshot+timestamp)
//   root.json, mirrors.json               signed metadata to upload via the admin API
//   cabal-stanza.txt                      the root-keys/key-threshold for users
//
// Re-sign root.json/mirrors.json before they expire with `--resign <out-dir>`
// (reuses the existing keys, bumps the version).
import { mkdirSync, readFileSync, writeFileSync, existsSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { generate, loadJwk, signWith, tufTime } from "./lib.mjs";

const args = process.argv.slice(2);
const opt = (name, def) => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : def;
};
const resign = args.includes("--resign");
const out = args.find((a, i) => !a.startsWith("--") && !(i > 0 && args[i - 1].startsWith("--") && args[i - 1] !== "--resign"));
if (!out) {
  console.error("usage: node scripts/tuf-keygen.mjs <out-dir> [--root-keys 3] [--threshold 2] [--years 1] [--resign]");
  process.exit(2);
}
const nRoot = Number(opt("--root-keys", 3));
const threshold = Number(opt("--threshold", 2));
const years = Number(opt("--years", 1));
const keysDir = join(out, "keys");

const save = (file, jwk) => writeFileSync(join(keysDir, file), JSON.stringify(jwk) + "\n", { mode: 0o600 });
const load = async (file) => {
  const jwk = JSON.parse(readFileSync(join(keysDir, file), "utf8"));
  return { jwk, ...(await loadJwk(jwk)) };
};

let root, mirrors, online, version = 1;
if (resign) {
  root = [];
  for (const f of readdirSync(keysDir).filter((f) => f.startsWith("root-")).sort()) root.push(await load(f));
  mirrors = await load("mirrors.jwk");
  online = await load("online.jwk");
  if (existsSync(join(out, "root.json"))) version = JSON.parse(readFileSync(join(out, "root.json"), "utf8")).signed.version + 1;
} else {
  if (existsSync(keysDir)) {
    console.error(`${keysDir} already exists; refusing to overwrite keys (use --resign)`);
    process.exit(1);
  }
  mkdirSync(keysDir, { recursive: true, mode: 0o700 });
  root = [];
  for (let i = 1; i <= nRoot; i++) {
    const k = await generate();
    save(`root-${i}.jwk`, k.jwk);
    root.push(k);
  }
  mirrors = await generate();
  save("mirrors.jwk", mirrors.jwk);
  online = await generate();
  save("online.jwk", online.jwk);
}

const expires = new Date();
expires.setUTCFullYear(expires.getUTCFullYear() + years);
const keys = {};
for (const k of [...root, mirrors, online]) keys[k.keyid] = { keytype: "ed25519", keyval: { public: k.publicB64 } };
const rootSigned = {
  _type: "Root",
  expires: tufTime(expires),
  keys,
  roles: {
    root: { keyids: root.map((k) => k.keyid), threshold },
    mirrors: { keyids: [mirrors.keyid], threshold: 1 },
    targets: { keyids: [], threshold: 1 },
    snapshot: { keyids: [online.keyid], threshold: 1 },
    timestamp: { keyids: [online.keyid], threshold: 1 },
  },
  version,
};
writeFileSync(join(out, "root.json"), await signWith(root, rootSigned));
writeFileSync(
  join(out, "mirrors.json"),
  await signWith([mirrors], { _type: "Mirrorlist", expires: tufTime(expires), mirrors: [], version }),
);
const stanza = `  secure: True\n  root-keys: ${root.map((k) => k.keyid).join("\n             ")}\n  key-threshold: ${threshold}\n`;
writeFileSync(join(out, "cabal-stanza.txt"), stanza);
console.log(`wrote ${out}/root.json and mirrors.json (version ${version}, expires ${tufTime(expires)})`);
console.log(`online key id: ${online.keyid}  (secret: ${keysDir}/online.jwk -> TUF_ONLINE_KEY)`);
console.log(`root key ids (threshold ${threshold}):\n  ${root.map((k) => k.keyid).join("\n  ")}`);

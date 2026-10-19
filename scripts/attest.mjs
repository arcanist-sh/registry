#!/usr/bin/env node
// Sign and submit a BHC verification attestation.
//
//   BHC_VERIFIER_KEY='<private Ed25519 JWK>' node scripts/attest.mjs \
//     --registry https://registry.arcanist.sh --verifier ci-bhc \
//     --package foo --version 1.0.0 --sha256 <hex> --bhc-version 0.2.17 \
//     --profile default --result pass --log-url https://github.com/.../runs/1
//
//   node scripts/attest.mjs --keygen     prints a new verifier key pair
import { b64, canonical, generate, loadJwk } from "./lib.mjs";
import { webcrypto as crypto } from "node:crypto";

const args = process.argv.slice(2);
const opt = (n) => {
  const i = args.indexOf(n);
  return i >= 0 ? args[i + 1] : undefined;
};
if (args.includes("--keygen")) {
  const k = await generate();
  console.log(JSON.stringify({ private_jwk: k.jwk, public_key: k.publicB64 }, null, 2));
  process.exit(0);
}
const need = (n) => {
  const v = opt(n);
  if (!v) {
    console.error(`missing ${n}`);
    process.exit(2);
  }
  return v;
};
const attestation = {
  package: need("--package"),
  version: need("--version"),
  sha256: need("--sha256"),
  bhc_version: need("--bhc-version"),
  profile: opt("--profile") ?? "default",
  result: need("--result"),
  built_at: new Date().toISOString().replace(/\.\d+Z$/, "Z"),
};
if (opt("--log-url")) attestation.log_url = opt("--log-url");
const key = await loadJwk(JSON.parse(process.env.BHC_VERIFIER_KEY ?? "{}"));
const sig = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, key.key, new TextEncoder().encode(canonical(attestation))));
const registry = (opt("--registry") ?? "https://registry.arcanist.sh").replace(/\/$/, "");
const res = await fetch(`${registry}/api/v1/packages/${attestation.package}/${attestation.version}/attestations`, {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ attestation, verifier: need("--verifier"), signature: b64(sig) }),
});
console.log(res.status, await res.text());
process.exit(res.ok ? 0 : 1);

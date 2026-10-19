# arcanist.sh package registry

A Haskell package registry for the arcanist.sh ecosystem (hx + BHC). It runs
on Cloudflare Workers, with D1 for metadata and R2 for blobs.

- **Plain cabal can use it.** The registry is a hackage-security (TUF)
  repository: signed `timestamp.json`/`snapshot.json`, and an append-only
  `01-index.tar` that clients update incrementally with HTTP `Range`. The
  legacy `secure: False` mode works too. Tested with cabal-install 3.16.1.0
  and GHC 9.8.2.
- **The JSON API serves hx.** It covers search, package and version info,
  publish, yank and unyank, owners, scoped API tokens, and BHC-verification
  attestations.
- Design and rationale: [`docs/DESIGN.md`](docs/DESIGN.md).

Status: works locally (`wrangler dev --local`, vitest with the Workers
runtime). **Not deployed.** Every step that touches a Cloudflare account,
DNS or GitHub is listed under [Deploy](#deploy-owner-checklist), so each one
can be approved separately.

## Using it from cabal

```cabal
-- cabal.project (or ~/.config/cabal/config)
repository registry.arcanist.sh
  url: https://registry.arcanist.sh/
  secure: True
  root-keys: <root key id 1>
             <root key id 2>
             <root key id 3>
  key-threshold: 2
```

`hx registry add` writes this stanza for you. The key ids come from
`GET /api/v1/config`, or from `cabal-stanza.txt` written by the key ceremony.
cabal merges this repository with Hackage. Names that exist on Hackage are
reserved here, so the two never compete for the same package name.

## Local development

```sh
npm install                      # wrangler, vitest, @cloudflare/vitest-plugin, typescript
cp .dev.vars.example .dev.vars   # ADMIN_TOKEN (and optionally TUF_ONLINE_KEY)
npm run db:migrate:local         # wrangler d1 migrations apply ... --local
npm run dev                      # wrangler dev --local on http://localhost:8787
npm test                         # vitest inside workerd, local D1/R2
npm run typecheck
```

A full local loop:

```sh
# offline key ceremony (writes keys/ with mode 0600; never commit it)
node scripts/tuf-keygen.mjs ../tuf-dev
# put keys/online.jwk into .dev.vars as TUF_ONLINE_KEY='<json>' and restart dev
curl -X PUT -H "Authorization: Bearer dev-admin-token" --data-binary @../tuf-dev/root.json    localhost:8787/api/v1/admin/tuf/root.json
curl -X PUT -H "Authorization: Bearer dev-admin-token" --data-binary @../tuf-dev/mirrors.json localhost:8787/api/v1/admin/tuf/mirrors.json
curl -X POST -H "Authorization: Bearer dev-admin-token" -d '{"login":"me"}' localhost:8787/api/v1/admin/users   # prints a token once
hx registry login --registry http://localhost:8787 --token-stdin <<< "$TOKEN"
hx publish --registry http://localhost:8787
```

## API summary

| | |
|---|---|
| `GET /api/v1/config` | registry name, TUF root key ids, limits |
| `GET /api/v1/search?q=` | search by name and synopsis |
| `GET /api/v1/packages/:name` | versions, yanked flags, owners, `bhc_verified` |
| `GET /api/v1/packages/:name/:version` | deps, sha256, attestations |
| `PUT /api/v1/packages/upload` | publish an sdist (`Authorization: Bearer hxr_...`) |
| `PUT` / `DELETE /api/v1/packages/:name/:version/yank` | yank / unyank |
| `GET` · `PUT` · `DELETE /api/v1/packages/:name/owners[/:login]` | owners |
| `GET` · `POST` · `DELETE /api/v1/tokens[/:id]` | your API tokens |
| `POST /api/v1/packages/:name/:version/attestations` | signed BHC verification |
| `/api/v1/admin/...` | users, verifiers, reserved-name grants, TUF upload, seal (`ADMIN_TOKEN`) |

Cabal paths: `/01-index.tar`, `/01-index.tar.gz`, `/00-index.tar.gz`,
`/{root,mirrors,snapshot,timestamp}.json` and `/package/<pkgid>.tar.gz`.

## Deploy (owner checklist)

Each numbered step is externally visible. None of them has been run. Run them
in order, from this directory, after `npm install`.

1. **Log in to Cloudflare:** `npx wrangler login`.
2. **Create the D1 database:** `npx wrangler d1 create arcanist-registry`.
   Copy the printed `database_id` into `wrangler.jsonc`, replacing the
   all-zero placeholder.
3. **Create the R2 bucket:** `npx wrangler r2 bucket create arcanist-registry`.
4. **Apply migrations remotely:** `npx wrangler d1 migrations apply arcanist-registry --remote`.
5. **Rate limiter ids:** check that the `namespace_id`s in `wrangler.jsonc`
   (4201 to 4203) are not used by another Worker in the account. Change them
   if they are.
6. **Key ceremony** (offline, on a trusted machine):
   `node scripts/tuf-keygen.mjs <secure-dir>`. Store `keys/root-*.jwk` and
   `keys/mirrors.jwk` offline, ideally split across people or media. Only
   `keys/online.jwk` goes to Cloudflare.
7. **Secrets:**
   - `npx wrangler secret put ADMIN_TOKEN` (paste a value such as one from
     `openssl rand -base64 32`)
   - `npx wrangler secret put TUF_ONLINE_KEY < <secure-dir>/keys/online.jwk`
8. **Deploy:** `npx wrangler deploy` (optionally `--dry-run` first). The
   registry comes up at `arcanist-registry.<account>.workers.dev`.
9. **DNS / custom domain:** the `arcanist.sh` zone must be on Cloudflare.
   Uncomment the `routes` entry (`registry.arcanist.sh`, `custom_domain: true`)
   in `wrangler.jsonc`, then run `npx wrangler deploy` again. Wrangler creates
   the DNS record and the certificate. If the domain differs, also change
   `PUBLIC_URL` and `REGISTRY_NAME` in `vars`.
10. **Upload the TUF root and mirrors:**
    `curl -X PUT -H "Authorization: Bearer $ADMIN_TOKEN" --data-binary @<secure-dir>/root.json https://registry.arcanist.sh/api/v1/admin/tuf/root.json`,
    then the same for `mirrors.json`. The Worker checks the root's
    self-signatures and that the online key is the snapshot/timestamp key.
11. **First user:**
    `curl -X POST -H "Authorization: Bearer $ADMIN_TOKEN" -d '{"login":"<you>"}' https://registry.arcanist.sh/api/v1/admin/users`.
    The response contains a token that is shown only once.
12. **Publish the root key ids** (from `cabal-stanza.txt`) on arcanist.sh,
    so users can pin them independently of `/api/v1/config`.
13. **BHC verifier (GitHub):** generate a key with
    `node scripts/attest.mjs --keygen`. Register it with
    `POST /api/v1/admin/verifiers {"name":"ci-bhc","public_key":"..."}`. Create
    a verifier repository with `verifier/bhc-verify.yml`, and add the secret
    `BHC_VERIFIER_KEY` there. The workflow is a documented template and has
    not been run.
14. **hx:** once the registry is live, a later hx release can make
    `arcanist` resolvable by name only, or the default. Until then it stays
    opt-in (`--registry arcanist`).

Maintenance: a daily cron (`17 3 * * *`) re-signs the timestamp and snapshot
and seals index chunks into R2 segments. Re-sign `root.json` and
`mirrors.json` before they expire (1 year) with
`node scripts/tuf-keygen.mjs <secure-dir> --resign`, then repeat step 10.

## Cost estimate

List prices from developers.cloudflare.com, checked 2026-10-19:

- **Workers Free:** 100k requests per day and 10 ms CPU per invocation.
- **Workers Paid:** $5 per month, with 10M requests and 30M CPU-ms
  included, then $0.30 per million requests and $0.02 per million CPU-ms.
- **D1:** Free allows 5M rows read and 100k rows written per day, with 5 GB of
  storage. Paid includes 25B rows read and 50M rows written per month, then
  $0.001 per million reads and $1 per million writes, and $0.75 per GB-month
  over 5 GB.
- **R2:** 10 GB-month, 1M Class A and 10M Class B operations per month are
  free. Beyond that, storage is $0.015 per GB-month, Class A $4.50 per million
  and Class B $0.36 per million. Egress is free.

| scenario | traffic per month | plan | estimated cost |
|----------|-------------------|------|----------------|
| launch | 200 packages, about 1k versions; about 100k requests (cabal updates, downloads, API) | Free | **$0** |
| growing | 5k packages, about 50k versions (about 2.5 GB of tarballs); about 1M `cabal update`s (3 requests each), 2M tarball downloads, 1M API calls, so about 6M requests | Paid | **about $5** (everything within the included quotas) |
| large | about 50M requests, 20M downloads, 25 GB stored | Paid | about $5 + 40 × $0.30 (requests) + 10 × $0.36 (R2 Class B, per million) + 15 GB × $0.015 + about 45M CPU-ms × $0.02/M (at about 1.5 ms per request), so **about $22** |

Notes:

- **Workers Paid is recommended for production.** Publishing gunzips and
  hashes up to 16 MiB in the Worker, which can exceed the Free plan's 10 ms CPU
  limit for larger packages. Read paths use well under 10 ms.
- D1 rows read per request are small (point lookups, plus one row per sealed
  index segment), so reads stay far below the quotas.
- Pricing of the rate-limiting binding is not listed on the pricing page.
  Verify it before relying on the Free plan.
- Edge caching (the Cache API in front of tarballs and sealed segments) would
  cut R2 Class B operations further. It is follow-up work.

## Layout

```
src/            Worker (TypeScript): index.ts router, publish, api, repo (cabal files), tuf, index-store, auth, policy
migrations/     D1 schema
test/           vitest (Workers runtime, local D1/R2)
scripts/        offline: tuf-keygen.mjs (key ceremony), attest.mjs (verifier signing)
verifier/       GitHub Actions template for the BHC verifier
docs/DESIGN.md  design decisions
```

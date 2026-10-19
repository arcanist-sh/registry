// Name policy: GHC boot packages are never publishable, names are unique
// case-insensitively, and names that exist on Hackage are reserved (cabal
// merges same-named packages across repositories, so a registry "aeson" would
// leak into every user's aeson solve). Admins can grant a reserved name.

import { HttpError, nowSec } from "./util";

export const BOOT_PACKAGES = new Set([
  "array", "base", "binary", "bytestring", "cabal", "cabal-syntax", "containers", "deepseq", "directory",
  "exceptions", "filepath", "ghc", "ghc-bignum", "ghc-boot", "ghc-boot-th", "ghc-compact", "ghc-experimental",
  "ghc-heap", "ghc-internal", "ghc-platform", "ghc-prim", "ghc-toolchain", "ghci", "haskeline", "hpc",
  "integer-gmp", "integer-simple", "mtl", "os-string", "parsec", "pretty", "process", "rts", "semaphore-compat",
  "stm", "template-haskell", "terminfo", "text", "time", "transformers", "unix", "win32", "xhtml",
]);

const HACKAGE_CACHE_SECONDS = 7 * 86400;

/** Check that `userId` may create the new package `name`. */
export async function checkNewName(env: Env, name: string, userId: number): Promise<void> {
  const lower = name.toLowerCase();
  if (BOOT_PACKAGES.has(lower)) {
    throw new HttpError(403, "name_reserved", `"${name}" is a GHC boot package name and cannot be published here`);
  }
  const clash = await env.DB.prepare("SELECT name FROM packages WHERE name_lower = ?").bind(lower).first<{ name: string }>();
  if (clash) {
    throw new HttpError(409, "name_taken", `"${name}" conflicts with existing package "${clash.name}" (names are case-insensitive)`);
  }
  const row = await env.DB.prepare("SELECT on_hackage, checked_at, granted_to FROM name_reservations WHERE name_lower = ?")
    .bind(lower)
    .first<{ on_hackage: number; checked_at: number; granted_to: number | null }>();
  if (row?.granted_to !== null && row?.granted_to !== undefined) {
    if (row.granted_to === userId) return;
    throw new HttpError(403, "name_reserved", `"${name}" is reserved for another user`);
  }
  if (env.HACKAGE_RESERVATION !== "on") return;

  let onHackage: boolean;
  if (row && nowSec() - row.checked_at < HACKAGE_CACHE_SECONDS) {
    onHackage = row.on_hackage === 1;
  } else {
    onHackage = await existsOnHackage(env, name);
    await env.DB.prepare(
      `INSERT INTO name_reservations (name_lower, on_hackage, checked_at) VALUES (?, ?, ?)
       ON CONFLICT (name_lower) DO UPDATE SET on_hackage = excluded.on_hackage, checked_at = excluded.checked_at`,
    )
      .bind(lower, onHackage ? 1 : 0, nowSec())
      .run();
  }
  if (onHackage) {
    throw new HttpError(
      403,
      "name_reserved",
      `"${name}" exists on Hackage and is reserved`,
      "choose another name, or ask the registry operator to grant it if you maintain the Hackage package",
    );
  }
}

async function existsOnHackage(env: Env, name: string): Promise<boolean> {
  let res: Response;
  try {
    res = await fetch(`${env.HACKAGE_URL}/package/${encodeURIComponent(name)}/preferred`, {
      headers: { Accept: "application/json", "User-Agent": "arcanist-registry" },
      signal: AbortSignal.timeout(5000),
    });
  } catch {
    throw unavailable();
  }
  await res.body?.cancel();
  if (res.status === 200) return true;
  if (res.status === 404) return false;
  throw unavailable();
}

function unavailable(): HttpError {
  return new HttpError(503, "hackage_unavailable", "could not check Hackage for this package name; try again shortly", undefined, {
    "Retry-After": "30",
  });
}

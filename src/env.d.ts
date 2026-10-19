// Optional secret absent from .dev.vars, so `wrangler types` cannot see it.
interface OptionalSecrets {
  /** Ed25519 private JWK for signing snapshot.json/timestamp.json. Unset = no TUF. */
  TUF_ONLINE_KEY?: string;
}
interface Env extends OptionalSecrets {}
declare namespace Cloudflare {
  interface Env extends OptionalSecrets {}
}

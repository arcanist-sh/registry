// arcanist.sh package registry Worker.

import * as api from "./api";
import { authenticate } from "./auth";
import { sealIndex } from "./index-store";
import { handlePublish } from "./publish";
import { refreshTuf, serveIndex, servePackageTarball, serveTufFile } from "./repo";
import { HttpError, errorResponse, json } from "./util";

const TUF_FILES = new Set(["root.json", "mirrors.json", "snapshot.json", "timestamp.json"]);

function splitPkgId(pkgid: string): [string, string] | null {
  const m = /^(.+)-([0-9]+(?:\.[0-9]+)*)$/.exec(pkgid);
  return m ? [m[1], m[2]] : null;
}

function methodNotAllowed(): never {
  throw new HttpError(405, "method_not_allowed", "method not allowed for this path");
}

async function route(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  const url = new URL(req.url);
  const path = url.pathname;
  const m = req.method;
  const read = m === "GET" || m === "HEAD";

  // ---- cabal repository ----
  if (path === "/01-index.tar" || path === "/01-index.tar.gz" || path === "/00-index.tar.gz") {
    if (!read) methodNotAllowed();
    return serveIndex(env, req, path.endsWith(".gz") ? "gz" : "tar");
  }
  if (path.startsWith("/") && TUF_FILES.has(path.slice(1))) {
    if (!read) methodNotAllowed();
    return serveTufFile(env, path.slice(1));
  }
  let mm = /^\/package\/([^/]+)\.tar\.gz$/.exec(path);
  if (mm) {
    if (!read) methodNotAllowed();
    const id = splitPkgId(decodeURIComponent(mm[1]));
    if (!id) throw new HttpError(404, "not_found", "no such package");
    return servePackageTarball(env, id[0], id[1], m);
  }
  mm = /^\/package\/([^/]+)\/([^/]+)\.cabal$/.exec(path);
  if (mm) {
    const id = splitPkgId(decodeURIComponent(mm[1]));
    if (!id || id[0] !== decodeURIComponent(mm[2])) throw new HttpError(404, "not_found", "no such package");
    return api.cabalFile(env, id[0], id[1]);
  }

  // ---- JSON API ----
  if (path === "/" || path === "") {
    return json({ name: env.REGISTRY_NAME, api: `${env.PUBLIC_URL}/api/v1/config`, docs: "https://arcanist.sh" });
  }
  if (!path.startsWith("/api/v1/")) throw new HttpError(404, "not_found", `no route for ${path}`);
  const parts = path.slice("/api/v1/".length).split("/").filter(Boolean).map(decodeURIComponent);
  const [head, a, b, c] = parts;

  switch (head) {
    case "config":
      return api.getConfig(env);
    case "search":
      return api.search(env, url);
    case "unverified":
      return api.unverified(env, url);
    case "me":
      return api.me(await authenticate(env, req, ctx));
    case "admin":
      return api.admin(env, req, parts.slice(1));
    case "tokens": {
      const caller = await authenticate(env, req, ctx);
      if (!a && m === "GET") return api.listTokens(env, caller);
      if (!a && m === "POST") return api.createToken(env, req, caller);
      if (a && m === "DELETE") return api.revokeToken(env, caller, a);
      methodNotAllowed();
    }
    // eslint-disable-next-line no-fallthrough
    case "packages": {
      if (a === "upload" && !b) {
        if (m !== "PUT" && m !== "POST") methodNotAllowed();
        return handlePublish(env, req, await authenticate(env, req, ctx));
      }
      if (!a) throw new HttpError(404, "not_found", "use /api/v1/search?q=");
      if (!b && read) return api.packageInfo(env, a);
      if (b === "owners") {
        if (!c && read) return api.listOwners(env, a);
        if (c && (m === "PUT" || m === "DELETE")) return api.changeOwner(env, await authenticate(env, req, ctx), a, c, m === "PUT");
        methodNotAllowed();
      }
      if (b && !c && read) return api.versionInfo(env, a, b);
      if (b && c === "yank" && (m === "PUT" || m === "DELETE")) {
        return api.setYanked(env, await authenticate(env, req, ctx), a, b, m === "PUT");
      }
      if (b && c === "attestations" && m === "POST") return api.submitAttestation(env, req, a, b);
      methodNotAllowed();
    }
  }
  throw new HttpError(404, "not_found", `no route for ${path}`);
}

export default {
  async fetch(req, env, ctx): Promise<Response> {
    try {
      return await route(req, env, ctx);
    } catch (e) {
      if (e instanceof HttpError) return errorResponse(e);
      console.error(JSON.stringify({ msg: "unhandled error", url: req.url, error: String((e as Error)?.stack ?? e) }));
      return errorResponse(new HttpError(500, "internal", "internal error"));
    }
  },

  async scheduled(_controller, env, ctx): Promise<void> {
    ctx.waitUntil(
      (async () => {
        const sealed = await sealIndex(env);
        const tuf = await refreshTuf(env);
        console.log(JSON.stringify({ msg: "scheduled maintenance", sealed: sealed.sealed, tuf }));
      })(),
    );
  },
} satisfies ExportedHandler<Env>;

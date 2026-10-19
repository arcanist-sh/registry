// Small shared helpers: base64, JSON responses, structured errors, time.

export function b64encode(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

export function b64decode(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function b64url(bytes: Uint8Array): string {
  return b64encode(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64urlToB64(s: string): string {
  const t = s.replace(/-/g, "+").replace(/_/g, "/");
  return t + "=".repeat((4 - (t.length % 4)) % 4);
}

export const nowSec = (): number => Math.floor(Date.now() / 1000);

/** An error that maps to a JSON error response. */
export class HttpError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
    public hint?: string,
    public headers?: Record<string, string>,
  ) {
    super(message);
  }
}

// Accept-Ranges on every response: hackage-security learns that the server
// supports ranges from whatever response it sees first (timestamp.json), and
// only then attempts incremental 01-index.tar updates.
const SECURITY_HEADERS = {
  "Accept-Ranges": "bytes",
  "X-Content-Type-Options": "nosniff",
  "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
};

export function json(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body, null, 2) + "\n", {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", ...SECURITY_HEADERS, ...headers },
  });
}

export function errorResponse(e: HttpError): Response {
  const error: Record<string, string> = { code: e.code, message: e.message };
  if (e.hint) error.hint = e.hint;
  return json({ error }, e.status, e.headers);
}

export function withSecurityHeaders(headers: Record<string, string>): Record<string, string> {
  return { ...SECURITY_HEADERS, ...headers };
}

/** Read a request body, failing once it exceeds `max` bytes regardless of Content-Length. */
export async function readBodyLimited(req: Request, max: number): Promise<Uint8Array> {
  const declared = req.headers.get("Content-Length");
  if (declared !== null && Number(declared) > max) {
    throw new HttpError(413, "too_large", `request body is larger than the ${max}-byte limit`);
  }
  if (!req.body) return new Uint8Array(0);
  const reader = req.body.getReader();
  const parts: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > max) {
      await reader.cancel();
      throw new HttpError(413, "too_large", `request body is larger than the ${max}-byte limit`);
    }
    parts.push(value);
  }
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export async function readJson<T>(req: Request, max = 64 * 1024): Promise<T> {
  const body = await readBodyLimited(req, max);
  try {
    return JSON.parse(new TextDecoder().decode(body)) as T;
  } catch {
    throw new HttpError(400, "bad_json", "request body is not valid JSON");
  }
}

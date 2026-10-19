// Resumable SHA-256.
//
// WebCrypto cannot export a hash midstate, but the index snapshot hashes must
// be extended by each publish without re-reading the whole index. This small
// FIPS 180-4 implementation serializes its state (105 bytes) so it can be
// stored in D1 and resumed later.

const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

const INIT = [
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

export const SHA256_STATE_BYTES = 32 + 8 + 1 + 64;

export class Sha256 {
  private h = new Uint32Array(INIT);
  private buf = new Uint8Array(64);
  private bufLen = 0;
  private total = 0; // bytes hashed so far
  private w = new Uint32Array(64);

  static fromState(state: Uint8Array): Sha256 {
    if (state.length !== SHA256_STATE_BYTES) throw new Error("bad sha256 state length");
    const s = new Sha256();
    const dv = new DataView(state.buffer, state.byteOffset, state.byteLength);
    for (let i = 0; i < 8; i++) s.h[i] = dv.getUint32(i * 4);
    s.total = Number(dv.getBigUint64(32));
    s.bufLen = state[40];
    if (s.bufLen > 63) throw new Error("bad sha256 state buffer");
    s.buf.set(state.subarray(41, 41 + 64));
    return s;
  }

  state(): Uint8Array {
    const out = new Uint8Array(SHA256_STATE_BYTES);
    const dv = new DataView(out.buffer);
    for (let i = 0; i < 8; i++) dv.setUint32(i * 4, this.h[i]);
    dv.setBigUint64(32, BigInt(this.total));
    out[40] = this.bufLen;
    out.set(this.buf, 41);
    return out;
  }

  clone(): Sha256 {
    return Sha256.fromState(this.state());
  }

  get length(): number {
    return this.total;
  }

  update(data: Uint8Array): this {
    let i = 0;
    this.total += data.length;
    if (this.bufLen > 0) {
      const take = Math.min(64 - this.bufLen, data.length);
      this.buf.set(data.subarray(0, take), this.bufLen);
      this.bufLen += take;
      i = take;
      if (this.bufLen === 64) {
        this.block(this.buf, 0);
        this.bufLen = 0;
      }
    }
    for (; i + 64 <= data.length; i += 64) this.block(data, i);
    if (i < data.length) {
      this.buf.set(data.subarray(i), 0);
      this.bufLen = data.length - i;
    }
    return this;
  }

  /** Finish a copy of this hash; the receiver stays resumable. */
  digest(): Uint8Array {
    const c = this.clone();
    const bitLen = BigInt(c.total) * 8n;
    const pad = new Uint8Array(((c.bufLen < 56 ? 56 : 120) - c.bufLen) + 8);
    pad[0] = 0x80;
    new DataView(pad.buffer).setBigUint64(pad.length - 8, bitLen);
    c.update(pad);
    const out = new Uint8Array(32);
    const dv = new DataView(out.buffer);
    for (let i = 0; i < 8; i++) dv.setUint32(i * 4, c.h[i]);
    return out;
  }

  hex(): string {
    return toHex(this.digest());
  }

  private block(p: Uint8Array, off: number) {
    const w = this.w;
    for (let t = 0; t < 16; t++) {
      const j = off + t * 4;
      w[t] = (p[j] << 24) | (p[j + 1] << 16) | (p[j + 2] << 8) | p[j + 3];
    }
    for (let t = 16; t < 64; t++) {
      const x = w[t - 15];
      const y = w[t - 2];
      const s0 = ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
      const s1 = ((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10);
      w[t] = (w[t - 16] + s0 + w[t - 7] + s1) | 0;
    }
    let [a, b, c, d, e, f, g, h] = this.h;
    for (let t = 0; t < 64; t++) {
      const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + K[t] + w[t]) | 0;
      const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) | 0;
      h = g;
      g = f;
      f = e;
      e = (d + t1) | 0;
      d = c;
      c = b;
      b = a;
      a = (t1 + t2) | 0;
    }
    const H = this.h;
    H[0] += a; H[1] += b; H[2] += c; H[3] += d;
    H[4] += e; H[5] += f; H[6] += g; H[7] += h;
  }
}

export function toHex(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}

export async function sha256Hex(data: Uint8Array | string): Promise<string> {
  const bytes = typeof data === "string" ? new TextEncoder().encode(data) : data;
  return toHex(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)));
}

// gzip helpers. Each index chunk is stored as its own gzip member; members
// concatenate into a valid multi-member .tar.gz (RFC 1952 section 2.2).

import { TAR_TRAILER, concat } from "./tar";

export async function gzip(data: Uint8Array): Promise<Uint8Array> {
  const stream = new Blob([data]).stream().pipeThrough(new CompressionStream("gzip"));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

export class SizeLimitError extends Error {}

/** Decompress gzip, refusing to produce more than `maxBytes` (zip-bomb guard). */
export async function gunzipLimited(data: Uint8Array, maxBytes: number): Promise<Uint8Array> {
  const reader = new Blob([data]).stream().pipeThrough(new DecompressionStream("gzip")).getReader();
  const parts: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > maxBytes) {
      await reader.cancel();
      throw new SizeLimitError(`unpacked tarball exceeds ${maxBytes} bytes`);
    }
    parts.push(value);
  }
  return concat(parts);
}

let crcTable: Uint32Array | undefined;
function crc32(data: Uint8Array): number {
  if (!crcTable) {
    crcTable = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      crcTable[n] = c >>> 0;
    }
  }
  let c = 0xffffffff;
  for (const b of data) c = crcTable[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

/**
 * gzip member holding the 1024-byte tar trailer, built by hand as a single
 * stored deflate block so its bytes never depend on the runtime's zlib
 * version (they are covered by signed snapshot hashes).
 */
function storedGzipMember(data: Uint8Array): Uint8Array {
  if (data.length > 0xffff) throw new Error("stored block too large");
  const header = new Uint8Array([0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff]);
  const block = new Uint8Array(5);
  block[0] = 0x01; // BFINAL=1, BTYPE=00 (stored)
  block[1] = data.length & 0xff;
  block[2] = data.length >>> 8;
  block[3] = ~data.length & 0xff;
  block[4] = (~data.length >>> 8) & 0xff;
  const footer = new Uint8Array(8);
  const dv = new DataView(footer.buffer);
  dv.setUint32(0, crc32(data), true);
  dv.setUint32(4, data.length, true);
  return concat([header, block, data, footer]);
}

export const GZ_TRAILER = storedGzipMember(TAR_TRAILER);

/** Small, dependency-free byte helpers used by every detector. */

export function u8(n: number): number {
  return n & 0xff;
}

export function u16le(b: Uint8Array, o: number): number {
  return b[o]! | (b[o + 1]! << 8);
}

export function u16be(b: Uint8Array, o: number): number {
  return (b[o]! << 8) | b[o + 1]!;
}

export function u24le(b: Uint8Array, o: number): number {
  return b[o]! | (b[o + 1]! << 8) | (b[o + 2]! << 16);
}

export function u32le(b: Uint8Array, o: number): number {
  return (b[o]! | (b[o + 1]! << 8) | (b[o + 2]! << 16) | (b[o + 3]! << 24)) >>> 0;
}

export function u32be(b: Uint8Array, o: number): number {
  return ((b[o]! << 24) | (b[o + 1]! << 16) | (b[o + 2]! << 8) | b[o + 3]!) >>> 0;
}

/** 64-bit little-endian as a Number; safe up to 2^53-1. */
export function u64le(b: Uint8Array, o: number): number {
  const lo = u32le(b, o);
  const hi = u32le(b, o + 4);
  if (hi > 0x1fffff) return Number.MAX_SAFE_INTEGER;
  return hi * 0x1_0000_0000 + lo;
}

/** ZIP64 stores 64-bit values; 0xFFFFFFFF means "look in the extra field". */
export function u64be(b: Uint8Array, o: number): number {
  const hi = u32be(b, o);
  if (hi > 0x1fffff) return Number.MAX_SAFE_INTEGER;
  return hi * 0x1_0000_0000 + u32be(b, o + 4);
}

const ascii = new TextDecoder('latin1');
const utf8 = new TextDecoder('utf-8', { fatal: false });

/** Byte-exact ASCII scan of a whole buffer (latin1 keeps 1 char == 1 byte). */
export function latin1(b: Uint8Array): string {
  return ascii.decode(b);
}

export function utf8Lenient(b: Uint8Array): string {
  return utf8.decode(b);
}

export function asciiStartsWith(b: Uint8Array, s: string, offset = 0): boolean {
  if (offset < 0 || offset + s.length > b.length) return false;
  for (let i = 0; i < s.length; i++) {
    if (b[offset + i] !== s.charCodeAt(i)) return false;
  }
  return true;
}

export function asciiIndexOf(b: Uint8Array, s: string, from = 0, to = b.length): number {
  const n = s.length;
  const last = Math.min(to, b.length) - n;
  outer: for (let i = Math.max(0, from); i <= last; i++) {
    for (let j = 0; j < n; j++) {
      if (b[i + j] !== s.charCodeAt(j)) continue outer;
    }
    return i;
  }
  return -1;
}

export function bytesEqual(b: Uint8Array, s: number[], offset = 0): boolean {
  if (offset + s.length > b.length) return false;
  for (let i = 0; i < s.length; i++) if (b[offset + i] !== s[i]) return false;
  return true;
}

/** Index of `needle` inside `haystack`, both byte arrays. */
export function indexOfBytes(haystack: Uint8Array, needle: Uint8Array, from = 0): number {
  const n = needle.length;
  if (n === 0) return from;
  const last = haystack.length - n;
  outer: for (let i = Math.max(0, from); i <= last; i++) {
    for (let j = 0; j < n; j++) {
      if (haystack[i + j] !== needle[j]) continue outer;
    }
    return i;
  }
  return -1;
}

/**
 * Shannon entropy in bits per byte, computed over at most `sample` bytes.
 * Pure random data sits near 8.0; structured or padded data much lower.
 */
export function entropy(b: Uint8Array, sample = 64 * 1024): number {
  const n = Math.min(b.length, sample);
  if (n === 0) return 0;
  const counts = new Uint32Array(256);
  // Stride so a huge buffer is sampled across its whole length, not just its head.
  const stride = Math.max(1, Math.floor(b.length / n));
  let taken = 0;
  for (let i = 0; i < b.length && taken < n; i += stride, taken++) counts[b[i]!]++;
  let h = 0;
  for (let i = 0; i < 256; i++) {
    const c = counts[i]!;
    if (c === 0) continue;
    const p = c / taken;
    h -= p * Math.log2(p);
  }
  return h;
}

/** Ratio of bytes that are printable ASCII / whitespace. */
export function printableRatio(b: Uint8Array, sample = 8192): number {
  const n = Math.min(b.length, sample);
  if (n === 0) return 0;
  let printable = 0;
  for (let i = 0; i < n; i++) {
    const c = b[i]!;
    if ((c >= 0x20 && c < 0x7f) || c === 0x09 || c === 0x0a || c === 0x0d) printable++;
  }
  return printable / n;
}

export function formatBytes(n: number): string {
  if (!Number.isFinite(n)) return String(n);
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let v = n;
  let u = 0;
  while (v >= 1024 && u < units.length - 1) {
    v /= 1024;
    u++;
  }
  return `${v < 10 && u > 0 ? v.toFixed(1) : Math.round(v)} ${units[u]}`;
}

export function clampInt(v: number, lo: number, hi: number): number {
  return Math.min(hi, Math.max(lo, Math.trunc(v)));
}

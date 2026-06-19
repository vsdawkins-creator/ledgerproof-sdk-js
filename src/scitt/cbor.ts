/**
 * Minimal deterministic CBOR codec (RFC 8949) — scoped to exactly what the
 * SCITT / COSE profile needs, and nothing more.
 *
 * Why hand-rolled (not cbor-x / @auth0/cose):
 * COSE_Sign1 requires byte-exact control over (a) integer-keyed protected and
 * unprotected header maps, (b) deterministic map-key ordering for the protected
 * header bstr (which is signed), (c) detached payloads (`nil` inside the
 * Sig_structure), and (d) a `bstr .cbor` wrapped inclusion-proof array. A small
 * purpose-built encoder gives us that control with zero new runtime deps and a
 * tiny, auditable surface. See scitt/README rationale in the module docstring.
 *
 * Supported major types (encode + decode):
 *   0 unsigned int        (0 .. 2^53-1, encoded shortest-form)
 *   1 negative int        (-1 .. -(2^53))         — needed for alg = -8, label -1
 *   2 byte string         (definite length)
 *   3 text string         (definite length, UTF-8)
 *   4 array               (definite length)
 *   5 map                 (definite length; deterministic key order on encode)
 *   7 simple              (false/true/null only)
 *
 * Determinism (RFC 8949 §4.2.1):
 *   - Integers use the shortest possible encoding.
 *   - Definite-length strings/arrays/maps only.
 *   - Map keys are sorted by their encoded byte representation (bytewise
 *     lexicographic), the "Core Deterministic Encoding" rule. For the COSE
 *     integer label maps used here this reduces to: smaller-magnitude unsigned
 *     keys first, then negative keys — which matches COSE expectations.
 *
 * Floats, tags (except where the caller pre-wraps), bignums, indefinite lengths,
 * and maps with non-(int|string) keys are intentionally unsupported and throw.
 */

// A CBOR map is an ordered list of [key, value] pairs. We keep it as an array of
// entries (not a JS object) so integer keys and value types survive precisely.
export type CborMapEntries = Array<[CborKey, CborValue]>;
export type CborKey = number | string;
export type CborValue =
  | number
  | string
  | boolean
  | null
  | Uint8Array
  | CborValue[]
  | CborMap;

/** Wrapper marking an ordered CBOR map (integer or string keys preserved). */
export class CborMap {
  constructor(public readonly entries: CborMapEntries) {}
  get(key: CborKey): CborValue | undefined {
    for (const [k, v] of this.entries) if (k === key) return v;
    return undefined;
  }
}

export function cborMap(entries: CborMapEntries): CborMap {
  return new CborMap(entries);
}

// ── Encoder ──────────────────────────────────────────────────────────────────

const MAX_SAFE = Number.MAX_SAFE_INTEGER; // 2^53 - 1

class Writer {
  private chunks: number[] = [];
  push(b: number): void {
    this.chunks.push(b & 0xff);
  }
  pushBytes(bytes: Uint8Array): void {
    for (const b of bytes) this.chunks.push(b);
  }
  result(): Uint8Array {
    return Uint8Array.from(this.chunks);
  }
}

/** Encode a head: major type (high 3 bits) + argument, shortest-form. */
function writeHead(w: Writer, major: number, argument: number): void {
  const mt = major << 5;
  if (argument < 0 || !Number.isInteger(argument)) {
    throw new Error(`cbor: invalid head argument ${argument}`);
  }
  if (argument < 24) {
    w.push(mt | argument);
  } else if (argument < 0x100) {
    w.push(mt | 24);
    w.push(argument);
  } else if (argument < 0x10000) {
    w.push(mt | 25);
    w.push(argument >>> 8);
    w.push(argument & 0xff);
  } else if (argument < 0x100000000) {
    w.push(mt | 26);
    w.push((argument >>> 24) & 0xff);
    w.push((argument >>> 16) & 0xff);
    w.push((argument >>> 8) & 0xff);
    w.push(argument & 0xff);
  } else {
    // 64-bit argument for values up to 2^53-1. Split into hi/lo 32-bit halves.
    if (argument > MAX_SAFE) {
      throw new Error(`cbor: integer ${argument} exceeds 2^53-1`);
    }
    w.push(mt | 27);
    const hi = Math.floor(argument / 0x100000000);
    const lo = argument >>> 0;
    w.push((hi >>> 24) & 0xff);
    w.push((hi >>> 16) & 0xff);
    w.push((hi >>> 8) & 0xff);
    w.push(hi & 0xff);
    w.push((lo >>> 24) & 0xff);
    w.push((lo >>> 16) & 0xff);
    w.push((lo >>> 8) & 0xff);
    w.push(lo & 0xff);
  }
}

function encodeValue(w: Writer, value: CborValue): void {
  if (value === null) {
    w.push(0xf6); // simple null
    return;
  }
  if (value === false) {
    w.push(0xf4);
    return;
  }
  if (value === true) {
    w.push(0xf5);
    return;
  }
  if (typeof value === "number") {
    if (!Number.isInteger(value)) {
      throw new Error(`cbor: non-integer numbers unsupported (got ${value})`);
    }
    if (value >= 0) {
      writeHead(w, 0, value);
    } else {
      // Negative integer: major type 1, argument = -1 - n.
      const arg = -1 - value;
      writeHead(w, 1, arg);
    }
    return;
  }
  if (typeof value === "string") {
    const bytes = new TextEncoder().encode(value);
    writeHead(w, 3, bytes.length);
    w.pushBytes(bytes);
    return;
  }
  if (value instanceof Uint8Array) {
    writeHead(w, 2, value.length);
    w.pushBytes(value);
    return;
  }
  if (Array.isArray(value)) {
    writeHead(w, 4, value.length);
    for (const item of value) encodeValue(w, item);
    return;
  }
  if (value instanceof CborMap) {
    encodeMap(w, value);
    return;
  }
  throw new Error(`cbor: unsupported value type ${typeof value}`);
}

function encodeMap(w: Writer, map: CborMap): void {
  // Deterministic ordering: sort entries by encoded-key bytes (RFC 8949 §4.2.1).
  const encoded = map.entries.map(([k, v]) => {
    const kw = new Writer();
    encodeKey(kw, k);
    return { keyBytes: kw.result(), value: v };
  });
  encoded.sort((a, b) => compareBytes(a.keyBytes, b.keyBytes));
  // Reject duplicate keys (would be ambiguous and non-conformant).
  for (let i = 1; i < encoded.length; i++) {
    if (compareBytes(encoded[i - 1]!.keyBytes, encoded[i]!.keyBytes) === 0) {
      throw new Error("cbor: duplicate map key");
    }
  }
  writeHead(w, 5, encoded.length);
  for (const { keyBytes, value } of encoded) {
    w.pushBytes(keyBytes);
    encodeValue(w, value);
  }
}

function encodeKey(w: Writer, key: CborKey): void {
  if (typeof key === "number") {
    if (!Number.isInteger(key)) throw new Error("cbor: non-integer map key");
    encodeValue(w, key);
  } else if (typeof key === "string") {
    encodeValue(w, key);
  } else {
    throw new Error("cbor: map keys must be integer or string");
  }
}

/** Encode a CBOR value to bytes using deterministic encoding. */
export function encode(value: CborValue): Uint8Array {
  const w = new Writer();
  encodeValue(w, value);
  return w.result();
}

// ── Decoder ──────────────────────────────────────────────────────────────────

class Reader {
  constructor(
    private readonly buf: Uint8Array,
    public pos = 0
  ) {}
  byte(): number {
    if (this.pos >= this.buf.length) throw new Error("cbor: unexpected end of input");
    return this.buf[this.pos++]!;
  }
  bytes(n: number): Uint8Array {
    if (this.pos + n > this.buf.length) throw new Error("cbor: unexpected end of input");
    const slice = this.buf.subarray(this.pos, this.pos + n);
    this.pos += n;
    return slice;
  }
  get done(): boolean {
    return this.pos >= this.buf.length;
  }
}

function readArgument(r: Reader, info: number): number {
  if (info < 24) return info;
  if (info === 24) return r.byte();
  if (info === 25) {
    const b0 = r.byte();
    const b1 = r.byte();
    return (b0 << 8) | b1;
  }
  if (info === 26) {
    const b0 = r.byte();
    const b1 = r.byte();
    const b2 = r.byte();
    const b3 = r.byte();
    return (b0 * 0x1000000 + ((b1 << 16) | (b2 << 8) | b3)) >>> 0;
  }
  if (info === 27) {
    const hi =
      r.byte() * 0x1000000 + ((r.byte() << 16) | (r.byte() << 8) | r.byte());
    const lo =
      r.byte() * 0x1000000 + ((r.byte() << 16) | (r.byte() << 8) | r.byte());
    const value = hi * 0x100000000 + (lo >>> 0);
    if (value > MAX_SAFE) throw new Error("cbor: integer exceeds 2^53-1");
    return value;
  }
  throw new Error(`cbor: unsupported additional info ${info}`);
}

function decodeValue(r: Reader): CborValue {
  const initial = r.byte();
  const major = initial >> 5;
  const info = initial & 0x1f;

  switch (major) {
    case 0: // unsigned int
      return readArgument(r, info);
    case 1: // negative int
      return -1 - readArgument(r, info);
    case 2: {
      // byte string
      const len = readArgument(r, info);
      return r.bytes(len).slice();
    }
    case 3: {
      // text string
      const len = readArgument(r, info);
      return new TextDecoder("utf-8", { fatal: true }).decode(r.bytes(len));
    }
    case 4: {
      // array
      const len = readArgument(r, info);
      const arr: CborValue[] = [];
      for (let i = 0; i < len; i++) arr.push(decodeValue(r));
      return arr;
    }
    case 5: {
      // map
      const len = readArgument(r, info);
      const entries: CborMapEntries = [];
      for (let i = 0; i < len; i++) {
        const key = decodeValue(r);
        if (typeof key !== "number" && typeof key !== "string") {
          throw new Error("cbor: map key must be integer or string");
        }
        const val = decodeValue(r);
        entries.push([key, val]);
      }
      return new CborMap(entries);
    }
    case 7: {
      if (info === 20) return false;
      if (info === 21) return true;
      if (info === 22) return null;
      throw new Error(`cbor: unsupported simple/float value (info ${info})`);
    }
    default:
      throw new Error(`cbor: unsupported major type ${major}`);
  }
}

/** Decode a single CBOR value. Throws on trailing bytes. */
export function decode(bytes: Uint8Array): CborValue {
  const r = new Reader(bytes);
  const value = decodeValue(r);
  if (!r.done) throw new Error("cbor: trailing bytes after top-level value");
  return value;
}

/** Decode a single CBOR value, returning it plus the number of bytes consumed. */
export function decodeFirst(bytes: Uint8Array): { value: CborValue; length: number } {
  const r = new Reader(bytes);
  const value = decodeValue(r);
  return { value, length: r.pos };
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/** Bytewise lexicographic comparison (shorter-but-equal-prefix sorts first). */
export function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    if (a[i]! !== b[i]!) return a[i]! - b[i]!;
  }
  return a.length - b.length;
}

/** Concatenate byte arrays. */
export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const a of arrays) total += a.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

/** Constant-time-ish equality for two byte arrays (length-leaking, value-safe). */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

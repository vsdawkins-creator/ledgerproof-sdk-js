/**
 * LedgerProof Witness Envelope — v1 (TypeScript reference).
 *
 * The single source of truth for what a publisher signs. Its canonicalization is
 * byte-identical to the Python reference (lpr_api/witness/envelope.py), proven by
 * 13-api-backend/tests/test_witness_envelope.py.
 *
 * Spec: 04-lpr-spec/LedgerProof-Witness-Envelope-v1.md
 */
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils";
import { ed25519 } from "@noble/curves/ed25519";

export const ENVELOPE_VERSION = 1 as const;
export const ENVELOPE_TYP = "ledgerproof/witness-envelope" as const;
export const GENESIS_PREV_HASH = "0".repeat(64);
const MAX_SAFE = Number.MAX_SAFE_INTEGER;

export interface WitnessEnvelope {
  v: 1;
  typ: "ledgerproof/witness-envelope";
  /** SHA-256 of the artifact being attested (64 lowercase hex). */
  content_hash: string;
  /** Stable publisher identifier; resolves via identity_resolver. */
  publisher_id: string;
  /** https URL or did:web where publisher_id's PUBLIC key is published. */
  identity_resolver: string;
  /** This account's claimed append-only position (integer >= 0). */
  sequence: number;
  /** entry_hash of the previous envelope in this account's chain (64 hex; genesis = 64 zeros). */
  prev_hash: string;
  /** Recent Bitcoin block — the cryptographic lower time bound. */
  bitcoin: { height: number; block_hash: string };
  /** Signer's asserted time, RFC3339 UTC (informational). */
  client_timestamp: string;
}

type CanonicalValue = string | number | CanonicalValue[] | { [k: string]: CanonicalValue };

/**
 * RFC 8785 / JCS subset canonicalization.
 * Constrained value space: string | integer | array | object. No floats, no
 * booleans, no null. ASCII keys. Deterministic across languages.
 */
export function canonicalize(value: CanonicalValue): string {
  return ser(value);
}

function ser(v: CanonicalValue): string {
  if (typeof v === "string") return serString(v);
  if (typeof v === "number") return serNumber(v);
  if (Array.isArray(v)) return "[" + v.map(ser).join(",") + "]";
  if (v !== null && typeof v === "object") {
    const keys = Object.keys(v).sort();
    return "{" + keys.map((k) => serString(k) + ":" + ser(v[k]!)).join(",") + "}";
  }
  throw new TypeError(`canonicalize: unsupported value (${typeof v})`);
}

function serNumber(n: number): string {
  if (!Number.isInteger(n)) throw new TypeError(`canonicalize: only integers are allowed, got ${n}`);
  if (Math.abs(n) > MAX_SAFE) throw new RangeError(`canonicalize: integer ${n} exceeds 2^53-1`);
  return String(n);
}

function serString(s: string): string {
  let out = '"';
  for (const ch of s) {
    const code = ch.codePointAt(0)!;
    if (ch === '"') out += '\\"';
    else if (ch === "\\") out += "\\\\";
    else if (code === 0x08) out += "\\b";
    else if (code === 0x09) out += "\\t";
    else if (code === 0x0a) out += "\\n";
    else if (code === 0x0c) out += "\\f";
    else if (code === 0x0d) out += "\\r";
    else if (code < 0x20) out += "\\u" + code.toString(16).padStart(4, "0");
    else out += ch;
  }
  return out + '"';
}

/** The exact bytes that are signed and hashed. */
export function signedBytes(env: WitnessEnvelope): Uint8Array {
  return utf8ToBytes(canonicalize(env as unknown as CanonicalValue));
}

/** entry_hash = SHA-256(signedBytes), lowercase hex. Referenced by the next prev_hash. */
export function entryHash(env: WitnessEnvelope): string {
  return bytesToHex(sha256(signedBytes(env)));
}

/** Ed25519 signature over signedBytes, lowercase hex. privKeyHex = 32-byte seed. */
export async function signEnvelope(env: WitnessEnvelope, privKeyHex: string): Promise<string> {
  return bytesToHex(ed25519.sign(signedBytes(env), hexToBytes(privKeyHex)));
}

/** Verify an Ed25519 signature over signedBytes. publicKeyHex = 32-byte key. */
export async function verifyEnvelope(
  env: WitnessEnvelope,
  signatureHex: string,
  publicKeyHex: string
): Promise<boolean> {
  try {
    return ed25519.verify(hexToBytes(signatureHex), signedBytes(env), hexToBytes(publicKeyHex));
  } catch {
    return false;
  }
}

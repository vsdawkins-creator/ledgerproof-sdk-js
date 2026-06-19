/**
 * Minimal COSE_Sign1 (RFC 9052) with Ed25519 (RFC 9053), supporting detached
 * payloads (RFC 9052 §4.4). Integer-keyed headers throughout. Signs via the
 * SDK's @noble-backed Keypair.
 *
 * COSE_Sign1 wire structure (RFC 9052 §4.2), tagged with CWT/COSE tag 18:
 *
 *   18([ protected : bstr,        ; serialized (deterministic) header map
 *        unprotected : map,       ; header map (not signed)
 *        payload : bstr / nil,    ; nil => detached
 *        signature : bstr ])
 *
 * The Sig_structure that is actually signed (RFC 9052 §4.4):
 *
 *   Sig_structure = [
 *     context : "Signature1",
 *     body_protected : bstr,      ; the protected header bstr above
 *     external_aad : bstr,        ; empty here
 *     payload : bstr              ; the (possibly detached) content bytes
 *   ]
 *
 * For detached payloads the `payload` field on the wire is `nil`, but the
 * Sig_structure still hashes the actual detached content supplied out-of-band.
 * That is the whole point of a detached COSE Receipt: a verifier MUST recompute
 * the payload (here: the Merkle root) and cannot read it from the envelope.
 */

import type { Keypair } from "../keys.js";
import * as cbor from "./cbor.js";
import { CborMap, type CborMapEntries, type CborValue } from "./cbor.js";

/** The COSE_Sign1 CBOR tag (RFC 9052 §2). */
export const COSE_SIGN1_TAG = 18;

/** EdDSA algorithm identifier (RFC 9053 §2.2 / COSE registry). */
export const ALG_EDDSA = -8;

/** A decoded COSE_Sign1 message. `payload === null` means detached. */
export interface CoseSign1 {
  /** Serialized protected header (the exact signed bytes). */
  protected: Uint8Array;
  /** Decoded protected header map (parsed from `protected`). */
  protectedMap: CborMap;
  /** Unprotected header map. */
  unprotected: CborMap;
  /** Attached payload bytes, or null when detached. */
  payload: Uint8Array | null;
  /** 64-byte Ed25519 signature. */
  signature: Uint8Array;
}

/**
 * Build the RFC 9052 §4.4 Sig_structure bytes for a Signature1 context.
 *
 * @param protectedHeader serialized protected header bstr
 * @param payload the content bytes to sign (the *detached* content for receipts)
 * @param externalAad external additional authenticated data (empty by default)
 */
export function sigStructure(
  protectedHeader: Uint8Array,
  payload: Uint8Array,
  externalAad: Uint8Array = new Uint8Array(0)
): Uint8Array {
  const structure: CborValue[] = [
    "Signature1",
    protectedHeader,
    externalAad,
    payload,
  ];
  return cbor.encode(structure);
}

/**
 * Encode and Ed25519-sign a COSE_Sign1 message.
 *
 * @param opts.protectedHeader entries for the protected (signed) header map
 * @param opts.unprotectedHeader entries for the unprotected header map
 * @param opts.payload the content bytes
 * @param opts.detached when true, the wire payload is `nil` but the signature is
 *        still computed over `opts.payload` (the detached content)
 * @param opts.keypair the signing Keypair
 * @returns the tagged COSE_Sign1 bytes (with tag 18)
 */
export function signCoseSign1(opts: {
  protectedHeader: CborMapEntries;
  unprotectedHeader: CborMapEntries;
  payload: Uint8Array;
  detached: boolean;
  keypair: Keypair;
}): Uint8Array {
  const protectedBytes = cbor.encode(new CborMap(opts.protectedHeader));
  const toBeSigned = sigStructure(protectedBytes, opts.payload);
  const signature = opts.keypair.sign(toBeSigned);
  if (signature.length !== 64) {
    throw new Error(`cose: expected 64-byte Ed25519 signature, got ${signature.length}`);
  }

  const wirePayload: CborValue = opts.detached ? null : opts.payload;
  const message: CborValue[] = [
    protectedBytes,
    new CborMap(opts.unprotectedHeader),
    wirePayload,
    signature,
  ];
  return encodeTagged(COSE_SIGN1_TAG, cbor.encode(message));
}

/**
 * Decode a (possibly tagged) COSE_Sign1 message into its components.
 * Accepts either the tag-18-wrapped form or a bare 4-element array.
 */
export function decodeCoseSign1(bytes: Uint8Array): CoseSign1 {
  // Strip an optional tag-18 prefix at the byte level FIRST, then decode the
  // bare 4-element array. (Our minimal codec doesn't model tags as values, so a
  // tag head would otherwise be rejected as an unsupported major type.)
  const content = stripTagPrefix(bytes, COSE_SIGN1_TAG);
  const value = cbor.decode(content);

  if (!Array.isArray(value) || value.length !== 4) {
    throw new Error("cose: COSE_Sign1 must be a 4-element array");
  }
  const [prot, unprot, payload, sig] = value;
  if (!(prot instanceof Uint8Array)) {
    throw new Error("cose: protected header must be a byte string");
  }
  if (!(unprot instanceof CborMap)) {
    throw new Error("cose: unprotected header must be a map");
  }
  if (payload !== null && !(payload instanceof Uint8Array)) {
    throw new Error("cose: payload must be a byte string or nil");
  }
  if (!(sig instanceof Uint8Array)) {
    throw new Error("cose: signature must be a byte string");
  }
  // A zero-length protected header decodes to an empty map.
  const protectedMap =
    prot.length === 0 ? new CborMap([]) : (cbor.decode(prot) as CborMap);
  if (!(protectedMap instanceof CborMap)) {
    throw new Error("cose: protected header bstr must wrap a map");
  }
  return {
    protected: prot,
    protectedMap,
    unprotected: unprot,
    payload: payload ?? null,
    signature: sig,
  };
}

/**
 * Verify a COSE_Sign1 Ed25519 signature.
 *
 * @param msg decoded COSE_Sign1
 * @param publicKey 32-byte Ed25519 public key
 * @param detachedPayload required when `msg.payload` is null — the content the
 *        signature was computed over (e.g. the recomputed Merkle root)
 * @param externalAad external AAD (empty by default)
 */
export function verifyCoseSign1(
  msg: CoseSign1,
  publicKey: Uint8Array,
  detachedPayload?: Uint8Array,
  externalAad: Uint8Array = new Uint8Array(0)
): boolean {
  const payload = msg.payload ?? detachedPayload;
  if (payload === undefined || payload === null) {
    throw new Error("cose: detached payload required to verify a detached COSE_Sign1");
  }
  const toBeSigned = sigStructure(msg.protected, payload, externalAad);
  return ed25519Verify(msg.signature, toBeSigned, publicKey);
}

// ── Tag handling ─────────────────────────────────────────────────────────────
//
// Our minimal CBOR codec doesn't model tags as values, so we handle the single
// tag we emit (18) at the byte level: prepend the tag head on encode, and detect
// + skip it on decode.

function encodeTagged(tag: number, contentBytes: Uint8Array): Uint8Array {
  // Tag head: major type 6. Tags < 24 fit in one byte.
  if (tag < 24) {
    return cbor.concatBytes(Uint8Array.from([0xc0 | tag]), contentBytes);
  }
  if (tag < 0x100) {
    return cbor.concatBytes(Uint8Array.from([0xd8, tag]), contentBytes);
  }
  throw new Error(`cose: unsupported tag ${tag}`);
}

/**
 * If `bytes` begins with the given CBOR tag head, return the content bytes that
 * follow the tag; otherwise return `bytes` unchanged (an untagged COSE_Sign1).
 */
function stripTagPrefix(bytes: Uint8Array, tag: number): Uint8Array {
  if (bytes.length === 0) return bytes;
  const b0 = bytes[0]!;
  if (tag < 24 && b0 === (0xc0 | tag)) {
    return bytes.subarray(1);
  }
  if (tag >= 24 && tag < 0x100 && b0 === 0xd8 && bytes[1] === tag) {
    return bytes.subarray(2);
  }
  return bytes;
}

// ── Ed25519 verify (public-key only, no Keypair needed) ──────────────────────

import { ed25519 } from "@noble/curves/ed25519";

// @noble/curves bundles SHA-512 synchronously, so no sha512Sync wiring is needed.

/** Verify an Ed25519 signature against a raw 32-byte public key. */
export function ed25519Verify(
  signature: Uint8Array,
  message: Uint8Array,
  publicKey: Uint8Array
): boolean {
  try {
    return ed25519.verify(signature, message, publicKey);
  } catch {
    return false;
  }
}

/**
 * SCITT Signed Statements, Receipts, and Transparent Statements.
 *
 * Implements the LedgerProof SCITT Profile (DRAFT v0.1):
 *   §2 Signed Statement   → {@link encodeSignedStatement}
 *   §4 Receipt            → {@link assembleReceipt}
 *   §5 Transparent Stmt   → {@link attachReceipt}
 *
 * Every COSE structure here is built with the deterministic CBOR codec and the
 * hand-rolled COSE_Sign1 so the protected-header bytes, detached payloads, and
 * `bstr .cbor`-wrapped inclusion proof are byte-exact per the targeted drafts.
 */

import type { Keypair } from "../keys.js";
import * as cbor from "./cbor.js";
import { CborMap, type CborMapEntries } from "./cbor.js";
import {
  ALG_EDDSA,
  decodeCoseSign1,
  signCoseSign1,
  type CoseSign1,
} from "./cose.js";
import {
  CODE_POINTS,
  COSE_HEADER,
  CWT_CLAIM,
  DEFAULT_CONTENT_TYPE,
  TYP_SCITT_STATEMENT,
  VDP_INCLUSION_LABEL,
  type CodePoints,
} from "./constants.js";
import { hashLeaf } from "./merkle.js";
import type { ReceiptInput, SignedStatementOptions } from "./types.js";

/**
 * Build and Ed25519-sign a SCITT Signed Statement as a COSE_Sign1 (spec §2).
 *
 * Protected header:
 *   { 1:-8 (EdDSA), 3:content_type, 4:kid,
 *     16:"application/scitt-statement+cose",
 *     15:{ 1:iss, 2:sub } }
 * Payload: the Article-50 `content` object serialized as CBOR (a map).
 * Signature: Ed25519 over the RFC 9052 §4.4 Sig_structure.
 *
 * @param content the Article-50 content object (e.g. AiArticle50Content)
 * @param opts issuer keypair + CWT iss/sub (+ optional kid / content_type)
 * @returns the tagged COSE_Sign1 Signed Statement bytes
 */
export function encodeSignedStatement(
  content: Record<string, unknown>,
  opts: SignedStatementOptions
): Uint8Array {
  // Content constraint (spec §2.1): every integer in the content MUST be a
  // safe CBOR/JSON integer (|n| ≤ 2^53-1). Validate up front with a friendly,
  // path-named error so callers see *which* field is out of range — long before
  // the low-level CBOR writer would reject it with a generic message.
  assertSafeContentIntegers(content);

  const kidBytes = resolveKid(opts.kid, opts.keypair);

  // CWT_Claims map (header 15): { 1: iss, 2: sub } — both REQUIRED (spec §2).
  const cwtClaims = new CborMap([
    [CWT_CLAIM.iss, opts.iss],
    [CWT_CLAIM.sub, opts.sub],
  ]);

  const protectedHeader: CborMapEntries = [
    [COSE_HEADER.alg, ALG_EDDSA],
    [COSE_HEADER.contentType, opts.contentType ?? DEFAULT_CONTENT_TYPE],
    [COSE_HEADER.kid, kidBytes],
    [COSE_HEADER.typ, TYP_SCITT_STATEMENT],
    [COSE_HEADER.cwtClaims, cwtClaims],
  ];

  // Payload = Article-50 content serialized as a CBOR map (spec §2).
  const payload = cbor.encode(toCborMap(content));

  return signCoseSign1({
    protectedHeader,
    unprotectedHeader: [], // empty at issuance; receipts attach later (spec §5)
    payload,
    detached: false,
    keypair: opts.keypair,
  });
}

/**
 * Build and Ed25519-sign a SCITT Receipt as a detached COSE_Sign1 (spec §4).
 *
 * Protected header:  { 1:-8 (EdDSA), 395:1 (vds = RFC9162_SHA256) }
 * Payload:           nil (DETACHED) — the detached content is the 32-byte root
 * Unprotected header:{ 396: { -1: [ bstr.cbor [tree_size, leaf_index, [+path]] ] } }
 * Signature:         TS-key Ed25519 over the Sig_structure whose payload is the root
 *
 * The inclusion proof is CBOR-encoded as `[tree_size, leaf_index, [path...]]`
 * and then wrapped as a CBOR byte string (`bstr .cbor`), matching the
 * cose-receipts inclusion-proof encoding.
 *
 * @param input merkleRoot (detached payload) + tree_size/leaf_index/path
 * @param tsKeypair the Transparency-Service signing key
 * @param codePoints optional override of provisional code points (spec §8)
 * @returns the tagged, detached COSE_Sign1 Receipt bytes
 */
export function assembleReceipt(
  input: ReceiptInput,
  tsKeypair: Keypair,
  codePoints: CodePoints = CODE_POINTS
): Uint8Array {
  if (input.merkleRoot.length !== 32) {
    throw new Error(
      `scitt: merkleRoot must be 32 bytes (SHA-256), got ${input.merkleRoot.length}`
    );
  }
  if (!Number.isInteger(input.treeSize) || input.treeSize < 1) {
    throw new Error(`scitt: treeSize must be a positive integer, got ${input.treeSize}`);
  }
  if (
    !Number.isInteger(input.leafIndex) ||
    input.leafIndex < 0 ||
    input.leafIndex >= input.treeSize
  ) {
    throw new Error(
      `scitt: leafIndex ${input.leafIndex} out of range [0, ${input.treeSize})`
    );
  }
  for (const h of input.inclusionPath) {
    if (h.length !== 32) {
      throw new Error("scitt: every inclusion-path element must be a 32-byte hash");
    }
  }

  // Inner inclusion-proof array, then wrap as bstr .cbor.
  const proofArray = cbor.encode([
    input.treeSize,
    input.leafIndex,
    input.inclusionPath as cbor.CborValue[],
  ]);

  // vdp map (396): { -1: [ <bstr .cbor proof> ] }  (list of inclusion proofs).
  const vdp = new CborMap([[VDP_INCLUSION_LABEL, [proofArray]]]);

  const protectedHeader: CborMapEntries = [
    [COSE_HEADER.alg, ALG_EDDSA],
    [codePoints.vds, codePoints.vdsAlg],
  ];
  const unprotectedHeader: CborMapEntries = [[codePoints.vdp, vdp]];

  return signCoseSign1({
    protectedHeader,
    unprotectedHeader,
    payload: input.merkleRoot, // detached content the signature covers
    detached: true,
    keypair: tsKeypair,
  });
}

/**
 * Produce a Transparent Statement by attaching a Receipt to the Signed
 * Statement's unprotected header at label 394 (`receipts`) — spec §5.
 *
 * The `receipts` label holds an array of Receipts, so repeated calls append.
 * Returns new bytes; the input is not mutated. The protected header and
 * signature of the Signed Statement are preserved exactly (re-encoding only the
 * envelope around the unchanged signed bytes).
 *
 * @param signedStatement a COSE_Sign1 Signed Statement (from encodeSignedStatement)
 * @param receipt a COSE_Sign1 Receipt (from assembleReceipt)
 * @param codePoints optional override of provisional code points (spec §8)
 */
export function attachReceipt(
  signedStatement: Uint8Array,
  receipt: Uint8Array,
  codePoints: CodePoints = CODE_POINTS
): Uint8Array {
  const stmt = decodeCoseSign1(signedStatement);

  // Existing receipts at label 394, if any (array of bstr COSE_Sign1 Receipts).
  const existing = stmt.unprotected.get(codePoints.receipts);
  let receipts: cbor.CborValue[];
  if (existing === undefined) {
    receipts = [];
  } else if (Array.isArray(existing)) {
    receipts = [...existing];
  } else {
    throw new Error("scitt: existing `receipts` header is not an array");
  }
  receipts.push(receipt);

  // Rebuild the unprotected map: keep all other entries, set/replace label 394.
  const newEntries: CborMapEntries = stmt.unprotected.entries.filter(
    ([k]) => k !== codePoints.receipts
  );
  newEntries.push([codePoints.receipts, receipts]);

  // Re-encode the COSE_Sign1 with the original protected bytes, payload, and
  // signature untouched (we are only changing the *unprotected* header).
  const message: cbor.CborValue[] = [
    stmt.protected,
    new CborMap(newEntries),
    stmt.payload, // null if detached, else the payload bytes
    stmt.signature,
  ];
  return encodeTaggedSign1(cbor.encode(message));
}

/**
 * Compute the RFC 9162 leaf hash for a Signed/Transparent Statement, with the
 * unprotected header EMPTIED first (spec §3 / arch §6.3): the unprotected header
 * is not part of the signed statement and MUST be cleared before hashing.
 *
 *   leaf = SHA-256(0x00 || COSE_Sign1-with-empty-unprotected-header)
 *
 * @param statement Signed Statement or Transparent Statement bytes
 * @returns the 32-byte leaf hash
 */
export function statementLeafHash(statement: Uint8Array): Uint8Array {
  return hashLeaf(emptyUnprotected(statement));
}

/**
 * Return the COSE_Sign1 bytes with the unprotected header replaced by an empty
 * map, preserving the protected header bytes, payload, and signature exactly.
 */
export function emptyUnprotected(statement: Uint8Array): Uint8Array {
  const msg = decodeCoseSign1(statement);
  const message: cbor.CborValue[] = [
    msg.protected,
    new CborMap([]),
    msg.payload,
    msg.signature,
  ];
  return encodeTaggedSign1(cbor.encode(message));
}

/** Decode a Signed/Transparent Statement (re-export of the COSE decoder). */
export function decodeStatement(statement: Uint8Array): CoseSign1 {
  return decodeCoseSign1(statement);
}

// ── internals ────────────────────────────────────────────────────────────────

import { COSE_SIGN1_TAG } from "./cose.js";

/** Prepend the COSE_Sign1 tag (18) head to a bare 4-element array encoding. */
function encodeTaggedSign1(bare: Uint8Array): Uint8Array {
  return cbor.concatBytes(Uint8Array.from([0xc0 | COSE_SIGN1_TAG]), bare);
}

function resolveKid(
  kid: Uint8Array | string | undefined,
  keypair: Keypair
): Uint8Array {
  if (kid === undefined) return keypair.publicKey();
  if (typeof kid === "string") return new TextEncoder().encode(kid);
  return kid;
}

/**
 * Largest integer that survives a CBOR/JSON round-trip without precision loss
 * (`Number.MAX_SAFE_INTEGER`, 2^53-1). Integers in SCITT content MUST stay
 * within `±MAX_SAFE_CONTENT_INT` so the same value is recovered byte-for-byte by
 * the Python Transparency Service and any JSON-based verifier (spec §2.1).
 */
export const MAX_SAFE_CONTENT_INT = Number.MAX_SAFE_INTEGER; // 2^53 - 1

/**
 * Recursively assert that every integer reachable in `content` is within the
 * safe CBOR/JSON integer range (|n| ≤ 2^53-1), throwing a clear error that names
 * the exact JSON path (e.g. `content.eu_ai_act_50.training_tokens`) of the first
 * offending value. Larger identifiers / nanosecond timestamps MUST be encoded as
 * strings; timestamps are ISO-8601 strings (spec §2.1 "Content constraints").
 *
 * This is intentionally a *friendly* pre-flight check — the deterministic CBOR
 * writer also rejects out-of-range integers, but only with a generic, pathless
 * message. Catching it here points the caller straight at the field to fix.
 */
export function assertSafeContentIntegers(content: Record<string, unknown>): void {
  walkForUnsafeIntegers(content, "content");
}

function walkForUnsafeIntegers(value: unknown, path: string): void {
  if (typeof value === "number") {
    // Non-integer numbers are a separate (also-rejected) concern handled by the
    // encoder; here we only police the *magnitude* of integers.
    if (Number.isInteger(value) && Math.abs(value) > MAX_SAFE_CONTENT_INT) {
      throw new Error(
        `scitt: integer at '${path}' is ${value}, which exceeds the safe ` +
          `CBOR/JSON range (|n| ≤ 2^53-1 = ${MAX_SAFE_CONTENT_INT}). ` +
          `Encode large IDs or nanosecond timestamps as strings; use ISO-8601 ` +
          `strings for timestamps.`
      );
    }
    return;
  }
  if (typeof value === "bigint") {
    // A BigInt can hold values far outside the safe range; reject with the same
    // guidance regardless of magnitude (BigInt isn't a valid CBOR content type
    // in this profile anyway).
    throw new Error(
      `scitt: value at '${path}' is a BigInt (${String(value)}); BigInt is not ` +
        `a supported content type. Encode large IDs / nanosecond timestamps as ` +
        `strings (|n| ≤ 2^53-1 for numeric fields).`
    );
  }
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) {
      walkForUnsafeIntegers(value[i], `${path}[${i}]`);
    }
    return;
  }
  if (value !== null && typeof value === "object" && !(value instanceof Uint8Array)) {
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      walkForUnsafeIntegers(v, `${path}.${k}`);
    }
  }
}

/**
 * Convert a plain JS object into a deterministic CBOR map. String keys only
 * (Article-50 content is JSON-shaped). Nested objects/arrays are converted
 * recursively; `undefined`/`null` values are dropped to mirror the SDK's
 * canonical-JSON behavior (it strips undefined/null before hashing).
 */
function toCborMap(obj: Record<string, unknown>): CborMap {
  const entries: CborMapEntries = [];
  for (const [k, v] of Object.entries(obj)) {
    if (v === undefined || v === null) continue;
    entries.push([k, toCborValue(v)]);
  }
  return new CborMap(entries);
}

function toCborValue(v: unknown): cbor.CborValue {
  if (v === null) return null;
  if (typeof v === "boolean") return v;
  if (typeof v === "number") {
    if (!Number.isInteger(v)) {
      throw new Error(
        `scitt: non-integer number ${v} in content; encode as string for CBOR safety`
      );
    }
    return v;
  }
  if (typeof v === "string") return v;
  if (v instanceof Uint8Array) return v;
  if (Array.isArray(v)) return v.map(toCborValue);
  if (typeof v === "object") return toCborMap(v as Record<string, unknown>);
  throw new Error(`scitt: cannot CBOR-encode content value of type ${typeof v}`);
}

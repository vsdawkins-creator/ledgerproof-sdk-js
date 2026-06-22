/**
 * Trust-minimized verification of a SCITT Transparent Statement (spec §7).
 *
 * Steps (valid iff 1–4 pass; "bitcoin-confirmed" iff 5 also passes):
 *   1. Verify the Issuer COSE_Sign1 signature over the Signed Statement.
 *   2. Recompute leaf = SHA-256(0x00 || statement-with-EMPTIED-unprotected).
 *   3. Apply the inclusion proof (RFC 9162 §2.1.3.2) to recompute the root.
 *   4. Verify the Receipt COSE_Sign1 (TS key); its DETACHED payload MUST equal
 *      the recomputed root.
 *   5. [bonus] Confirm the root is in the Bitcoin OP_RETURN at the receipt's
 *      txid via a public explorer (4-byte "LPR1" || 32-byte root).
 *
 * None of steps 1–4 require trusting the LedgerProof API.
 */

import { bytesToHex } from "@noble/hashes/utils";

import * as cbor from "./cbor.js";
import { CborMap } from "./cbor.js";
import { decodeCoseSign1, verifyCoseSign1, type CoseSign1 } from "./cose.js";
import {
  ANCHOR_SEQ_ROOT_OFFSET,
  BITCOIN_OP_RETURN_PREFIX,
  BITCOIN_OP_RETURN_PREFIX_LEN,
  CODE_POINTS,
  COSE_HEADER,
  DEFAULT_MEMPOOL_API,
  LEGACY_ANCHOR_PREFIX,
  LEGACY_ROOT_OFFSET,
  ROOT_LEN,
  SCITT_ROOT_OFFSET,
  VDP_INCLUSION_LABEL,
  type CodePoints,
} from "./constants.js";
import { bytesEqual, concatBytes } from "./cbor.js";
import { rootFromInclusionProof } from "./merkle.js";
import { statementLeafHash } from "./statement.js";
import type { VerifyOptions, VerifyResult } from "./types.js";

/** A parsed inclusion proof extracted from a Receipt's vdp header. */
export interface ParsedInclusionProof {
  treeSize: number;
  leafIndex: number;
  path: Uint8Array[];
}

/**
 * Verify a Transparent Statement per spec §7.
 *
 * @param ts the Transparent Statement bytes (Signed Statement + attached Receipt)
 * @param opts issuer/TS public keys, optional kid resolver, optional Bitcoin check
 * @param codePoints optional override of provisional code points (spec §8)
 */
export async function verifyTransparentStatement(
  ts: Uint8Array,
  opts: VerifyOptions = {},
  codePoints: CodePoints = CODE_POINTS
): Promise<VerifyResult> {
  const statement = decodeCoseSign1(ts);

  // ── Step 1: Issuer signature over the Signed Statement ──────────────────────
  // The signature is over the statement's own protected header + payload; the
  // unprotected header (which now carries the receipt) is not signed, so an
  // attached receipt does not disturb issuer verification.
  const issuerKey = resolveIssuerKey(statement, opts);
  let issuerSignatureValid = false;
  if (issuerKey) {
    try {
      issuerSignatureValid = verifyCoseSign1(statement, issuerKey);
    } catch {
      issuerSignatureValid = false;
    }
  }

  // ── Step 2: leaf hash over the statement with EMPTIED unprotected header ─────
  // Recompute from the original bytes so attaching the receipt doesn't change
  // the leaf (the unprotected header is cleared before hashing — spec §3).
  const leafHash = statementLeafHash(ts);

  // ── Extract the Receipt and its inclusion proof ─────────────────────────────
  const receiptBytes = extractReceipt(statement, codePoints);
  let receipt: CoseSign1 | undefined;
  let proof: ParsedInclusionProof | undefined;
  if (receiptBytes) {
    receipt = decodeCoseSign1(receiptBytes);
    proof = parseInclusionProof(receipt, codePoints);
  }

  // ── Step 3: recompute the root from the inclusion proof ─────────────────────
  let recomputedRoot: Uint8Array | undefined;
  let inclusionProofValid = false;
  if (proof) {
    try {
      recomputedRoot = rootFromInclusionProof(
        leafHash,
        proof.leafIndex,
        proof.treeSize,
        proof.path
      );
    } catch {
      recomputedRoot = undefined;
    }
  }

  // ── Step 4: verify the Receipt signature over the recomputed root ───────────
  // The Receipt payload is detached, so verification MUST supply the recomputed
  // root as the detached content. If the proof produced a root and the Receipt
  // signature validates against it, inclusion is proven.
  let receiptSignatureValid = false;
  if (receipt && recomputedRoot && opts.tsPublicKey) {
    try {
      receiptSignatureValid = verifyCoseSign1(
        receipt,
        opts.tsPublicKey,
        recomputedRoot
      );
    } catch {
      receiptSignatureValid = false;
    }
    // inclusion is "valid" when the recomputed root is exactly the signed root.
    // For a detached receipt that equality IS the signature check above; we also
    // expose the boolean independently for callers that pass an unsigned path.
    inclusionProofValid = receiptSignatureValid;
  } else if (recomputedRoot && receipt) {
    // No TS key supplied: we can still report that a root was recomputable, but
    // cannot confirm it equals the *signed* root. Compare against any attached
    // (non-detached) payload if present; otherwise leave inclusion unproven.
    if (receipt.payload && bytesEqual(receipt.payload, recomputedRoot)) {
      inclusionProofValid = true;
    }
  }

  const recomputedRootHex = recomputedRoot ? bytesToHex(recomputedRoot) : "";

  // ── Step 5 (bonus): Bitcoin OP_RETURN witness ───────────────────────────────
  let bitcoinConfirmed: boolean | undefined;
  if (opts.bitcoinCheck) {
    if (recomputedRoot && opts.txid) {
      bitcoinConfirmed = await checkBitcoinOpReturn(
        opts.txid,
        recomputedRoot,
        opts.mempoolApiBase ?? DEFAULT_MEMPOOL_API,
        opts.fetch ?? globalThis.fetch
      );
    } else {
      bitcoinConfirmed = false;
    }
  }

  const valid =
    issuerSignatureValid && inclusionProofValid && receiptSignatureValid;

  const result: VerifyResult = {
    issuerSignatureValid,
    inclusionProofValid,
    receiptSignatureValid,
    recomputedRoot: recomputedRootHex,
    valid,
  };
  if (bitcoinConfirmed !== undefined) result.bitcoinConfirmed = bitcoinConfirmed;
  return result;
}

// ── helpers ──────────────────────────────────────────────────────────────────

function resolveIssuerKey(
  statement: CoseSign1,
  opts: VerifyOptions
): Uint8Array | undefined {
  if (opts.issuerPublicKey) return opts.issuerPublicKey;
  if (opts.resolveIssuerKey) {
    const kid = statement.protectedMap.get(COSE_HEADER.kid);
    return opts.resolveIssuerKey(kid instanceof Uint8Array ? kid : undefined);
  }
  return undefined;
}

/** Pull the first Receipt (bstr) out of the statement's `receipts` header (394). */
export function extractReceipt(
  statement: CoseSign1,
  codePoints: CodePoints = CODE_POINTS
): Uint8Array | undefined {
  const receipts = statement.unprotected.get(codePoints.receipts);
  if (receipts === undefined) return undefined;
  if (!Array.isArray(receipts)) {
    throw new Error("scitt: `receipts` header must be an array of Receipts");
  }
  if (receipts.length === 0) return undefined;
  const first = receipts[0];
  if (!(first instanceof Uint8Array)) {
    throw new Error("scitt: each Receipt must be a COSE_Sign1 byte string");
  }
  return first;
}

/**
 * Parse the inclusion proof from a Receipt's vdp header (396):
 *   { -1: [ <bstr .cbor [tree_size, leaf_index, [+path]]> ] }
 */
export function parseInclusionProof(
  receipt: CoseSign1,
  codePoints: CodePoints = CODE_POINTS
): ParsedInclusionProof {
  const vdp = receipt.unprotected.get(codePoints.vdp);
  if (!(vdp instanceof CborMap)) {
    throw new Error("scitt: Receipt is missing the vdp (proofs) header map");
  }
  const proofs = vdp.get(VDP_INCLUSION_LABEL);
  if (!Array.isArray(proofs) || proofs.length === 0) {
    throw new Error("scitt: Receipt vdp has no inclusion proofs");
  }
  const wrapped = proofs[0];
  if (!(wrapped instanceof Uint8Array)) {
    throw new Error("scitt: inclusion proof must be a bstr .cbor byte string");
  }
  const inner = cbor.decode(wrapped);
  if (!Array.isArray(inner) || inner.length !== 3) {
    throw new Error("scitt: inclusion proof must be [tree_size, leaf_index, path]");
  }
  const [treeSize, leafIndex, path] = inner;
  if (typeof treeSize !== "number" || typeof leafIndex !== "number") {
    throw new Error("scitt: tree_size and leaf_index must be integers");
  }
  if (!Array.isArray(path)) {
    throw new Error("scitt: inclusion path must be an array of hashes");
  }
  const pathBytes: Uint8Array[] = path.map((h) => {
    if (!(h instanceof Uint8Array)) {
      throw new Error("scitt: each inclusion-path element must be a byte string");
    }
    return h;
  });
  return { treeSize, leafIndex, path: pathBytes };
}

/**
 * Spec §7 step 5: confirm the daily root is committed in a Bitcoin OP_RETURN
 * output of transaction `txid`.
 *
 * LedgerProof commits the legacy daily root and the SCITT daily root in a SINGLE
 * transaction with a versioned, prefixed layout (spec §6):
 *   - Legacy / SCITT-disabled:  `LPR1 || root`                  (36 bytes)
 *   - Combined (SCITT enabled): `LPR1 || legacy_root || scitt_root`  (68 bytes)
 *
 * This check therefore no longer requires the OP_RETURN data to equal
 * `"LPR1" || root` exactly. Instead it requires the data to (a) begin with the
 * `LPR1` prefix and (b) CONTAIN the recomputed `root` at a recognized 32-byte
 * slot — the legacy slot (offset 4) or the SCITT slot (offset 36) — so a SCITT
 * verifier confirms its root inside the combined commitment. See
 * {@link locateRootInOpReturn}.
 *
 * Queries a mempool.space-style REST API (`GET /tx/{txid}`) and scans the
 * transaction's outputs. Returns false on any network/parse error or if no
 * matching output is found.
 */
export async function checkBitcoinOpReturn(
  txid: string,
  root: Uint8Array,
  apiBase: string,
  fetchImpl: typeof fetch
): Promise<boolean> {
  if (!fetchImpl) return false;

  let tx: BitcoinTx;
  try {
    const url = `${apiBase.replace(/\/$/, "")}/tx/${encodeURIComponent(txid)}`;
    const resp = await fetchImpl(url);
    if (!resp.ok) return false;
    tx = (await resp.json()) as BitcoinTx;
  } catch {
    return false;
  }

  for (const vout of tx.vout ?? []) {
    // mempool.space exposes `scriptpubkey` (hex) and `scriptpubkey_type`.
    if (vout.scriptpubkey_type && vout.scriptpubkey_type !== "op_return") continue;
    const spk = vout.scriptpubkey;
    if (typeof spk !== "string") continue;
    // OP_RETURN script: 0x6a <pushdata...>. Locate the root within the pushed
    // data (legacy or combined layout).
    const dataHex = extractOpReturnData(spk);
    if (dataHex && locateRootInOpReturn(hexToBytesLocal(dataHex), root)) {
      return true;
    }
  }
  return false;
}

/**
 * Locate a 32-byte `root` inside the data of a LedgerProof OP_RETURN, LENGTH-
 * DISCRIMINATING the known on-chain layouts (spec §6, LPR-VER-001).
 *
 * The byte length selects the layout, and the root is only compared at the slot(s)
 * that layout actually defines — slots are NOT bled across lengths, so a value
 * straddling two roots (or sitting mid-root) cannot produce a false positive:
 *   - 44 bytes: `MAGIC{LPR1|QE20} || seq_start || seq_end || root`  → root@12 only
 *   - 68 bytes: `LPR1 || legacy_root || scitt_root`                 → roots@4 and @36
 *   - 36 bytes: `LPR1 || root`                                      → root@4 only
 * Other lengths, and the legacy `QE20` magic on the 68/36 SCITT layouts, are
 * rejected. A future `LPR2` layout is rejected until explicitly supported.
 */
export function locateRootInOpReturn(data: Uint8Array, root: Uint8Array): boolean {
  if (root.length !== ROOT_LEN) return false;
  if (data.length < BITCOIN_OP_RETURN_PREFIX_LEN) return false;
  const magic = String.fromCharCode(
    ...data.subarray(0, BITCOIN_OP_RETURN_PREFIX_LEN)
  );
  // Branch on the exact byte length; pick the root slot(s) that length defines.
  let slots: number[];
  if (data.length === 44) {
    // Deployed legacy: accept LPR1 (v1.0+) or legacy QE20 (pre-v1); root after the seq bounds.
    if (magic !== BITCOIN_OP_RETURN_PREFIX && magic !== LEGACY_ANCHOR_PREFIX) return false;
    slots = [ANCHOR_SEQ_ROOT_OFFSET];
  } else if (data.length === 68) {
    // Combined SCITT — LPR1 only (the SCITT pipeline never used the QE20 tag).
    if (magic !== BITCOIN_OP_RETURN_PREFIX) return false;
    slots = [LEGACY_ROOT_OFFSET, SCITT_ROOT_OFFSET];
  } else if (data.length === 36) {
    if (magic !== BITCOIN_OP_RETURN_PREFIX) return false;
    slots = [LEGACY_ROOT_OFFSET];
  } else {
    return false;
  }
  for (const off of slots) {
    if (bytesEqual(data.subarray(off, off + ROOT_LEN), root)) {
      return true;
    }
  }
  return false;
}

interface BitcoinTx {
  vout?: Array<{ scriptpubkey?: string; scriptpubkey_type?: string }>;
}

/**
 * Given an OP_RETURN scriptPubKey hex (starting `6a`), return the pushed data
 * payload hex (handling direct-length and OP_PUSHDATA1 prefixes). Returns
 * undefined if the script isn't a recognizable single-push OP_RETURN.
 */
export function extractOpReturnData(scriptHex: string): string | undefined {
  const bytes = hexToBytesLocal(scriptHex);
  if (bytes.length < 2 || bytes[0] !== 0x6a) return undefined;
  let i = 1;
  let len: number;
  const opcode = bytes[i++]!;
  if (opcode < 0x4c) {
    len = opcode; // direct length push (1..75 bytes)
  } else if (opcode === 0x4c) {
    // OP_PUSHDATA1: next byte is the length.
    if (i >= bytes.length) return undefined;
    len = bytes[i++]!;
  } else {
    return undefined; // larger pushes not used for a 36-byte payload
  }
  if (i + len > bytes.length) return undefined;
  return bytesToHex(bytes.subarray(i, i + len));
}

function hexToBytesLocal(hex: string): Uint8Array {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (clean.length % 2 !== 0) return new Uint8Array(0);
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

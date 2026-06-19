/**
 * `@ledgerproof/sdk/scitt` — real (not mock) SCITT Signed Statements, COSE
 * Receipts, and Transparent Statements, implementing the LedgerProof SCITT
 * Profile (DRAFT v0.1).
 *
 * Targeted Internet-Drafts (see {@link PROFILE}):
 *   - draft-ietf-scitt-architecture-22
 *   - draft-ietf-cose-merkle-tree-proofs-18 ("COSE Receipts")
 *   - RFC 9162 (Merkle), RFC 9052/9053 (COSE/EdDSA), RFC 8392 (CWT claims)
 *
 * Honest claim wording (spec §0): LedgerProof *implements the IETF SCITT
 * architecture (draft-22) with COSE Receipts (draft-18), additionally anchored
 * to Bitcoin* — never "SCITT RFC/standard/certified/compliant".
 *
 * Public surface:
 *   - encodeSignedStatement(content, opts)            → COSE_Sign1 Signed Statement (§2)
 *   - assembleReceipt(input, tsKeypair[, codePoints]) → detached COSE Receipt (§4)
 *   - attachReceipt(signedStatement, receipt)         → Transparent Statement (§5)
 *   - verifyTransparentStatement(ts, opts?)           → §7 verification result
 *   - CODE_POINTS                                      → provisional code points (§8)
 */

export {
  encodeSignedStatement,
  assembleReceipt,
  attachReceipt,
  statementLeafHash,
  emptyUnprotected,
  decodeStatement,
  assertSafeContentIntegers,
  MAX_SAFE_CONTENT_INT,
} from "./statement.js";

export {
  verifyTransparentStatement,
  extractReceipt,
  parseInclusionProof,
  checkBitcoinOpReturn,
  locateRootInOpReturn,
  extractOpReturnData,
  type ParsedInclusionProof,
} from "./verify.js";

export {
  CODE_POINTS,
  COSE_HEADER,
  CWT_CLAIM,
  VDP_INCLUSION_LABEL,
  TYP_SCITT_STATEMENT,
  DEFAULT_CONTENT_TYPE,
  BITCOIN_OP_RETURN_PREFIX,
  BITCOIN_OP_RETURN_PREFIX_LEN,
  ROOT_LEN,
  LEGACY_ROOT_OFFSET,
  SCITT_ROOT_OFFSET,
  DEFAULT_MEMPOOL_API,
  PROFILE,
  type CodePoints,
} from "./constants.js";

export type {
  SignedStatementOptions,
  ReceiptInput,
  VerifyOptions,
  VerifyResult,
} from "./types.js";

// Lower-level building blocks, exported for advanced callers and conformance
// tests (Merkle + COSE primitives). Stable but secondary to the high-level API.
export {
  hashLeaf,
  hashNode,
  merkleRoot,
  merkleRootFromLeafHashes,
  inclusionProof,
  inclusionProofFromLeafHashes,
  rootFromInclusionProof,
} from "./merkle.js";

export {
  signCoseSign1,
  decodeCoseSign1,
  verifyCoseSign1,
  sigStructure,
  ed25519Verify,
  ALG_EDDSA,
  COSE_SIGN1_TAG,
  type CoseSign1,
} from "./cose.js";

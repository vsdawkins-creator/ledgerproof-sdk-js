/**
 * Types for the SCITT receipt module.
 */

/** Options for {@link encodeSignedStatement}. */
export interface SignedStatementOptions {
  /** Signing key for the Issuer (the publisher). Reuses the SDK Keypair. */
  keypair: import("../keys.js").Keypair;
  /** CWT `iss` (claim 1): publisher identity — LEI, EUID, did:key, etc. (spec §2). */
  iss: string;
  /** CWT `sub` (claim 2): the artifact identifier / content hash (spec §2). */
  sub: string;
  /**
   * Issuer key id (COSE header 4). Bytes or a string (UTF-8 encoded). Defaults to
   * the keypair's public key bytes when omitted.
   */
  kid?: Uint8Array | string;
  /** Payload content type (COSE header 3). Defaults to the Article-50 media type. */
  contentType?: string;
}

/** Options for {@link assembleReceipt}. */
export interface ReceiptInput {
  /** The recomputed daily Merkle root — the 32-byte detached payload (spec §4). */
  merkleRoot: Uint8Array;
  /** Total number of leaves in the tree (RFC 9162 inclusion proof). */
  treeSize: number;
  /** Zero-based index of this statement's leaf. */
  leafIndex: number;
  /** Ordered sibling hashes, bottom-up (the RFC 9162 §2.1.3.1 audit path). */
  inclusionPath: Uint8Array[];
}

/** Options for {@link verifyTransparentStatement}. */
export interface VerifyOptions {
  /**
   * Issuer public key (32 bytes) to verify the Signed Statement signature
   * against. If omitted, the verifier reports `issuerSignatureValid: false`
   * unless a resolver is supplied.
   */
  issuerPublicKey?: Uint8Array;
  /**
   * Transparency-Service public key (32 bytes) to verify the Receipt signature.
   * Required for `receiptSignatureValid` to be true.
   */
  tsPublicKey?: Uint8Array;
  /**
   * Optional resolver from a COSE `kid` (header 4) to a 32-byte public key, used
   * when `issuerPublicKey` is not given directly.
   */
  resolveIssuerKey?: (kid: Uint8Array | undefined) => Uint8Array | undefined;
  /** Enable the spec §7 step 5 Bitcoin OP_RETURN witness check. */
  bitcoinCheck?: boolean;
  /** Bitcoin transaction id holding the OP_RETURN anchor (for `bitcoinCheck`). */
  txid?: string;
  /** Override the mempool-style explorer API base. */
  mempoolApiBase?: string;
  /** Injectable fetch (defaults to globalThis.fetch). */
  fetch?: typeof fetch;
}

/** Result of {@link verifyTransparentStatement} (spec §7). */
export interface VerifyResult {
  /** Step 1: Issuer COSE_Sign1 signature verified. */
  issuerSignatureValid: boolean;
  /** Step 3: the recomputed root matched the Receipt's detached payload. */
  inclusionProofValid: boolean;
  /** Step 4: Receipt COSE_Sign1 (TS key) signature verified over the root. */
  receiptSignatureValid: boolean;
  /** The Merkle root recomputed from the inclusion proof (hex). */
  recomputedRoot: string;
  /** Step 5 (bonus): the root was found in the Bitcoin OP_RETURN at `txid`. */
  bitcoinConfirmed?: boolean;
  /** Overall validity — true iff steps 1–4 all pass (spec §7). */
  valid: boolean;
}

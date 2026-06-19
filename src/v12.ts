/**
 * LPR 1.2 — Canonicality SDK methods (TypeScript).
 *
 * Forward-looking scaffolding. Implementations land per Tickets #10, #15,
 * #23, #30 in the v1.2 implementation plan.
 *
 * Spec reference: 04-lpr-spec/LPR-1.2-CANONICALITY-ANNEX.md
 */

// ──────────────────────────────────────────────────────────────────────
// §3 Lineage chains
// ──────────────────────────────────────────────────────────────────────

export interface ChainEntry {
  receiptId: string;
  issuerDid: string;
  lineagePosition: number;
  previousReceiptId: string | null;
  anchorStatus: string;
  anchorBlockHeight: number | null;
  identityVerificationLevel: string;
  supersedes: boolean;
  issuedAt: string; // ISO 8601
}

export interface ChainHistory {
  chainRootId: string;
  entries: ChainEntry[];
}

export interface PublishV1_1WithPredecessorOptions {
  content: Uint8Array;
  previousReceiptId: string;
  supersedes?: boolean;
}

export interface DelegateChainOptions {
  chainRootId: string;
  delegateDid: string;
  expiresAt: Date;
  supersessionAllowed?: boolean;
}

// ──────────────────────────────────────────────────────────────────────
// §4 Similarity
// ──────────────────────────────────────────────────────────────────────

export type SimilarityAlgorithm =
  | "tlsh-1"
  | "ssdeep-1"
  | "phash-1"
  | "audio-fp-1"
  | "video-kf-1"
  | "code-ast-1";

export interface SimilarityHit {
  receiptId: string;
  distance: number;
  similarity: number; // 0..1
  issuerDid: string;
  issuedAt: string;
  anchorStatus: string;
}

// ──────────────────────────────────────────────────────────────────────
// §5 Attestation
// ──────────────────────────────────────────────────────────────────────

export type AttestationType =
  | "co-sign"
  | "witness"
  | "notary"
  | "regulator"
  | "publisher"
  | "received";

export interface AttestReceiptOptions {
  targetReceiptId: string;
  attestationType: AttestationType;
  signerDid: string;
  signerKey: Uint8Array;
  statement?: string;
}

export interface Attestation {
  attestationId: string;
  targetReceiptId: string;
  attestorDid: string;
  attestationType: AttestationType;
  statement?: string;
  issuedAt: string;
  anchoredAt: string | null;
  revoked: boolean;
  identityVerificationLevel: string;
}

// ──────────────────────────────────────────────────────────────────────
// §6 Canonical Registry
// ──────────────────────────────────────────────────────────────────────

export interface ClaimCanonicalOptions {
  receiptId: string;
  statement: string;
  evidenceReceiptIds?: string[];
}

export interface DisputeClaimOptions {
  claimId: string;
  competingReceiptId: string;
  rationale: string;
  evidenceReceiptIds?: string[];
}

export interface CanonicalityState {
  receiptId: string;
  state:
    | "unclaimed"
    | "chain_member"
    | "canonical_claimed"
    | "canonical_uncontested"
    | "disputed"
    | "upheld_by_foundation"
    | "overturned_by_foundation"
    | "no_clear_canonical";
  canonicalClaimId: string | null;
  resolutionId: string | null;
  attestationCount: number;
}

// ──────────────────────────────────────────────────────────────────────
// Client extension (mixed in via prototype merge in v1.2 release)
// ──────────────────────────────────────────────────────────────────────

export interface LedgerProofClientV12 {
  // §3 Lineage chains
  publishV1_1WithPredecessor(opts: PublishV1_1WithPredecessorOptions): Promise<{ receiptId: string }>;
  getChainHistory(receiptId: string): Promise<ChainHistory>;
  getChainCanonicalHead(chainRootId: string): Promise<ChainEntry>;
  delegateChain(opts: DelegateChainOptions): Promise<{ delegationId: string }>;

  // §4 Similarity
  findSimilar(opts: {
    content?: Uint8Array;
    similarityHash?: { type: SimilarityAlgorithm; value: string };
    contentType: string;
    threshold?: number;
    limit?: number;
  }): Promise<SimilarityHit[]>;

  // §5 Attestation
  attestReceipt(opts: AttestReceiptOptions): Promise<{ attestationId: string }>;
  listAttestations(receiptId: string, opts?: { includeRevoked?: boolean }): Promise<Attestation[]>;
  revokeAttestation(opts: {
    attestationId: string;
    revokerDid: string;
    revokerKey: Uint8Array;
    rationale: string;
  }): Promise<{ revocationId: string }>;

  // §6 Canonical claims
  claimCanonical(opts: ClaimCanonicalOptions): Promise<{ claimId: string }>;
  disputeCanonicalClaim(opts: DisputeClaimOptions): Promise<{ disputeId: string }>;
  getCanonicality(receiptId: string): Promise<CanonicalityState>;
}

// ──────────────────────────────────────────────────────────────────────
// Errors mirroring Rust LPR12XX_ codes
// ──────────────────────────────────────────────────────────────────────

export class CanonicalityError extends Error {
  code: string = "";
}

export class ChainError extends CanonicalityError {}
export class SimilarityError extends CanonicalityError {}
export class AttestationError extends CanonicalityError {}
export class CanonicalRegistryError extends CanonicalityError {}

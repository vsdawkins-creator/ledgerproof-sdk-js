/**
 * SCITT profile constants and code points.
 *
 * Per spec §8, the COSE Receipts code points (receipts / vds / vdp) are still
 * "requested assignment" in draft-ietf-cose-merkle-tree-proofs-18 and MAY change
 * at IANA. They are therefore expressed as a single mutable {@link CODE_POINTS}
 * object so an IANA reassignment is a one-line edit, never a code change spread
 * across the module.
 *
 * Targeted draft versions (spec header):
 *   - draft-ietf-scitt-architecture-22         (2025-10-10)
 *   - draft-ietf-cose-merkle-tree-proofs-18    (2025-12-02) — "COSE Receipts"
 *   - RFC 9162 (Merkle), RFC 9052/9053 (COSE/EdDSA), RFC 8392 (CWT claims)
 */

/**
 * Provisional COSE Receipts code points (spec §8). Mutable so an IANA change is
 * a one-line edit. `vdsAlg` is the verifiable-data-structure algorithm value
 * (1 = RFC9162_SHA256).
 */
export const CODE_POINTS = {
  /** Unprotected header label carrying attached Receipts (spec §5). */
  receipts: 394,
  /** Protected header label: verifiable data structure id (spec §4). */
  vds: 395,
  /** Unprotected header label: verifiable data structure proofs (spec §4). */
  vdp: 396,
  /** VDS value: RFC9162_SHA256 (spec §3). */
  vdsAlg: 1,
} as const;

/** Mutable type mirror of CODE_POINTS for callers that override at runtime. */
export type CodePoints = {
  receipts: number;
  vds: number;
  vdp: number;
  vdsAlg: number;
};

// ── COSE / CWT standard header labels (RFC 9052 §3.1, RFC 8392 §3) ────────────

/** COSE protected/unprotected header labels used by this profile. */
export const COSE_HEADER = {
  /** alg (RFC 9052 §3.1) */
  alg: 1,
  /** content type (RFC 9052 §3.1) */
  contentType: 3,
  /** key id (RFC 9052 §3.1) */
  kid: 4,
  /** CWT Claims in COSE header (draft-ietf-cose-cwt-claims-in-headers) */
  cwtClaims: 15,
  /** typ — declared type of the COSE object (draft / cose-receipts §4.4) */
  typ: 16,
} as const;

/** CWT claim keys (RFC 8392 §3). */
export const CWT_CLAIM = {
  /** iss (issuer) */
  iss: 1,
  /** sub (subject) */
  sub: 2,
} as const;

/** Label inside the vdp map (396) that holds the inclusion-proof array. */
export const VDP_INCLUSION_LABEL = -1;

// ── Profile string constants ─────────────────────────────────────────────────

/** typ value binding the Signed Statement to this profile (spec §2). */
export const TYP_SCITT_STATEMENT = "application/scitt-statement+cose";

/** Default content_type for the Article-50 payload (spec §2). */
export const DEFAULT_CONTENT_TYPE = "application/ai-article-50+json";

/** Targeted Internet-Draft versions, emitted for forward-compat / provenance. */
export const PROFILE = {
  scittArchitecture: "draft-ietf-scitt-architecture-22",
  coseReceipts: "draft-ietf-cose-merkle-tree-proofs-18",
} as const;

// ── Bitcoin anchor (spec §6) ─────────────────────────────────────────────────

/**
 * 4-byte magic prefixing the root(s) in the Bitcoin OP_RETURN (spec §6).
 *
 * Known on-wire layouts sharing this prefix (the verifier accepts all of them):
 *   - Deployed anchor worker:   `LPR1 || seq_start(4) || seq_end(4) || root`
 *                                                               (4 + 8 + 32 = 44 B) — root at offset 12
 *   - Legacy / SCITT-disabled:  `LPR1 || root`                  (4 + 32  = 36 B) — root at offset 4
 *   - Combined (SCITT enabled): `LPR1 || legacy_root || scitt_root`
 *                                                               (4 + 32 + 32 = 68 B) — roots at offset 4 and 36
 * The 44-byte form is what the production anchor worker actually writes (it adds
 * the sequence range covered by the batch). The combined layout commits BOTH the
 * legacy daily root and the SCITT daily root in a SINGLE transaction, well within
 * the 80-byte OP_RETURN limit. See the *_ROOT_OFFSET constants below.
 *
 * The legacy `QE20` magic (pre-v1 forensic anchors) shares the 44-byte layout and
 * is accepted alongside `LPR1` per LPR-VER-001's OP_RETURN tag policy.
 */
export const BITCOIN_OP_RETURN_PREFIX = "LPR1";

/**
 * Legacy 4-byte magic for pre-v1 forensic anchors (May 2026). Shares the 44-byte
 * `MAGIC || seq_start || seq_end || root` layout with {@link BITCOIN_OP_RETURN_PREFIX};
 * verifiers accept both so the full on-chain history verifies (LPR-VER-001).
 */
export const LEGACY_ANCHOR_PREFIX = "QE20";

/** Byte length of the {@link BITCOIN_OP_RETURN_PREFIX} ("LPR1"). */
export const BITCOIN_OP_RETURN_PREFIX_LEN = 4;

/** Byte length of a SHA-256 root. */
export const ROOT_LEN = 32;

/**
 * Offset of the legacy root within the OP_RETURN data (both layouts): right
 * after the 4-byte prefix.
 */
export const LEGACY_ROOT_OFFSET = BITCOIN_OP_RETURN_PREFIX_LEN; // 4

/**
 * Offset of the SCITT root within the COMBINED OP_RETURN data: after the prefix
 * and the 32-byte legacy root.
 */
export const SCITT_ROOT_OFFSET = BITCOIN_OP_RETURN_PREFIX_LEN + ROOT_LEN; // 36

/**
 * Offset of the root within the DEPLOYED 44-byte anchor-worker layout
 * (`MAGIC || seq_start(4) || seq_end(4) || root`): after the prefix and the two
 * 4-byte big-endian sequence bounds.
 */
export const ANCHOR_SEQ_ROOT_OFFSET = BITCOIN_OP_RETURN_PREFIX_LEN + 8; // 12

/** Default public Bitcoin explorer API for the bonus witness check (spec §7.5). */
export const DEFAULT_MEMPOOL_API = "https://mempool.space/api";

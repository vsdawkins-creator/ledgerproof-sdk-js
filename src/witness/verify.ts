/**
 * LedgerProof Witness — independent verifier (spec §6).
 *
 * This is the "verify, don't trust" path. Every check that matters can be made
 * WITHOUT trusting LedgerProof:
 *   1. the publisher's signature over the canonical envelope
 *   2. the publisher's key, resolved from THEIR identity (not our database)
 *   3. (optional) the artifact matches content_hash
 *   4. the Bitcoin lower time bound
 *   5. the chain link (prev_hash == entry_hash(previous))
 *   6. the Bitcoin anchor (finality) — wired once the anchor pipeline emits roots
 *
 * Spec: 04-lpr-spec/LedgerProof-Witness-Envelope-v1.md §6
 */
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils";
import {
  GENESIS_PREV_HASH,
  entryHash,
  verifyEnvelope,
  type WitnessEnvelope,
} from "./envelope.js";

export interface WitnessEntry {
  envelope: WitnessEnvelope;
  client_signature: string;
  public_key: string;
  entry_hash?: string;
  anchor_status?: string;
  anchor_id?: string;
}

export interface VerifyOptions {
  /** Base URL to fetch prior entries for the chain-link check. */
  apiBase?: string;
  fetch?: typeof fetch;
  /** If given, confirm SHA-256(artifact) === envelope.content_hash. */
  artifact?: Uint8Array | string;
  /** Default true. Resolve the publisher key from identity_resolver. */
  checkIdentity?: boolean;
  /** Default true. Confirm bitcoin.block_hash is real at bitcoin.height. */
  checkBitcoinLowerBound?: boolean;
  /** Default true (needs apiBase). Confirm the prev_hash chain link. */
  checkChain?: boolean;
}

export interface VerifyResult {
  ok: boolean;
  signatureValid: boolean;
  /** null = not checked. */
  identityResolved: boolean | null;
  contentMatched: boolean | null;
  bitcoinLowerBoundValid: boolean | null;
  chainLinkValid: boolean | null;
  /** null = pending (entry not yet Bitcoin-anchored, or anchor check not run). */
  anchorConfirmed: boolean | null;
  errors: string[];
}

/** Verify a witnessed entry per spec §6. None of 1–5 trusts LedgerProof. */
export async function verifyWitnessEntry(
  entry: WitnessEntry,
  opts: VerifyOptions = {}
): Promise<VerifyResult> {
  const fetchImpl = opts.fetch ?? fetch;
  const env = entry.envelope;
  const errors: string[] = [];
  const result: VerifyResult = {
    ok: false,
    signatureValid: false,
    identityResolved: null,
    contentMatched: null,
    bitcoinLowerBoundValid: null,
    chainLinkValid: null,
    anchorConfirmed: null,
    errors,
  };

  // 1. Publisher signature over the canonical envelope.
  result.signatureValid = await verifyEnvelope(env, entry.client_signature, entry.public_key);
  if (!result.signatureValid) errors.push("publisher signature does not verify over the envelope");

  // 2. Identity: the key is published at the publisher's OWN identity_resolver.
  if (opts.checkIdentity !== false) {
    try {
      const keys = await resolvePublisherKeys(env.identity_resolver, fetchImpl);
      result.identityResolved = keys.includes(entry.public_key.toLowerCase());
      if (!result.identityResolved) {
        errors.push("public_key is not published at identity_resolver");
      }
    } catch (e) {
      result.identityResolved = false;
      errors.push(`identity resolution failed: ${(e as Error).message}`);
    }
  }

  // 3. Content binding (optional).
  if (opts.artifact !== undefined) {
    const h = bytesToHex(
      sha256(typeof opts.artifact === "string" ? utf8ToBytes(opts.artifact) : opts.artifact)
    );
    result.contentMatched = h === env.content_hash;
    if (!result.contentMatched) errors.push("artifact does not match content_hash");
  }

  // 4. Bitcoin lower time bound — the entry could not predate this block.
  if (opts.checkBitcoinLowerBound !== false) {
    try {
      const realHash = await fetchBlockHash(env.bitcoin.height, fetchImpl);
      result.bitcoinLowerBoundValid = realHash === env.bitcoin.block_hash;
      if (!result.bitcoinLowerBoundValid) {
        errors.push("bitcoin.block_hash is not the real hash at bitcoin.height");
      }
    } catch (e) {
      result.bitcoinLowerBoundValid = false;
      errors.push(`bitcoin lower-bound check failed: ${(e as Error).message}`);
    }
  }

  // 5. Chain link — prev_hash equals entry_hash(previous), or genesis at sequence 0.
  if (opts.checkChain !== false) {
    try {
      if (env.sequence === 0) {
        result.chainLinkValid = env.prev_hash === GENESIS_PREV_HASH;
        if (!result.chainLinkValid) errors.push("genesis entry (sequence 0) must have an all-zero prev_hash");
      } else if (opts.apiBase) {
        const prev = await fetchEntry(opts.apiBase, env.sequence - 1, fetchImpl);
        result.chainLinkValid = entryHash(prev.envelope) === env.prev_hash;
        if (!result.chainLinkValid) errors.push("prev_hash does not match the previous entry's hash");
      } else {
        result.chainLinkValid = null; // cannot walk the chain without apiBase
      }
    } catch (e) {
      result.chainLinkValid = false;
      errors.push(`chain-link check failed: ${(e as Error).message}`);
    }
  }

  // 6. Bitcoin anchor (finality): implemented once the witness anchor pipeline
  //    emits Merkle roots to OP_RETURN. Until then, anchorConfirmed stays null
  //    (pending) rather than asserting a finality we cannot yet prove.

  result.ok =
    result.signatureValid &&
    result.identityResolved !== false &&
    result.contentMatched !== false &&
    result.bitcoinLowerBoundValid !== false &&
    result.chainLinkValid !== false;
  return result;
}

/** Fetch the public keys published at a publisher's identity_resolver. */
export async function resolvePublisherKeys(
  identityResolver: string,
  fetchImpl: typeof fetch = fetch
): Promise<string[]> {
  const res = await fetchImpl(identityResolver);
  if (!res.ok) throw new Error(`identity_resolver returned ${res.status}`);
  const doc = (await res.json()) as { keys?: { public_key_hex?: string }[] };
  return (doc.keys ?? [])
    .map((k) => (k.public_key_hex ?? "").toLowerCase())
    .filter((k) => /^[0-9a-f]{64}$/.test(k));
}

async function fetchBlockHash(height: number, fetchImpl: typeof fetch): Promise<string> {
  const res = await fetchImpl(`https://mempool.space/api/block-height/${height}`);
  if (!res.ok) throw new Error(`mempool.space block-height ${height} returned ${res.status}`);
  return (await res.text()).trim();
}

async function fetchEntry(
  apiBase: string,
  sequence: number,
  fetchImpl: typeof fetch
): Promise<WitnessEntry> {
  const res = await fetchImpl(`${apiBase.replace(/\/+$/, "")}/v1/entries/${sequence}`);
  if (!res.ok) throw new Error(`entry ${sequence} returned ${res.status}`);
  return (await res.json()) as WitnessEntry;
}

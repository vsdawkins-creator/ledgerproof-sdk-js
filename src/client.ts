/**
 * LedgerProof client — the TypeScript counterpart to the Python `LedgerProof`.
 *
 * Same protocol, same canonical JSON, same verification semantics. Works on
 * Node, Bun, Deno, Cloudflare Workers, Vercel Edge, and modern browsers.
 */

import { artifactHash, canonicalJson, sha256Hex } from "./canonical.js";
import {
  ChainError,
  ConfigurationError,
  GDPRSafetyError,
  LedgerProofError,
  ValidationError,
} from "./errors.js";
import { Keypair } from "./keys.js";
import { Transport } from "./transport.js";
import type {
  AiArticle50Content,
  ContentCategory,
  EntryResponse,
  GenerationType,
  LedgerProofConfig,
  PerceptualHash,
  Receipt,
} from "./types.js";

export const DEFAULT_API_BASE = "https://api.ledgerproofhq.io";
const GENESIS_PREV_HASH = "0".repeat(64);
const TIP_PROBE_LIMIT = 10_000;

const EMAIL_REGEX = /[\w.+-]+@[\w-]+\.[\w.-]+/;
const SHA256_HEX_REGEX = /^[0-9a-f]{64}$/i;

export interface PublishArticle50Options {
  /**
   * The raw artifact, hashed locally with SHA-256. Optional ONLY when
   * `precomputedArtifactHash` is supplied (privacy path — see below); otherwise
   * required. If both are given, the bytes are used solely to derive
   * `artifact_bytes` and are NOT re-hashed.
   */
  artifact?: string | Uint8Array;
  /**
   * Precomputed SHA-256 (64 hex chars) of the artifact. When provided, the SDK
   * skips local hashing and sets `content.artifact_hash` to this value
   * verbatim, so the raw artifact never has to be handed to the SDK. Intended
   * for privacy over remote transports: the caller hashes locally and passes
   * only the digest. Everything downstream (canonical JSON, Ed25519 signing,
   * publish) is identical to the raw path. Mutually compatible with `artifact`
   * (used only for `artifactBytes`); mutually exclusive in practice with
   * relying on the SDK to hash.
   */
  precomputedArtifactHash?: string;
  artifactContentType: string;
  /**
   * Byte length of the artifact for `content.artifact_bytes`. Required (or
   * derivable from `artifact`) on the precomputed-hash path since the raw
   * bytes may be unavailable. If omitted and `artifact` is present, it is
   * derived from the artifact's byte length.
   */
  artifactBytes?: number;
  aiSystemId: string;
  deployerName: string;
  contentCategory: ContentCategory;
  aiSystemVersion?: string;
  supervisoryAuthority?: string;
  generationType?: GenerationType;
  sourceContentHash?: string;
  perceptualHash?: PerceptualHash;
  transparencyMarker?: string;
  isPublicInterest?: boolean;
  enforcementDate?: string;
  profileVersion?: string;
}

export class LedgerProof {
  private readonly publisherId: string;
  private readonly deployerCountry: string;
  private readonly apiKey: string;
  private readonly apiBase: string;
  private readonly keyId: string;
  private readonly keypair: Keypair;
  private readonly transport: Transport;
  private keyRegistered = false;

  constructor(config: LedgerProofConfig) {
    if (config.publisherId.includes("@")) {
      throw new GDPRSafetyError(
        "publisher_id must be a legal-entity identifier (LEI/EUID/VAT/DID), not an email"
      );
    }
    this.publisherId = config.publisherId;
    this.deployerCountry = config.deployerCountry.toUpperCase();
    const apiKey =
      config.apiKey ??
      (typeof process !== "undefined" ? process.env?.LEDGERPROOF_API_KEY : undefined);
    if (!apiKey) {
      throw new ConfigurationError(
        "API key required: pass config.apiKey or set LEDGERPROOF_API_KEY"
      );
    }
    this.apiKey = apiKey;
    this.apiBase =
      config.apiBase ??
      (typeof process !== "undefined" ? process.env?.LEDGERPROOF_API_BASE : undefined) ??
      DEFAULT_API_BASE;
    this.keyId =
      config.keyId ??
      (typeof process !== "undefined" ? process.env?.LEDGERPROOF_KEY_ID : undefined) ??
      "default";

    const signingHex =
      config.signingKeyHex ??
      (typeof process !== "undefined"
        ? process.env?.LEDGERPROOF_SIGNING_KEY_HEX
        : undefined);
    this.keypair = signingHex ? Keypair.fromHex(signingHex) : Keypair.generate();

    this.transport = new Transport({
      apiBase: this.apiBase,
      apiKey: this.apiKey,
      publisherId: this.publisherId,
    });
  }

  /**
   * Issue an `ai/article-50/v1` receipt.
   *
   * Two paths, producing byte-for-byte identical signed records for the same
   * artifact:
   *   1. Raw path: pass `artifact` (string or bytes); the SDK hashes it locally
   *      with SHA-256 and the bytes never leave the machine.
   *   2. Precomputed-hash path: pass `precomputedArtifactHash` (the SHA-256 you
   *      computed yourself); the SDK skips local hashing and uses that digest as
   *      `content.artifact_hash`. The raw artifact is never required — useful for
   *      privacy over remote transports. Supply `artifactBytes` (or `artifact`,
   *      used only to derive the byte length) for `content.artifact_bytes`.
   *
   * Canonicalization, Ed25519 signing, and publish are identical on both paths.
   */
  async publishAiArticle50(opts: PublishArticle50Options): Promise<Receipt> {
    if (EMAIL_REGEX.test(opts.deployerName)) {
      throw new GDPRSafetyError("deployerName looks like an email — use a legal name");
    }

    // Derive the raw bytes once (if present) — used for hashing and/or length.
    const rawBytes =
      opts.artifact === undefined
        ? undefined
        : typeof opts.artifact === "string"
          ? new TextEncoder().encode(opts.artifact)
          : opts.artifact;

    // ── Resolve artifact_hash: precomputed digest takes precedence ────────────
    let aHash: string;
    if (opts.precomputedArtifactHash !== undefined) {
      const provided = opts.precomputedArtifactHash.trim();
      if (!SHA256_HEX_REGEX.test(provided)) {
        throw new ValidationError(
          "precomputedArtifactHash must be a 64-character hex SHA-256 digest"
        );
      }
      // Normalize to lowercase hex so the canonical record is stable regardless
      // of the caller's casing — matches what artifactHash() would have emitted.
      aHash = provided.toLowerCase();
    } else {
      if (rawBytes === undefined) {
        throw new ValidationError(
          "publishAiArticle50 requires either `artifact` (hashed locally) or " +
            "`precomputedArtifactHash` (a SHA-256 you computed yourself)"
        );
      }
      aHash = artifactHash(rawBytes);
    }

    // ── Resolve artifact_bytes ────────────────────────────────────────────────
    // Prefer an explicit count; else derive from raw bytes when available. On
    // the precomputed path with no length given, the field is omitted (it is
    // optional in the v1.1 content and stripped below if undefined).
    let artifactByteCount: number | undefined;
    if (opts.artifactBytes !== undefined) {
      if (!Number.isInteger(opts.artifactBytes) || opts.artifactBytes < 0) {
        throw new ValidationError("artifactBytes must be a non-negative integer");
      }
      artifactByteCount = opts.artifactBytes;
    } else if (rawBytes !== undefined) {
      artifactByteCount = rawBytes.length;
    } else {
      artifactByteCount = undefined;
    }

    const content: Record<string, unknown> = {
      ai_system_id: opts.aiSystemId,
      ai_system_version: opts.aiSystemVersion,
      deployer_id: this.publisherId,
      deployer_name: opts.deployerName,
      deployer_country: this.deployerCountry,
      content_category: opts.contentCategory,
      artifact_hash: aHash,
      artifact_content_type: opts.artifactContentType,
      artifact_bytes: artifactByteCount,
      supervisory_authority: opts.supervisoryAuthority,
      generation_type: opts.generationType,
      source_content_hash: opts.sourceContentHash,
      perceptual_hash: opts.perceptualHash,
      transparency_marker: opts.transparencyMarker ?? "LPR-EU-AI-ACT-50",
      is_public_interest: opts.isPublicInterest,
      enforcement_date: opts.enforcementDate ?? "2026-08-02",
      profile_version: opts.profileVersion ?? "EU-AI-ACT-50-v1.1",
    };
    // Strip undefined keys so they don't appear in canonical JSON.
    const cleaned = Object.fromEntries(
      Object.entries(content).filter(([, v]) => v !== undefined && v !== null)
    );

    return this.publish("ai/article-50/v1", cleaned);
  }

  /** Fetch an entry from the public verifier endpoint. No auth required. */
  async verify(sequence: number): Promise<EntryResponse> {
    return this.transport.request<EntryResponse>({
      method: "GET",
      path: `/v1/entries/${sequence}`,
      authenticated: false,
    });
  }

  /** Look up receipts by SHA-256 of artifact content. Unauthenticated. */
  async lookupByContentHash(contentHash: string): Promise<EntryResponse[]> {
    const data = await this.transport.request<{ matches: EntryResponse[] }>({
      method: "GET",
      path: `/v1/receipts/by-content-hash/${contentHash}`,
      authenticated: false,
    });
    return data?.matches ?? [];
  }

  private async publish(
    contentType: string,
    contentDict: Record<string, unknown>
  ): Promise<Receipt> {
    await this.ensureKeyRegistered();

    let lastError: Error | undefined;
    for (let attempt = 0; attempt < 3; attempt++) {
      const { sequence, prevHash } = await this.discoverChainTip();
      const payload = this.buildPublishPayload(contentDict, contentType, sequence, prevHash);
      try {
        const response = await this.transport.request<{ sequence: number; entry_hash: string; receipt_id?: number }>({
          method: "POST",
          path: "/v1/publish",
          json: payload,
        });
        return {
          sequence: response.sequence,
          entry_hash: response.entry_hash,
          receipt_id: response.receipt_id,
          verify_url: `${this.apiBase}/v1/verify/${response.sequence}`,
        };
      } catch (exc) {
        lastError = exc as Error;
        if (
          exc instanceof ValidationError &&
          attempt < 2 &&
          (exc.message || "").toLowerCase().includes("sequence")
        ) {
          await new Promise((r) => setTimeout(r, 200 * (attempt + 1)));
          continue;
        }
        throw exc;
      }
    }
    throw new ChainError(`could not publish after 3 attempts: ${lastError?.message}`);
  }

  private buildPublishPayload(
    contentDict: Record<string, unknown>,
    contentType: string,
    sequence: number,
    prevHash: string
  ): Record<string, unknown> {
    const contentCanonical = canonicalJson(contentDict);
    const cHash = sha256Hex(contentCanonical);
    const entryTimestamp = isoNowMillis();

    const entryObj = {
      content: contentDict,
      content_hash: cHash,
      content_type: contentType,
      entry_timestamp: entryTimestamp,
      key_id: this.keyId,
      prev_hash: prevHash,
      protocol_version: "ledgerproof/1.0",
      publisher_id: this.publisherId,
      sequence,
    };
    const entryCanonical = canonicalJson(entryObj);
    const eHash = sha256Hex(entryCanonical);

    // Sign the RAW 32 bytes of the entry hash, not the hex string.
    const entryHashBytes = hexToBytes(eHash);
    const signature = this.keypair.sign(entryHashBytes);
    const signatureHex = bytesToHex(signature);

    return {
      publisher_id: this.publisherId,
      key_id: this.keyId,
      prev_hash: prevHash,
      entry_hash: eHash,
      signature: signatureHex,
      protocol_version: "ledgerproof/1.0",
      content_type: contentType,
      content_hash: cHash,
      content: contentDict,
      entry_json_canonical: entryCanonical,
      entry_timestamp: entryTimestamp,
    };
  }

  private async ensureKeyRegistered(): Promise<void> {
    if (this.keyRegistered) return;
    try {
      await this.transport.request({
        method: "POST",
        path: "/v1/keys",
        json: {
          key_id: this.keyId,
          verifying_key_b64: this.keypair.publicKeyBase64(),
        },
      });
    } catch (exc) {
      // Server's ON CONFLICT DO NOTHING means re-registration is fine.
      if (!(exc instanceof LedgerProofError)) throw exc;
    }
    this.keyRegistered = true;
  }

  private async discoverChainTip(): Promise<{ sequence: number; prevHash: string }> {
    let probe = 0;
    while (probe <= TIP_PROBE_LIMIT) {
      try {
        await this.transport.request({
          method: "GET",
          path: `/v1/entries/${probe}`,
          authenticated: false,
        });
        probe++;
      } catch (exc) {
        const status =
          exc instanceof Object && "statusCode" in exc ? (exc as { statusCode: number }).statusCode : undefined;
        if (status === 404) {
          if (probe === 0) return { sequence: 0, prevHash: GENESIS_PREV_HASH };
          const prev = await this.transport.request<EntryResponse>({
            method: "GET",
            path: `/v1/entries/${probe - 1}`,
            authenticated: false,
          });
          return { sequence: probe, prevHash: prev.entry_hash };
        }
        throw exc;
      }
    }
    throw new ChainError(`chain tip not found within ${TIP_PROBE_LIMIT} probes`);
  }
}

// ── Helpers ────────────────────────────────────────────────────────────────

function isoNowMillis(): string {
  const d = new Date();
  return d.toISOString().replace(/\.\d{3}Z$/, (m) => m); // ensure .xxxZ
}

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

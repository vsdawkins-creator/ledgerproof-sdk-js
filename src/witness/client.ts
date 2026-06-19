/**
 * LedgerProof Witness SDK — the publisher (signer) side.
 *
 * The publisher signs each envelope locally with their own Ed25519 key; that key
 * NEVER leaves the caller. LedgerProof only witnesses + anchors. Anyone verifies a
 * receipt against the key the publisher publishes at `identityResolver` — with no
 * trust in LedgerProof.
 *
 * Spec: 04-lpr-spec/LedgerProof-Witness-Envelope-v1.md
 */
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils";
import { ed25519 } from "@noble/curves/ed25519";
import {
  ENVELOPE_TYP,
  ENVELOPE_VERSION,
  signEnvelope,
  type WitnessEnvelope,
} from "./envelope.js";

const DEFAULT_API_BASE = "https://api-eu.ledgerproofhq.io";
const HEX64 = /^[0-9a-f]{64}$/;

export interface BitcoinTip {
  height: number;
  block_hash: string;
}
export type BitcoinSource = () => Promise<BitcoinTip>;

export interface WitnessClientConfig {
  /** Bearer API key for POST /v1/publish (account / abuse control). */
  apiKey: string;
  /** 32-byte Ed25519 seed (publisher key — stays local, never sent). */
  privateKeyHex: string;
  /** Stable publisher identifier (also the subject of the witness statement). */
  publisherId: string;
  /** https URL or did:web where this publisher's public key is published. */
  identityResolver: string;
  apiBase?: string;
  bitcoinSource?: BitcoinSource;
  fetch?: typeof fetch;
}

export interface PublishResult {
  sequence: number;
  entry_hash: string;
  witness_leaf: string;
  anchor_status: string;
  server_time?: string;
  verify_url?: string;
}

/** SHA-256 of an artifact (bytes or UTF-8 string) as lowercase hex. */
export function sha256Hex(data: Uint8Array | string): string {
  return bytesToHex(sha256(typeof data === "string" ? utf8ToBytes(data) : data));
}

/** Default lower-time-bound source: mempool.space current chain tip. */
export function mempoolBitcoinSource(fetchImpl: typeof fetch = fetch): BitcoinSource {
  return async () => {
    const [h, hh] = await Promise.all([
      fetchImpl("https://mempool.space/api/blocks/tip/height"),
      fetchImpl("https://mempool.space/api/blocks/tip/hash"),
    ]);
    const height = parseInt((await h.text()).trim(), 10);
    const block_hash = (await hh.text()).trim();
    if (!Number.isInteger(height) || !HEX64.test(block_hash)) {
      throw new Error("could not fetch a valid Bitcoin tip from mempool.space");
    }
    return { height, block_hash };
  };
}

/** Generate a fresh publisher keypair. The private hex stays with you forever. */
export async function generateWitnessKeypair(): Promise<{ privateKeyHex: string; publicKeyHex: string }> {
  const priv = ed25519.utils.randomPrivateKey();
  const pub = ed25519.getPublicKey(priv);
  return { privateKeyHex: bytesToHex(priv), publicKeyHex: bytesToHex(pub) };
}

export interface IdentityKey {
  kid: string;
  alg: "Ed25519";
  public_key_hex: string;
  valid_from: string;
  valid_to: string | null;
}

/**
 * Build the document to host at your `identityResolver`
 * (e.g. https://you.example/.well-known/ledgerproof-key.json). Verifiers fetch
 * this to confirm a witnessed entry's key is really yours — no trust in LedgerProof.
 */
export function buildIdentityDocument(
  publisherId: string,
  publicKeyHex: string,
  opts: { kid?: string; validFrom?: string } = {}
): { publisher_id: string; keys: IdentityKey[] } {
  return {
    publisher_id: publisherId,
    keys: [
      {
        kid: opts.kid ?? "key-1",
        alg: "Ed25519",
        public_key_hex: publicKeyHex,
        valid_from: opts.validFrom ?? new Date().toISOString(),
        valid_to: null,
      },
    ],
  };
}

export class WitnessClient {
  private readonly apiBase: string;
  private readonly apiKey: string;
  private readonly privateKeyHex: string;
  private readonly publisherId: string;
  private readonly identityResolver: string;
  private readonly bitcoinSource: BitcoinSource;
  private readonly fetchImpl: typeof fetch;
  private publicKeyHexCache?: string;

  constructor(cfg: WitnessClientConfig) {
    if (!HEX64.test(cfg.privateKeyHex)) {
      throw new Error("privateKeyHex must be a 32-byte Ed25519 seed (64 lowercase hex)");
    }
    this.apiBase = (cfg.apiBase ?? DEFAULT_API_BASE).replace(/\/+$/, "");
    this.apiKey = cfg.apiKey;
    this.privateKeyHex = cfg.privateKeyHex;
    this.publisherId = cfg.publisherId;
    this.identityResolver = cfg.identityResolver;
    this.fetchImpl = cfg.fetch ?? fetch;
    this.bitcoinSource = cfg.bitcoinSource ?? mempoolBitcoinSource(this.fetchImpl);
  }

  async publicKeyHex(): Promise<string> {
    if (!this.publicKeyHexCache) {
      this.publicKeyHexCache = bytesToHex(ed25519.getPublicKey(hexToBytes(this.privateKeyHex)));
    }
    return this.publicKeyHexCache;
  }

  /** Hash an artifact locally and publish a witnessed, publisher-signed envelope. */
  async publish(artifact: Uint8Array | string): Promise<PublishResult> {
    return this.publishContentHash(sha256Hex(artifact));
  }

  /** Publish a precomputed content hash (when you hashed the artifact yourself). */
  async publishContentHash(contentHash: string): Promise<PublishResult> {
    if (!HEX64.test(contentHash)) throw new Error("contentHash must be 64 lowercase hex");
    const bitcoin = await this.bitcoinSource();
    const public_key = await this.publicKeyHex();

    let lastErr: Error | undefined;
    for (let attempt = 0; attempt < 4; attempt++) {
      const tip = await this.tip();
      const env: WitnessEnvelope = {
        v: ENVELOPE_VERSION,
        typ: ENVELOPE_TYP,
        content_hash: contentHash,
        publisher_id: this.publisherId,
        identity_resolver: this.identityResolver,
        sequence: tip.next_sequence,
        prev_hash: tip.entry_hash,
        bitcoin,
        client_timestamp: new Date().toISOString().replace(/\.\d+Z$/, "Z"),
      };
      const signature = await signEnvelope(env, this.privateKeyHex);
      const res = await this.fetchImpl(`${this.apiBase}/v1/publish`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${this.apiKey}`,
        },
        body: JSON.stringify({ envelope: env, signature, public_key }),
      });
      if (res.status === 201) return (await res.json()) as PublishResult;
      if (res.status === 409) {
        // Another publisher extended the log first — re-read the tip and retry.
        lastErr = new Error(await safeText(res));
        continue;
      }
      throw new Error(`publish failed (${res.status}): ${await safeText(res)}`);
    }
    throw new Error(`publish failed after retries: ${lastErr?.message ?? "sequence contention"}`);
  }

  /** Current chain tip — the sequence + prev_hash a new entry must extend. */
  async tip(): Promise<{ sequence: number; entry_hash: string; next_sequence: number }> {
    const res = await this.fetchImpl(`${this.apiBase}/v1/tip`);
    if (!res.ok) throw new Error(`tip failed (${res.status})`);
    return (await res.json()) as { sequence: number; entry_hash: string; next_sequence: number };
  }

  /** Fetch a witnessed entry by sequence (public, no auth). */
  async getEntry(sequence: number): Promise<unknown> {
    const res = await this.fetchImpl(`${this.apiBase}/v1/entries/${sequence}`);
    if (res.status === 404) throw new Error(`entry ${sequence} not found`);
    if (!res.ok) throw new Error(`getEntry failed (${res.status})`);
    return res.json();
  }
}

async function safeText(res: Response): Promise<string> {
  try {
    return await res.text();
  } catch {
    return "";
  }
}

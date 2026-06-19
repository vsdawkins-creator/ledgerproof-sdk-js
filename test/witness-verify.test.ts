import { describe, expect, it } from "vitest";
import { generateWitnessKeypair, sha256Hex } from "../src/witness/client.js";
import {
  ENVELOPE_TYP,
  ENVELOPE_VERSION,
  signEnvelope,
  type WitnessEnvelope,
} from "../src/witness/envelope.js";
import { verifyWitnessEntry } from "../src/witness/verify.js";

const BLOCK_HASH = "0000000000000000000000000000000000000000000000000000000000abcdef";

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

/** A mock world that resolves the publisher's keys and the Bitcoin block hash. */
function mockFetch(publishedKeys: string[]): typeof fetch {
  return (async (url: string) => {
    const u = String(url);
    if (u.includes("/.well-known/")) {
      return json({
        publisher_id: "did:web:acme.example",
        keys: publishedKeys.map((k) => ({
          kid: "k",
          alg: "Ed25519",
          public_key_hex: k,
          valid_from: "2026-01-01T00:00:00Z",
          valid_to: null,
        })),
      });
    }
    if (u.includes("mempool.space/api/block-height/")) {
      return new Response(BLOCK_HASH, { status: 200 });
    }
    throw new Error(`unexpected fetch: ${u}`);
  }) as unknown as typeof fetch;
}

async function makeEntry(
  privateKeyHex: string,
  publicKeyHex: string,
  overrides: Partial<WitnessEnvelope> = {}
) {
  const env: WitnessEnvelope = {
    v: ENVELOPE_VERSION,
    typ: ENVELOPE_TYP,
    content_hash: "aa".repeat(32),
    publisher_id: "did:web:acme.example",
    identity_resolver: "https://acme.example/.well-known/ledgerproof-key.json",
    sequence: 0,
    prev_hash: "0".repeat(64),
    bitcoin: { height: 842113, block_hash: BLOCK_HASH },
    client_timestamp: "2026-06-17T21:00:00Z",
    ...overrides,
  };
  const sig = await signEnvelope(env, privateKeyHex);
  return { envelope: env, client_signature: sig, public_key: publicKeyHex };
}

describe("witness verifier (verify, don't trust)", () => {
  it("verifies a valid entry against the publisher's OWN published key", async () => {
    const { privateKeyHex, publicKeyHex } = await generateWitnessKeypair();
    const entry = await makeEntry(privateKeyHex, publicKeyHex);
    const r = await verifyWitnessEntry(entry, { fetch: mockFetch([publicKeyHex]) });
    expect(r.ok).toBe(true);
    expect(r.signatureValid).toBe(true);
    expect(r.identityResolved).toBe(true);
    expect(r.bitcoinLowerBoundValid).toBe(true);
    expect(r.chainLinkValid).toBe(true); // genesis: prev_hash is all zeros
  });

  it("fails when the artifact was tampered (the signature breaks)", async () => {
    const { privateKeyHex, publicKeyHex } = await generateWitnessKeypair();
    const entry = await makeEntry(privateKeyHex, publicKeyHex);
    entry.envelope.content_hash = "cc".repeat(32); // tamper AFTER signing
    const r = await verifyWitnessEntry(entry, { fetch: mockFetch([publicKeyHex]) });
    expect(r.ok).toBe(false);
    expect(r.signatureValid).toBe(false);
  });

  it("fails when the key is NOT published at the publisher's identity", async () => {
    const { privateKeyHex, publicKeyHex } = await generateWitnessKeypair();
    const entry = await makeEntry(privateKeyHex, publicKeyHex);
    const r = await verifyWitnessEntry(entry, { fetch: mockFetch(["ff".repeat(32)]) });
    expect(r.ok).toBe(false);
    expect(r.identityResolved).toBe(false);
  });

  it("fails when the Bitcoin lower bound is wrong", async () => {
    const { privateKeyHex, publicKeyHex } = await generateWitnessKeypair();
    const entry = await makeEntry(privateKeyHex, publicKeyHex, {
      bitcoin: { height: 842113, block_hash: "11".repeat(32) },
    });
    const r = await verifyWitnessEntry(entry, { fetch: mockFetch([publicKeyHex]) });
    expect(r.ok).toBe(false);
    expect(r.bitcoinLowerBoundValid).toBe(false);
  });

  it("confirms content when the artifact matches content_hash", async () => {
    const { privateKeyHex, publicKeyHex } = await generateWitnessKeypair();
    const entry = await makeEntry(privateKeyHex, publicKeyHex, { content_hash: sha256Hex("hello") });
    const r = await verifyWitnessEntry(entry, { fetch: mockFetch([publicKeyHex]), artifact: "hello" });
    expect(r.contentMatched).toBe(true);
    expect(r.ok).toBe(true);
  });
});

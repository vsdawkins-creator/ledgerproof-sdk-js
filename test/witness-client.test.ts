import { describe, expect, it } from "vitest";
import {
  WitnessClient,
  buildIdentityDocument,
  generateWitnessKeypair,
  sha256Hex,
} from "../src/witness/index.js";
import { entryHash, verifyEnvelope, type WitnessEnvelope } from "../src/witness/envelope.js";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

describe("witness client", () => {
  it("publishes locally-signed envelopes a witness accepts, and chains them", async () => {
    const { privateKeyHex, publicKeyHex } = await generateWitnessKeypair();
    const chain: { entry_hash: string }[] = [];

    // A mock witness that verifies the publisher signature and enforces the chain
    // EXACTLY as the backend does — so a green test means the SDK produces
    // backend-acceptable envelopes.
    const fetchImpl = (async (url: string, init?: RequestInit) => {
      const u = String(url);
      if (u.endsWith("/v1/tip")) {
        const seq = chain.length - 1;
        return jsonResponse({
          sequence: seq,
          entry_hash: chain.length ? chain[chain.length - 1]!.entry_hash : "0".repeat(64),
          next_sequence: seq + 1,
        });
      }
      if (u.endsWith("/v1/publish")) {
        const body = JSON.parse(String(init!.body));
        const env = body.envelope as WitnessEnvelope;
        if (!(await verifyEnvelope(env, body.signature, body.public_key))) {
          return new Response("bad signature", { status: 400 });
        }
        const expectedSeq = chain.length;
        const expectedPrev = chain.length ? chain[chain.length - 1]!.entry_hash : "0".repeat(64);
        if (env.sequence !== expectedSeq || env.prev_hash !== expectedPrev) {
          return new Response("sequence conflict", { status: 409 });
        }
        const eh = entryHash(env);
        chain.push({ entry_hash: eh });
        return jsonResponse(
          { sequence: env.sequence, entry_hash: eh, witness_leaf: "00".repeat(32), anchor_status: "PENDING" },
          201
        );
      }
      throw new Error(`unexpected fetch: ${u}`);
    }) as unknown as typeof fetch;

    const client = new WitnessClient({
      apiKey: "test",
      privateKeyHex,
      publisherId: "did:web:acme.example",
      identityResolver: "https://acme.example/.well-known/ledgerproof-key.json",
      bitcoinSource: async () => ({ height: 842113, block_hash: "bb".repeat(32) }),
      fetch: fetchImpl,
    });

    const r0 = await client.publish("hello world");
    expect(r0.sequence).toBe(0);
    expect(r0.entry_hash).toMatch(/^[0-9a-f]{64}$/);

    const r1 = await client.publishContentHash(sha256Hex("second artifact"));
    expect(r1.sequence).toBe(1); // correctly chained onto the first

    // The identity document carries the same key a third-party verifier resolves.
    const doc = buildIdentityDocument("did:web:acme.example", publicKeyHex);
    expect(doc.keys[0]!.public_key_hex).toBe(publicKeyHex);
    expect(doc.keys[0]!.alg).toBe("Ed25519");
  });
});

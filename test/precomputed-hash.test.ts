/**
 * Precomputed-hash entrypoint test suite.
 *
 * Proves the privacy-oriented `precomputedArtifactHash` path of
 * `publishAiArticle50` produces the EXACT same signed record (entry hash,
 * Ed25519 signature, content, content hash, canonical entry JSON) as the raw
 * path for the same artifact bytes — i.e. handing the SDK a SHA-256 you
 * computed yourself is cryptographically indistinguishable from letting it hash
 * the raw bytes, while keeping the artifact off the machine/wire.
 *
 * The HTTP layer is stubbed via a mock `globalThis.fetch` that:
 *   - returns 404 for GET /v1/entries/0  → chain tip = sequence 0, genesis prev
 *   - returns 200 for POST /v1/keys      → key registration succeeds
 *   - captures the POST /v1/publish body → the signed record under test
 * The system clock is frozen so `entry_timestamp` is identical across calls.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex } from "@noble/hashes/utils";

import { LedgerProof } from "../src/client.js";
import { artifactHash } from "../src/canonical.js";
import { ValidationError } from "../src/errors.js";

// Fixed signing seed so both clients sign with the identical Ed25519 key.
const SIGNING_KEY_HEX =
  "3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a";

const BASE_META = {
  artifactContentType: "text/plain",
  aiSystemId: "openai/gpt-4o",
  deployerName: "Acme Corp",
  contentCategory: "SYNTHETIC_TEXT" as const,
  aiSystemVersion: "2024-08",
  supervisoryAuthority: "BNetzA",
  generationType: "FULLY_GENERATED" as const,
  isPublicInterest: false,
};

/** A captured POST /v1/publish payload (the signed record we compare). */
type PublishBody = Record<string, unknown>;

/**
 * Install a deterministic fetch mock. Records every POST /v1/publish body into
 * `captured`. Genesis chain tip (entry 0 → 404) keeps sequence + prev_hash
 * constant across calls so the only run-to-run variable would be the clock,
 * which the caller freezes with fake timers.
 */
function installFetchMock(captured: PublishBody[]): void {
  const mock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input.toString();
    const method = (init?.method ?? "GET").toUpperCase();

    if (method === "GET" && url.endsWith("/v1/entries/0")) {
      return new Response("not found", { status: 404 });
    }
    if (method === "POST" && url.endsWith("/v1/keys")) {
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }
    if (method === "POST" && url.endsWith("/v1/publish")) {
      const body = JSON.parse(String(init?.body ?? "{}")) as PublishBody;
      captured.push(body);
      return new Response(
        JSON.stringify({
          sequence: body["sequence"] ?? 0,
          entry_hash: body["entry_hash"],
          receipt_id: 1,
        }),
        { status: 200, headers: { "content-type": "application/json" } }
      );
    }
    return new Response("unexpected request: " + method + " " + url, {
      status: 500,
    });
  });
  vi.stubGlobal("fetch", mock);
}

function newClient(): LedgerProof {
  return new LedgerProof({
    publisherId: "LEI:529900T8BM49AURSDO55",
    deployerCountry: "DE",
    apiKey: "test-key",
    apiBase: "https://api.test.invalid",
    keyId: "default",
    signingKeyHex: SIGNING_KEY_HEX,
  });
}

describe("publishAiArticle50 precomputed-hash entrypoint", () => {
  beforeEach(() => {
    // Freeze the clock so entry_timestamp is identical for every publish.
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-06-17T12:00:00.000Z"));
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("yields a byte-identical signed record vs. the raw path (string artifact)", async () => {
    const artifact = "The quick brown fox jumps over the lazy dog.";
    const precomputed = artifactHash(artifact); // what the caller computes locally

    const captured: PublishBody[] = [];
    installFetchMock(captured);

    // Path 1: raw artifact (SDK hashes locally).
    await newClient().publishAiArticle50({ artifact, ...BASE_META });

    // Path 2: precomputed SHA-256 (+ explicit byte length, since no raw bytes).
    await newClient().publishAiArticle50({
      precomputedArtifactHash: precomputed,
      artifactBytes: new TextEncoder().encode(artifact).length,
      ...BASE_META,
    });

    expect(captured).toHaveLength(2);
    const [raw, pre] = captured;

    // The whole signed record is identical: same content, same content_hash,
    // same canonical entry JSON, same entry_hash, same Ed25519 signature.
    expect(pre).toEqual(raw);
    // And spell out the security-critical fields explicitly.
    expect(pre!["entry_hash"]).toBe(raw!["entry_hash"]);
    expect(pre!["signature"]).toBe(raw!["signature"]);
    expect(pre!["content_hash"]).toBe(raw!["content_hash"]);
    expect(pre!["entry_json_canonical"]).toBe(raw!["entry_json_canonical"]);
    // The content carries the SHA-256 we expect, and it matches a local hash.
    const content = pre!["content"] as Record<string, unknown>;
    expect(content["artifact_hash"]).toBe(precomputed);
    expect(content["artifact_hash"]).toBe(bytesToHex(sha256(artifact)));
    expect(content["artifact_bytes"]).toBe(
      new TextEncoder().encode(artifact).length
    );
  });

  it("yields a byte-identical signed record vs. the raw path (binary artifact)", async () => {
    const artifact = new Uint8Array([0x00, 0x01, 0xff, 0x7f, 0x80, 0xfe, 0x42]);
    const precomputed = artifactHash(artifact);

    const captured: PublishBody[] = [];
    installFetchMock(captured);

    await newClient().publishAiArticle50({
      artifact,
      ...BASE_META,
      artifactContentType: "application/octet-stream",
    });
    await newClient().publishAiArticle50({
      precomputedArtifactHash: precomputed,
      artifactBytes: artifact.length,
      ...BASE_META,
      artifactContentType: "application/octet-stream",
    });

    expect(captured).toHaveLength(2);
    expect(captured[1]).toEqual(captured[0]);
    expect(captured[1]!["entry_hash"]).toBe(captured[0]!["entry_hash"]);
    expect(captured[1]!["signature"]).toBe(captured[0]!["signature"]);
  });

  it("derives artifact_bytes from a raw artifact passed alongside the digest", async () => {
    // When both are present, bytes feed only the length; the hash is NOT recomputed.
    const artifact = "byte-length derivation check";
    const precomputed = artifactHash(artifact);

    const captured: PublishBody[] = [];
    installFetchMock(captured);

    await newClient().publishAiArticle50({ artifact, ...BASE_META });
    await newClient().publishAiArticle50({
      artifact, // present, but only used for the byte count on this path
      precomputedArtifactHash: precomputed,
      ...BASE_META,
    });

    expect(captured[1]).toEqual(captured[0]);
  });

  it("normalizes uppercase precomputed hex to match the lowercase raw record", async () => {
    const artifact = "case-normalization";
    const lower = artifactHash(artifact);
    const upper = lower.toUpperCase();

    const captured: PublishBody[] = [];
    installFetchMock(captured);

    await newClient().publishAiArticle50({ artifact, ...BASE_META });
    await newClient().publishAiArticle50({
      precomputedArtifactHash: upper,
      artifactBytes: new TextEncoder().encode(artifact).length,
      ...BASE_META,
    });

    // Lowercased digest → identical canonical record + signature as the raw path.
    expect(captured[1]).toEqual(captured[0]);
    const content = captured[1]!["content"] as Record<string, unknown>;
    expect(content["artifact_hash"]).toBe(lower);
  });

  it("rejects a malformed precomputed hash (not 64 hex chars)", async () => {
    const captured: PublishBody[] = [];
    installFetchMock(captured);
    await expect(
      newClient().publishAiArticle50({
        precomputedArtifactHash: "deadbeef", // too short
        artifactBytes: 10,
        ...BASE_META,
      })
    ).rejects.toBeInstanceOf(ValidationError);
    // Nothing was published.
    expect(captured).toHaveLength(0);
  });

  it("rejects when neither artifact nor precomputed hash is provided", async () => {
    const captured: PublishBody[] = [];
    installFetchMock(captured);
    await expect(
      newClient().publishAiArticle50({
        // no artifact, no precomputedArtifactHash
        ...BASE_META,
      })
    ).rejects.toBeInstanceOf(ValidationError);
    expect(captured).toHaveLength(0);
  });
});

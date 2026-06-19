/**
 * Browser-side verifier — read-only utilities for verifying LPR receipts.
 *
 * Designed to ship inside browser extensions, in-page widgets, and the
 * Provenance Search public web tool. < 30 KB gzipped. No private-key
 * operations. No publishing. Just `verify()` and hash computation.
 */

import { sha256Hex } from "./canonical.js";
import type { EntryResponse } from "./types.js";

export interface VerifierOptions {
  apiBase?: string;
  fetch?: typeof fetch;
}

export const DEFAULT_API_BASE = "https://api-eu.ledgerproofhq.io";

/** Verify a receipt by sequence number. Returns the entry, or null if 404. */
export async function verifyReceipt(
  sequence: number,
  options: VerifierOptions = {}
): Promise<EntryResponse | null> {
  const apiBase = (options.apiBase ?? DEFAULT_API_BASE).replace(/\/$/, "");
  const fetchImpl = options.fetch ?? globalThis.fetch;
  const response = await fetchImpl(`${apiBase}/v1/entries/${sequence}`);
  if (response.status === 404) return null;
  if (!response.ok) {
    throw new Error(`verify failed: ${response.status} ${response.statusText}`);
  }
  return (await response.json()) as EntryResponse;
}

/**
 * Look up receipts matching a content hash (SHA-256 of the artifact).
 * Returns an empty array if no matches.
 */
export async function lookupByContentHash(
  contentHash: string,
  options: VerifierOptions = {}
): Promise<EntryResponse[]> {
  const apiBase = (options.apiBase ?? DEFAULT_API_BASE).replace(/\/$/, "");
  const fetchImpl = options.fetch ?? globalThis.fetch;
  const response = await fetchImpl(`${apiBase}/v1/receipts/by-content-hash/${contentHash}`);
  if (response.status === 404) return [];
  if (!response.ok) {
    throw new Error(`lookup failed: ${response.status}`);
  }
  const data = (await response.json()) as { matches?: EntryResponse[] };
  return data?.matches ?? [];
}

/**
 * Hash an artifact (a string or a `Blob`/`ArrayBuffer`/`Uint8Array`) using
 * the Web Crypto API where available, falling back to @noble/hashes.
 */
export async function hashArtifact(
  artifact: string | ArrayBuffer | Uint8Array | Blob
): Promise<string> {
  let bytes: Uint8Array;
  if (typeof artifact === "string") {
    bytes = new TextEncoder().encode(artifact);
  } else if (artifact instanceof Blob) {
    bytes = new Uint8Array(await artifact.arrayBuffer());
  } else if (artifact instanceof ArrayBuffer) {
    bytes = new Uint8Array(artifact);
  } else {
    bytes = artifact;
  }
  // Use Web Crypto if available — it's faster on big artifacts.
  if (globalThis.crypto?.subtle?.digest) {
    // Ensure we hand subtle.digest an ArrayBuffer-backed view (not SharedArrayBuffer).
    const buf = bytes.buffer instanceof ArrayBuffer
      ? bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength)
      : new Uint8Array(bytes).buffer;
    const digest = await globalThis.crypto.subtle.digest("SHA-256", buf);
    return Array.from(new Uint8Array(digest))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }
  // Fallback: synchronous noble implementation.
  return sha256Hex(bytes);
}

/**
 * Convenience: scan a page for any element with a `data-lpr-receipt` attribute
 * and return verification status for each.
 *
 * Intended for browser extensions and in-page widgets that surface a badge
 * next to AI-attested content.
 */
export async function scanPageForReceipts(
  options: VerifierOptions = {}
): Promise<Array<{ element: Element; entry: EntryResponse | null }>> {
  if (typeof document === "undefined") return [];
  const elements = Array.from(document.querySelectorAll("[data-lpr-receipt]"));
  return Promise.all(
    elements.map(async (element) => {
      const seqAttr = element.getAttribute("data-lpr-receipt");
      const sequence = seqAttr ? parseInt(seqAttr, 10) : Number.NaN;
      if (!Number.isFinite(sequence)) {
        return { element, entry: null };
      }
      const entry = await verifyReceipt(sequence, options).catch(() => null);
      return { element, entry };
    })
  );
}

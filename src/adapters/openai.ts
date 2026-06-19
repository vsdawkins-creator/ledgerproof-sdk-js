/**
 * OpenAI Node SDK adapter — same Stripe-play pattern as Python.
 *
 * Patches `client.chat.completions.create` (and the async variant). Returns
 * the same response object the user expected, with a `_ledgerproofPromise`
 * field they can await if they want the receipt synchronously.
 */

import { LedgerProof } from "../client.js";
import { LedgerProofError } from "../errors.js";
import type { Receipt } from "../types.js";

interface AttachOptions {
  publisherId: string;
  deployerCountry: string;
  deployerName: string;
  aiSystemId?: string;
  apiKey?: string;
  apiBase?: string;
  isPublicInterest?: boolean;
}

const PATCHED = new WeakMap<
  object,
  {
    original: Function;
    completions: { create: Function };
  }
>();

/**
 * Patch the OpenAI client's `chat.completions.create` to auto-issue receipts.
 * Idempotent: calling twice on the same client is a no-op.
 */
export function attach(client: any, options: AttachOptions): void {
  if (!client?.chat?.completions?.create) {
    throw new LedgerProofError(
      "target does not look like an OpenAI client; pass an openai.OpenAI() instance"
    );
  }
  if (PATCHED.has(client)) return;

  const lp = new LedgerProof({
    publisherId: options.publisherId,
    deployerCountry: options.deployerCountry,
    ...(options.apiKey !== undefined && { apiKey: options.apiKey }),
    ...(options.apiBase !== undefined && { apiBase: options.apiBase }),
  });

  const original = client.chat.completions.create.bind(client.chat.completions);
  const wrapped = async (...args: unknown[]) => {
    const result = await original(...args);
    const callArgs = (args[0] ?? {}) as Record<string, unknown>;
    const isStream = Boolean(callArgs.stream);
    if (isStream) {
      return wrapAsyncStream(result, lp, options, callArgs);
    }
    const text = extractText(result);
    if (text) {
      attachReceiptPromise(result, lp, options, callArgs, text);
    }
    return result;
  };

  client.chat.completions.create = wrapped;
  PATCHED.set(client, { original, completions: client.chat.completions });
}

/** Reverse the patch. Idempotent. */
export function detach(client: any): void {
  const entry = PATCHED.get(client);
  if (!entry) return;
  entry.completions.create = entry.original;
  PATCHED.delete(client);
}

// ── Internals ──────────────────────────────────────────────────────────────

function attachReceiptPromise(
  response: any,
  lp: LedgerProof,
  options: AttachOptions,
  callArgs: Record<string, unknown>,
  text: string
): void {
  const promise = issueSafe(lp, options, callArgs, text);
  try {
    response._ledgerproofPromise = promise;
  } catch {
    // Some response types are frozen — silently skip.
  }
}

async function issueSafe(
  lp: LedgerProof,
  options: AttachOptions,
  callArgs: Record<string, unknown>,
  text: string
): Promise<Receipt | null> {
  try {
    const model = typeof callArgs.model === "string" ? callArgs.model : "unknown";
    const aiSystemId = options.aiSystemId ?? `openai/${model}`;
    return await lp.publishAiArticle50({
      artifact: text,
      artifactContentType: "text/plain",
      aiSystemId,
      deployerName: options.deployerName,
      contentCategory: "SYNTHETIC_TEXT",
      generationType: "FULLY_GENERATED",
      ...(options.isPublicInterest !== undefined && { isPublicInterest: options.isPublicInterest }),
    });
  } catch {
    return null; // fail open
  }
}

function extractText(response: any): string {
  try {
    const choice = response?.choices?.[0];
    const content = choice?.message?.content;
    if (typeof content === "string") return content;
    if (Array.isArray(content)) {
      return content
        .filter((p: any) => p?.type === "text")
        .map((p: any) => p.text ?? "")
        .join("");
    }
    return "";
  } catch {
    return "";
  }
}

function extractTextFromChunk(chunk: any): string {
  try {
    return chunk?.choices?.[0]?.delta?.content ?? "";
  } catch {
    return "";
  }
}

function wrapAsyncStream(
  stream: any,
  lp: LedgerProof,
  options: AttachOptions,
  callArgs: Record<string, unknown>
): any {
  const chunks: string[] = [];
  const originalIterator = stream[Symbol.asyncIterator].bind(stream);
  return new Proxy(stream, {
    get(target, prop) {
      if (prop === Symbol.asyncIterator) {
        return () => ({
          async next() {
            const it = originalIterator();
            const result = await it.next();
            if (result.done) {
              const full = chunks.join("");
              if (full) {
                attachReceiptPromise(stream, lp, options, callArgs, full);
              }
              return result;
            }
            const text = extractTextFromChunk(result.value);
            if (text) chunks.push(text);
            return result;
          },
        });
      }
      return target[prop];
    },
  });
}

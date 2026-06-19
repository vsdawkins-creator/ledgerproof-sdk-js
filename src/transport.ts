/**
 * HTTP transport. Uses the platform's `fetch` so it works on Node 18+, Bun,
 * Deno, Cloudflare Workers, Vercel Edge, and browsers — no polyfills.
 */

import {
  APIError,
  AuthenticationError,
  ConfigurationError,
  NetworkError,
  RateLimitError,
  ValidationError,
} from "./errors.js";

const DEFAULT_MAX_RETRIES = 3;
const DEFAULT_TIMEOUT_MS = 30_000;
const RETRYABLE_STATUS = new Set([429, 502, 503, 504]);

export interface TransportOptions {
  apiBase: string;
  apiKey?: string;
  publisherId?: string;
  maxRetries?: number;
  timeoutMs?: number;
  userAgent?: string;
  fetch?: typeof fetch;
}

export interface RequestOptions {
  method: "GET" | "POST" | "DELETE";
  path: string;
  json?: unknown;
  headers?: Record<string, string>;
  authenticated?: boolean;
}

export class Transport {
  private readonly apiBase: string;
  private readonly apiKey?: string;
  private readonly publisherId?: string;
  private readonly maxRetries: number;
  private readonly timeoutMs: number;
  private readonly userAgent: string;
  private readonly fetchImpl: typeof fetch;

  constructor(options: TransportOptions) {
    this.apiBase = options.apiBase.replace(/\/$/, "");
    this.apiKey = options.apiKey;
    this.publisherId = options.publisherId;
    this.maxRetries = options.maxRetries ?? DEFAULT_MAX_RETRIES;
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.userAgent =
      options.userAgent ?? "ledgerproof-typescript/1.0.0 (web-fetch)";
    this.fetchImpl = options.fetch ?? globalThis.fetch;
    if (!this.fetchImpl) {
      throw new ConfigurationError(
        "no fetch implementation available; pass options.fetch or upgrade to Node 18+"
      );
    }
  }

  async request<T = unknown>(opts: RequestOptions): Promise<T> {
    const url = `${this.apiBase}${opts.path}`;
    const headers: Record<string, string> = {
      "User-Agent": this.userAgent,
      "Content-Type": "application/json",
      ...(opts.headers ?? {}),
    };
    if (opts.authenticated !== false) {
      if (!this.apiKey || !this.publisherId) {
        throw new ConfigurationError(
          "API key and publisherId required for authenticated requests"
        );
      }
      headers["X-Api-Key"] = this.apiKey;
      headers["X-Publisher-Id"] = this.publisherId;
    }

    const body = opts.json !== undefined ? JSON.stringify(opts.json) : undefined;

    let lastError: Error | undefined;
    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), this.timeoutMs);

      let response: Response;
      try {
        response = await this.fetchImpl(url, {
          method: opts.method,
          headers,
          body,
          signal: controller.signal,
        });
      } catch (exc) {
        clearTimeout(timeoutId);
        lastError = exc as Error;
        if (attempt < this.maxRetries) {
          await sleep(backoffDelay(attempt, null));
          continue;
        }
        throw new NetworkError(`network error contacting ${url}: ${lastError.message}`, {
          url,
        });
      }
      clearTimeout(timeoutId);

      if (response.ok) {
        if (response.status === 204) return undefined as T;
        return (await response.json()) as T;
      }

      if (RETRYABLE_STATUS.has(response.status) && attempt < this.maxRetries) {
        const retryAfter = response.headers.get("retry-after");
        await sleep(backoffDelay(attempt, retryAfter));
        continue;
      }

      await raiseForResponse(response, url);
    }

    throw new NetworkError(`exhausted retries to ${url}`, {
      cause: lastError?.message,
    });
  }
}

async function raiseForResponse(response: Response, url: string): Promise<never> {
  const requestId = response.headers.get("x-request-id") ?? undefined;
  const bodyText = await response.text().catch(() => "");
  let message: string = bodyText;
  let errors: Array<Record<string, unknown>> = [];
  try {
    const parsed = JSON.parse(bodyText);
    if (parsed?.error?.message) message = parsed.error.message;
    if (Array.isArray(parsed?.errors)) errors = parsed.errors;
  } catch {
    // body not JSON
  }
  const ctx = { status: response.status, requestId, url };

  if (response.status === 401 || response.status === 403) {
    throw new AuthenticationError(message, ctx);
  }
  if (response.status === 429) {
    const retryAfter = response.headers.get("retry-after");
    const retryAfterSeconds = retryAfter ? Number(retryAfter) : undefined;
    throw new RateLimitError(message, {
      retryAfterSeconds: Number.isFinite(retryAfterSeconds) ? retryAfterSeconds : undefined,
      context: ctx,
    });
  }
  if (response.status === 400 || response.status === 422) {
    throw new ValidationError(message, { errors, context: ctx });
  }
  throw new APIError(message, {
    statusCode: response.status,
    body: bodyText,
    requestId,
    context: ctx,
  });
}

function backoffDelay(attempt: number, retryAfter: string | null): number {
  if (retryAfter) {
    const sec = Number(retryAfter);
    if (Number.isFinite(sec)) return Math.min(sec * 1000, 30_000);
  }
  return Math.min(250 * 2 ** attempt, 30_000);
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

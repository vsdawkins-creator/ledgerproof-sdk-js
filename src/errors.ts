/**
 * Exception hierarchy. Mirrors the Python SDK exactly.
 */

export class LedgerProofError extends Error {
  readonly context: Record<string, unknown>;
  constructor(message: string, context: Record<string, unknown> = {}) {
    super(message);
    this.name = "LedgerProofError";
    this.context = context;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class ConfigurationError extends LedgerProofError {
  override readonly name = "ConfigurationError";
}

export class AuthenticationError extends LedgerProofError {
  override readonly name = "AuthenticationError";
}

export class RateLimitError extends LedgerProofError {
  override readonly name = "RateLimitError";
  readonly retryAfterSeconds: number | undefined;
  constructor(
    message: string,
    options: { retryAfterSeconds?: number; context?: Record<string, unknown> } = {}
  ) {
    super(message, options.context);
    this.retryAfterSeconds = options.retryAfterSeconds;
  }
}

export class APIError extends LedgerProofError {
  override readonly name = "APIError";
  readonly statusCode: number;
  readonly body: string | undefined;
  readonly requestId: string | undefined;
  constructor(
    message: string,
    options: {
      statusCode: number;
      body?: string;
      requestId?: string;
      context?: Record<string, unknown>;
    }
  ) {
    super(message, options.context);
    this.statusCode = options.statusCode;
    this.body = options.body;
    this.requestId = options.requestId;
  }
}

export class NetworkError extends LedgerProofError {
  override readonly name = "NetworkError";
}

export class ValidationError extends LedgerProofError {
  override readonly name = "ValidationError";
  readonly errors: Array<Record<string, unknown>>;
  constructor(
    message: string,
    options: { errors?: Array<Record<string, unknown>>; context?: Record<string, unknown> } = {}
  ) {
    super(message, options.context);
    this.errors = options.errors ?? [];
  }
}

export class GDPRSafetyError extends LedgerProofError {
  override readonly name = "GDPRSafetyError";
}

export class KeyManagementError extends LedgerProofError {
  override readonly name = "KeyManagementError";
}

export class ChainError extends LedgerProofError {
  override readonly name = "ChainError";
}

/**
 * @ledgerproof/sdk — EU AI Act Article 50 compliance for TypeScript.
 *
 * Three-line install (Vercel AI SDK example)::
 *
 *   import { LedgerProof } from "@ledgerproof/sdk";
 *   const lp = new LedgerProof({ publisherId: "LEI:...", deployerCountry: "DE" });
 *   const receipt = await lp.publishAiArticle50({
 *     artifact: "...", artifactContentType: "text/plain",
 *     aiSystemId: "openai/gpt-4o", deployerName: "Acme Corp",
 *     contentCategory: "SYNTHETIC_TEXT",
 *   });
 *
 * For OpenAI Node clients, use the attach() pattern::
 *
 *   import OpenAI from "openai";
 *   import { attach } from "@ledgerproof/sdk/adapters/openai";
 *   const client = new OpenAI();
 *   attach(client, { publisherId: "LEI:...", deployerCountry: "DE", deployerName: "Acme Corp" });
 *   // Every chat completion now auto-issues an LPR receipt.
 *
 * For browser/edge verification, import from `@ledgerproof/sdk/verifier`.
 */

export { LedgerProof, DEFAULT_API_BASE } from "./client.js";
export { Keypair } from "./keys.js";
export { Transport } from "./transport.js";
export {
  canonicalJson,
  sha256Hex,
  contentHash,
  entryHash,
  artifactHash,
} from "./canonical.js";
export type {
  AiArticle50Content,
  AiHumanReviewContent,
  AiChatbotSessionContent,
  ContentCategory,
  GenerationType,
  ReviewType,
  NotificationMethod,
  PerceptualHash,
  Receipt,
  EntryResponse,
  LedgerProofConfig,
} from "./types.js";
export {
  LedgerProofError,
  ConfigurationError,
  AuthenticationError,
  RateLimitError,
  APIError,
  NetworkError,
  ValidationError,
  GDPRSafetyError,
  KeyManagementError,
  ChainError,
} from "./errors.js";

// ── SCITT receipts (additive, opt-in) ───────────────────────────────────────
// Real COSE_Sign1 Signed Statements + COSE Receipts + Transparent Statements
// per the LedgerProof SCITT Profile. Also importable as "@ledgerproof/sdk/scitt".
export {
  encodeSignedStatement,
  assembleReceipt,
  attachReceipt,
  verifyTransparentStatement,
  CODE_POINTS,
} from "./scitt/index.js";
export type {
  SignedStatementOptions,
  ReceiptInput,
  VerifyOptions,
  VerifyResult,
} from "./scitt/index.js";

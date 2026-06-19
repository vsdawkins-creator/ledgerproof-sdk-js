/**
 * LPR v1.1 protocol types.
 *
 * Mirrors the Rust `AiArticle50Content`, `AiHumanReviewContent`, and
 * `AiChatbotSessionContent` structs. Field names and enum string values
 * preserved exactly so JSON round-trips through the Rust server.
 */

export type ContentCategory =
  | "SYNTHETIC_TEXT"
  | "SYNTHETIC_IMAGE"
  | "SYNTHETIC_AUDIO"
  | "SYNTHETIC_VIDEO"
  | "DEEPFAKE"
  | "SYNTHETIC_MULTIMODAL"
  | "AI_ASSISTED_DOCUMENT";

export type GenerationType =
  | "FULLY_GENERATED"
  | "AI_MANIPULATED"
  | "AI_ASSISTED";

export type ReviewType =
  | "SUBSTANTIAL_EDIT"
  | "FACTUAL_REVIEW"
  | "APPROVAL_ONLY";

export type NotificationMethod =
  | "INITIAL_BANNER"
  | "INLINE_MESSAGE"
  | "AUDIO_ANNOUNCEMENT"
  | "PRE_PROMPT_DISCLOSURE";

export interface PerceptualHash {
  algorithm: string;
  value: string;
  bits: number;
}

export interface AiArticle50Content {
  // v1.0 base
  ai_system_id: string;
  ai_system_version?: string;
  deployer_id: string;
  deployer_name: string;
  deployer_country: string;
  content_category: ContentCategory;
  artifact_hash: string;
  artifact_content_type: string;
  artifact_bytes: number;
  supervisory_authority?: string;
  // v1.1 additions
  generation_type?: GenerationType;
  source_content_hash?: string;
  perceptual_hash?: PerceptualHash;
  transparency_marker?: string;
  is_public_interest?: boolean;
  enforcement_date?: string;
  profile_version?: string;
}

export interface AiHumanReviewContent {
  original_entry_hash: string;
  original_sequence: number;
  reviewer_role: string;
  reviewer_country: string;
  review_timestamp: string;
  review_type: ReviewType;
  reviewed_artifact_hash: string;
  is_public_interest: boolean;
  review_rationale?: string;
}

export interface AiChatbotSessionContent {
  session_id_hash: string;
  ai_system_id: string;
  deployer_id: string;
  deployer_name: string;
  deployer_country: string;
  notification_timestamp: string;
  notification_method: NotificationMethod;
  notification_text_hash: string;
  obvious_exemption_claimed: boolean;
}

export interface Receipt {
  sequence: number;
  entry_hash: string;
  receipt_id?: number;
  /** Convenience: where to verify this receipt without authentication. */
  verify_url: string;
}

export interface EntryResponse {
  sequence: number;
  publisher_id: string;
  key_id: string;
  prev_hash: string;
  entry_hash: string;
  signature: string;
  protocol_version?: string;
  content_type: string;
  content_hash: string;
  content?: Record<string, unknown> | null;
  entry_json_canonical?: string | null;
  entry_timestamp: string;
  created_at: string;
  deleted_at?: string | null;
  deleted_reason?: string | null;
}

export interface LedgerProofConfig {
  publisherId: string;
  deployerCountry: string;
  apiKey?: string;
  apiBase?: string;
  keyId?: string;
  signingKeyHex?: string;
}

/**
 * Canonical JSON serialization and SHA-256 hashing.
 *
 * Output MUST match the Rust server's serde_json::to_string() byte-for-byte
 * or signatures fail. Same algorithm as the Python SDK's canonical.py.
 */

import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex } from "@noble/hashes/utils";

/**
 * Serialize `obj` to compact, deterministically sorted, ASCII-safe JSON.
 *
 * - Keys sorted lexicographically at every depth
 * - Compact separators (no whitespace)
 * - Non-ASCII characters escaped as \uXXXX
 * - Throws if obj contains NaN, Infinity, or -Infinity
 */
export function canonicalJson(obj: unknown): string {
  return stringify(obj);
}

function stringify(value: unknown): string {
  if (value === null || value === undefined) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new Error("canonical JSON does not support NaN or Infinity");
    }
    // Use JSON.stringify for number formatting (handles ints + floats correctly).
    return JSON.stringify(value);
  }
  if (typeof value === "string") {
    return escapeString(value);
  }
  if (Array.isArray(value)) {
    return "[" + value.map(stringify).join(",") + "]";
  }
  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    return (
      "{" +
      keys
        .filter((k) => obj[k] !== undefined)
        .map((k) => escapeString(k) + ":" + stringify(obj[k]))
        .join(",") +
      "}"
    );
  }
  throw new Error(`cannot canonicalize value of type ${typeof value}`);
}

function escapeString(s: string): string {
  // JSON.stringify on a string handles standard escapes; we then re-escape
  // any non-ASCII to match Python's ensure_ascii=True / Rust's default.
  const stdEscaped = JSON.stringify(s);
  // stdEscaped starts and ends with " — walk inside, escape any code point > 0x7E.
  let out = '"';
  for (let i = 1; i < stdEscaped.length - 1; i++) {
    const ch = stdEscaped[i]!;
    const code = ch.charCodeAt(0);
    if (code >= 0x20 && code <= 0x7e) {
      out += ch;
    } else if (code >= 0xd800 && code <= 0xdbff) {
      // High surrogate — emit pair as two \uXXXX.
      const high = code;
      const low = stdEscaped.charCodeAt(i + 1);
      out += "\\u" + high.toString(16).padStart(4, "0");
      out += "\\u" + low.toString(16).padStart(4, "0");
      i++;
    } else {
      out += "\\u" + code.toString(16).padStart(4, "0");
    }
  }
  out += '"';
  return out;
}

/** SHA-256 of a string or byte array, returned as lowercase hex. */
export function sha256Hex(data: string | Uint8Array): string {
  const bytes = typeof data === "string" ? new TextEncoder().encode(data) : data;
  return bytesToHex(sha256(bytes));
}

/** SHA-256 of canonical JSON of the content payload. */
export function contentHash(content: Record<string, unknown>): string {
  return sha256Hex(canonicalJson(content));
}

/** SHA-256 of canonical JSON of the entry envelope. */
export function entryHash(entry: Record<string, unknown>): string {
  return sha256Hex(canonicalJson(entry));
}

/** SHA-256 of an artifact (bytes or string). The artifact stays local. */
export function artifactHash(artifact: string | Uint8Array): string {
  return sha256Hex(artifact);
}

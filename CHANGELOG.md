# Changelog — `@ledgerproof/sdk` (TypeScript SDK)

All notable changes to the LedgerProof TypeScript SDK. The format adheres to [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 1.1.3 — 2026-06-22

### Fixed — default API endpoint (P0: zero-config calls were failing)
`DEFAULT_API_BASE` is repointed from `https://api-eu.ledgerproofhq.io` to the healthy `https://api.ledgerproofhq.io` in the client, witness client, and verifier. The previous EU default host is currently unreachable (its Fly app is suspended), so every default-configured SDK call was failing with a connection reset. Callers can still target any endpoint via the `apiBase` option or the `LEDGERPROOF_API_BASE` environment variable. No protocol, signing, or wire-format changes — the cryptographic path is byte-identical to 1.1.2.

## 1.1.2 — 2026-06-19

### Changed — release engineering (no code or API changes)
First release published from the public `ledgerproof-sdk-js` repository via CI **trusted publishing** (OIDC), carrying npm **build provenance**. The cryptographic implementation is byte-for-byte identical to 1.1.1 (Ed25519 via the Cure53-audited `@noble/curves`; SHA-256 via `@noble/hashes`) — this release exists solely to attach verifiable provenance, which npm generates only for builds from a public source repository.

## 1.1.1 — 2026-06-18

### Changed — audited Ed25519 implementation
The Ed25519 signature path now uses the implementation exported by `@noble/curves` instead of the standalone `@noble/ed25519` micro-library.

- **Why:** The standalone `@noble/ed25519@2.x` package is not independently audited — only its older v1 line was reviewed by Cure53 (Feb 2022). The audited noble Ed25519 ships in `@noble/curves` (Cure53, Sep 2024), and `@noble/hashes` (already used here for SHA-256) is likewise Cure53-audited (Sep 2024). After this change, every cryptographic primitive in the SDK comes from a Cure53-audited noble package.
- **Simpler:** `@noble/curves` bundles SHA-512 synchronously, so the manual `ed.etc.sha512Sync` wiring the standalone library required at module load is gone (`src/keys.ts`, `src/scitt/cose.ts`).
- **No wire-format change:** Ed25519 is deterministic (RFC 8032), so the same key + message yields the same signature under either library. Signature bytes are unchanged and the public API is unchanged — `signEnvelope`/`verifyEnvelope`/`generateWitnessKeypair` keep their `Promise`-returning signatures. The TypeScript↔Python byte-identity of the Witness Envelope is preserved, re-verified by the cross-language conformance test (`13-api-backend/tests/test_witness_envelope.py`) and the 61-test SDK suite.

### Dependencies
- Removed: `@noble/ed25519` `2.3.0`
- Added: `@noble/curves` `1.9.7` (exact-pinned, latest 1.x — the Cure53-audited line; depends on the same `@noble/hashes` `1.8.0` already pinned here, so no duplicate hashes copy is introduced)

Consistent with the supply-chain hardening policy below, the new dependency is exact-pinned with its integrity hash recorded in the lockfile, and the cross-language canonical-hash conformance test passes on the bumped tree before publish.

## 1.1.1-pre.0 — 2026-06-01 (pre-release; not yet published to npm)

### Added
- This CHANGELOG (back-filling the 1.0.0 release notes from the launch announcement).
- Documentation reference in README pointing to `spec.ledgerproofhq.io/errata/001` (LPR-ERRATA-001) for the Entry #0 historical artifact; clarifies that v1.1+ entries verify correctly under this SDK's content-hash computation.

### Changed — supply-chain hardening
The cryptographic-primitive dependencies are now pinned to exact SHA-locked versions instead of caret ranges. This eliminates the supply-chain attack vector where a compromised maintainer of `@noble/*` could ship a minor-version update that semver-resolves into this SDK and compromises every customer integration. Pinning the exact version means an attacker would have to either compromise the *specific* published version we depend on (much harder; provenance is checked) or publish a new version that we explicitly approve before shipping.

- `@noble/ed25519`: `^2.1.0` → `2.3.0` (exact-pinned to the latest stable 2.x; 3.x introduces breaking API changes that will be addressed in a separate v1.2 migration PR)
- `@noble/hashes`: `^1.4.0` → `1.8.0` (exact-pinned to the latest stable 1.x)

Future bumps to either dependency require:
1. An explicit PR with the new version + integrity hash recorded in the lockfile
2. A review by a contributor outside the original SDK maintainer set
3. The cross-language canonical-hash conformance test passing on the bumped version

This release is a pre-release on the `next` dist-tag. Install with `npm install @ledgerproof/sdk@next`. Promotion to `1.1.1` final on the `latest` dist-tag is gated on:
1. Published Trail of Bits canonicalization audit (target: 2026-06-08) per LPR-ERRATA-001
2. SLSA L3 provenance attestation on the release artifact (workflow added in this release; published with the final 1.1.1 build)
3. npm 2FA-on-publish + provenance enabled on the @ledgerproof org

### Reaffirmed (commitments unchanged from 1.0.0)
- Receipt format is append-only; v1.0 receipts continue to verify.
- No PII at the anchor layer; schema rejects email addresses in policy-protected fields at parse time.
- No content data leaves the customer perimeter; SDK hashes locally, transmits only hash + non-PII metadata + receipt structure.
- ESM and CJS dual publication; type declarations included.

### CI / supply-chain
- Cross-language canonical-hash conformance test in `ledgerproof-platform` CI (June 1, 2026; PR #3) gates against any future drift between this SDK's TypeScript canonicalization and the Rust publisher's Rust canonicalization. The test runs on every PR, every push to main/dev, and nightly. No release that fails this test will ship.

## 1.0.0 — 2026-05-26

### Initial release
- Stripe-style `attach()` pattern for OpenAI, Anthropic.
- `@ledgerproof/sdk/adapters/openai` and `@ledgerproof/sdk/adapters/anthropic` sub-packages.
- `@ledgerproof/sdk/verifier` for browser-side and Node-side verification (uses `@noble/*` under the hood).
- ESM + CJS dual publish.
- Companion edge bundles: `@ledgerproof/vercel-ai` and `@ledgerproof/cloudflare-workers`.
- Apache 2.0 license.

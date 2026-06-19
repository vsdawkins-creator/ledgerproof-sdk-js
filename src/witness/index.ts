/**
 * @ledgerproof/sdk/witness — the Blind Witness model.
 *
 * Publisher-signed envelopes that LedgerProof witnesses + anchors. You hold your
 * key; anyone verifies against the key you publish, with no trust in LedgerProof.
 *
 * Spec: 04-lpr-spec/LedgerProof-Witness-Envelope-v1.md
 */
export * from "./envelope.js";
export * from "./client.js";
export * from "./verify.js";

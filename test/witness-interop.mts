/**
 * Cross-language interop harness for the Witness Envelope.
 *
 * Invoked by 13-api-backend/tests/test_witness_envelope.py via:
 *   node --experimental-strip-types test/witness-interop.mts <fixture.json>
 *
 * Reads a fixture produced by Python, recomputes the canonical bytes, entry_hash,
 * and a stress canonicalization using the REAL SDK module, verifies Python's
 * signature, and signs the same envelope for Python to verify back. Emits JSON.
 */
import { readFileSync } from "node:fs";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils";
import {
  canonicalize,
  entryHash,
  signEnvelope,
  verifyEnvelope,
  type WitnessEnvelope,
} from "../src/witness/envelope.ts";

const fx = JSON.parse(readFileSync(process.argv[2], "utf-8"));
const env = fx.envelope as WitnessEnvelope;

const out = {
  ts_canonical_hex: bytesToHex(utf8ToBytes(canonicalize(env as never))),
  ts_entry_hash: entryHash(env),
  ts_verifies_py: await verifyEnvelope(env, fx.py_signature, fx.public_key),
  ts_signature: await signEnvelope(env, fx.test_private_key),
  ts_stress_hex:
    fx.stress !== undefined ? bytesToHex(utf8ToBytes(canonicalize(fx.stress))) : "",
};

process.stdout.write(JSON.stringify(out));

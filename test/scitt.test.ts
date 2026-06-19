/**
 * SCITT receipt module test suite.
 *
 * Coverage:
 *   - CBOR codec: deterministic encoding, round-trip, integer/negative keys,
 *     known-answer vectors (RFC 8949 examples), map key ordering.
 *   - COSE_Sign1: sign/verify, detached payloads, Sig_structure shape, tamper.
 *   - Merkle (RFC 9162): leaf/node KATs, root, inclusion proof generation, and
 *     root recomputation agreement across every leaf of trees sized 1..9.
 *   - Signed Statement / Receipt / Transparent Statement assembly (spec §2/§4/§5).
 *   - Full ROUND-TRIP: N statements → tree → proofs → TS-signed receipts → attach
 *     → verifyTransparentStatement passes.
 *   - Negatives: tampered payload, wrong root, bad proof, wrong key all fail.
 *   - Bitcoin OP_RETURN witness (mocked fetch): match + mismatch.
 *   - CODE_POINTS shape.
 */

import { describe, expect, it } from "vitest";
import { bytesToHex } from "@noble/hashes/utils";
import { sha256 } from "@noble/hashes/sha256";

import { Keypair } from "../src/keys.js";
import * as cbor from "../src/scitt/cbor.js";
import { CborMap } from "../src/scitt/cbor.js";
import {
  ALG_EDDSA,
  decodeCoseSign1,
  sigStructure,
  signCoseSign1,
  verifyCoseSign1,
} from "../src/scitt/cose.js";
import {
  hashLeaf,
  hashNode,
  inclusionProof,
  merkleRoot,
  rootFromInclusionProof,
} from "../src/scitt/merkle.js";
import {
  assembleReceipt,
  assertSafeContentIntegers,
  attachReceipt,
  decodeStatement,
  emptyUnprotected as emptyUnprotectedBytes,
  encodeSignedStatement,
  MAX_SAFE_CONTENT_INT,
  statementLeafHash,
} from "../src/scitt/statement.js";
import {
  extractReceipt,
  locateRootInOpReturn,
  parseInclusionProof,
  verifyTransparentStatement,
} from "../src/scitt/verify.js";
import {
  BITCOIN_OP_RETURN_PREFIX,
  CODE_POINTS,
  COSE_HEADER,
  CWT_CLAIM,
  LEGACY_ROOT_OFFSET,
  ROOT_LEN,
  SCITT_ROOT_OFFSET,
  TYP_SCITT_STATEMENT,
} from "../src/scitt/constants.js";

// ── Deterministic test keypairs (fixed seeds — never use in production) ───────
const ISSUER_SEED =
  "1111111111111111111111111111111111111111111111111111111111111111";
const TS_SEED =
  "2222222222222222222222222222222222222222222222222222222222222222";
const issuer = () => Keypair.fromHex(ISSUER_SEED);
const ts = () => Keypair.fromHex(TS_SEED);

const SAMPLE_CONTENT = {
  ai_system_id: "openai/gpt-4o",
  deployer_id: "LEI:529900T8BM49AURSDO55",
  deployer_name: "Acme Corp",
  deployer_country: "DE",
  content_category: "SYNTHETIC_TEXT",
  artifact_hash: "a".repeat(64),
  artifact_content_type: "text/plain",
  artifact_bytes: 1234,
  is_public_interest: false,
};

// ════════════════════════════════════════════════════════════════════════════
// CBOR codec
// ════════════════════════════════════════════════════════════════════════════
describe("cbor codec", () => {
  it("round-trips primitives and nested structures", () => {
    const value = new CborMap([
      [1, -8],
      [3, "application/x"],
      [4, new Uint8Array([1, 2, 3])],
      ["arr", [1, 2, 3, "x", true, false, null]],
      [
        15,
        new CborMap([
          [1, "iss"],
          [2, "sub"],
        ]),
      ],
    ]);
    const encoded = cbor.encode(value);
    const decoded = cbor.decode(encoded) as CborMap;
    expect(decoded).toBeInstanceOf(CborMap);
    expect(decoded.get(1)).toBe(-8);
    expect(decoded.get(3)).toBe("application/x");
    expect(decoded.get(4)).toEqual(new Uint8Array([1, 2, 3]));
    const inner = decoded.get(15) as CborMap;
    expect(inner.get(1)).toBe("iss");
    expect(inner.get(2)).toBe("sub");
  });

  it("encodes integers shortest-form (RFC 8949 known answers)", () => {
    expect(bytesToHex(cbor.encode(0))).toBe("00");
    expect(bytesToHex(cbor.encode(10))).toBe("0a");
    expect(bytesToHex(cbor.encode(23))).toBe("17");
    expect(bytesToHex(cbor.encode(24))).toBe("1818");
    expect(bytesToHex(cbor.encode(100))).toBe("1864");
    expect(bytesToHex(cbor.encode(1000))).toBe("1903e8");
    expect(bytesToHex(cbor.encode(1000000))).toBe("1a000f4240");
    // Negative integers.
    expect(bytesToHex(cbor.encode(-1))).toBe("20");
    expect(bytesToHex(cbor.encode(-8))).toBe("27"); // EdDSA alg id
    expect(bytesToHex(cbor.encode(-100))).toBe("3863");
  });

  it("encodes text/byte strings and arrays per RFC 8949", () => {
    expect(bytesToHex(cbor.encode(""))).toBe("60");
    expect(bytesToHex(cbor.encode("a"))).toBe("6161");
    expect(bytesToHex(cbor.encode("IETF"))).toBe("6449455446");
    expect(bytesToHex(cbor.encode(new Uint8Array([1, 2, 3, 4])))).toBe("4401020304");
    expect(bytesToHex(cbor.encode([1, 2, 3]))).toBe("83010203");
    expect(bytesToHex(cbor.encode([]))).toBe("80");
    expect(bytesToHex(cbor.encode(false))).toBe("f4");
    expect(bytesToHex(cbor.encode(true))).toBe("f5");
    expect(bytesToHex(cbor.encode(null))).toBe("f6");
  });

  it("orders map keys deterministically (ints before, by encoded bytes)", () => {
    // Provide keys out of order; expect canonical 1,3,4,15 ordering.
    const m = new CborMap([
      [15, "o"],
      [3, "c"],
      [1, "a"],
      [4, "d"],
    ]);
    const encoded = cbor.encode(m);
    // map(4): a4, then key 01 'a', 03 'c', 04 'd', 0f 'o'
    expect(bytesToHex(encoded)).toBe("a40161610361630461640f616f");
  });

  it("rejects duplicate map keys and trailing bytes", () => {
    expect(() => cbor.encode(new CborMap([[1, "a"], [1, "b"]]))).toThrow(/duplicate/);
    const good = cbor.encode(1);
    const withTrailing = cbor.concatBytes(good, new Uint8Array([0x00]));
    expect(() => cbor.decode(withTrailing)).toThrow(/trailing/);
  });

  it("rejects non-integer numbers (no float support)", () => {
    expect(() => cbor.encode(1.5)).toThrow();
  });
});

// ════════════════════════════════════════════════════════════════════════════
// COSE_Sign1
// ════════════════════════════════════════════════════════════════════════════
describe("COSE_Sign1", () => {
  it("Sig_structure has the RFC 9052 §4.4 Signature1 shape", () => {
    const prot = cbor.encode(new CborMap([[1, ALG_EDDSA]]));
    const payload = new Uint8Array([9, 9, 9]);
    const ss = sigStructure(prot, payload);
    const decoded = cbor.decode(ss) as cbor.CborValue[];
    expect(Array.isArray(decoded)).toBe(true);
    expect(decoded.length).toBe(4);
    expect(decoded[0]).toBe("Signature1");
    expect(decoded[1]).toEqual(prot);
    expect(decoded[2]).toEqual(new Uint8Array(0)); // external_aad
    expect(decoded[3]).toEqual(payload);
  });

  it("signs and verifies an attached COSE_Sign1", () => {
    const kp = issuer();
    const msg = signCoseSign1({
      protectedHeader: [[1, ALG_EDDSA]],
      unprotectedHeader: [],
      payload: new Uint8Array([1, 2, 3, 4]),
      detached: false,
      keypair: kp,
    });
    const decoded = decodeCoseSign1(msg);
    expect(decoded.payload).toEqual(new Uint8Array([1, 2, 3, 4]));
    expect(decoded.signature.length).toBe(64);
    expect(verifyCoseSign1(decoded, kp.publicKey())).toBe(true);
  });

  it("signs and verifies a DETACHED COSE_Sign1 (payload nil on the wire)", () => {
    const kp = ts();
    const root = sha256(new Uint8Array([7]));
    const msg = signCoseSign1({
      protectedHeader: [[1, ALG_EDDSA]],
      unprotectedHeader: [],
      payload: root,
      detached: true,
      keypair: kp,
    });
    const decoded = decodeCoseSign1(msg);
    expect(decoded.payload).toBeNull(); // detached → nil
    // Must supply the detached payload to verify.
    expect(verifyCoseSign1(decoded, kp.publicKey(), root)).toBe(true);
    expect(() => verifyCoseSign1(decoded, kp.publicKey())).toThrow(/detached/);
    // Wrong detached payload fails.
    expect(verifyCoseSign1(decoded, kp.publicKey(), sha256(new Uint8Array([8])))).toBe(
      false
    );
  });

  it("fails verification under a wrong key or tampered signature", () => {
    const kp = issuer();
    const msg = signCoseSign1({
      protectedHeader: [[1, ALG_EDDSA]],
      unprotectedHeader: [],
      payload: new Uint8Array([5, 5, 5]),
      detached: false,
      keypair: kp,
    });
    const decoded = decodeCoseSign1(msg);
    expect(verifyCoseSign1(decoded, ts().publicKey())).toBe(false);
    decoded.signature[0] ^= 0xff;
    expect(verifyCoseSign1(decoded, kp.publicKey())).toBe(false);
  });
});

// ════════════════════════════════════════════════════════════════════════════
// Merkle (RFC 9162)
// ════════════════════════════════════════════════════════════════════════════
describe("merkle (RFC 9162)", () => {
  it("leaf and node hashing match the 0x00 / 0x01 prefixed definitions", () => {
    const entry = new Uint8Array([0xde, 0xad]);
    expect(hashLeaf(entry)).toEqual(
      sha256(cbor.concatBytes(Uint8Array.from([0x00]), entry))
    );
    const l = hashLeaf(new Uint8Array([1]));
    const r = hashLeaf(new Uint8Array([2]));
    expect(hashNode(l, r)).toEqual(
      sha256(cbor.concatBytes(Uint8Array.from([0x01]), l, r))
    );
  });

  it("single-leaf tree root equals its leaf hash", () => {
    const e = new Uint8Array([42]);
    expect(merkleRoot([e])).toEqual(hashLeaf(e));
    expect(inclusionProof([e], 0)).toEqual([]);
    expect(rootFromInclusionProof(hashLeaf(e), 0, 1, [])).toEqual(hashLeaf(e));
  });

  it("two-leaf tree matches the hand-computed root", () => {
    const a = new Uint8Array([1]);
    const b = new Uint8Array([2]);
    const expected = hashNode(hashLeaf(a), hashLeaf(b));
    expect(merkleRoot([a, b])).toEqual(expected);
    // proof for leaf 0 is [leafHash(b)]; for leaf 1 is [leafHash(a)].
    expect(inclusionProof([a, b], 0)).toEqual([hashLeaf(b)]);
    expect(inclusionProof([a, b], 1)).toEqual([hashLeaf(a)]);
  });

  it("generation and verification agree for every leaf of trees sized 1..33", () => {
    // Spans balanced (powers of two) and unbalanced trees, exercising the
    // RFC 9162 §2.1.3.2 fn===sn (rightmost-leaf) collapse branch repeatedly.
    for (let n = 1; n <= 33; n++) {
      const entries = Array.from(
        { length: n },
        (_, i) => new Uint8Array([n & 0xff, i & 0xff, (i >> 8) & 0xff])
      );
      const root = merkleRoot(entries);
      for (let i = 0; i < n; i++) {
        const path = inclusionProof(entries, i);
        const recomputed = rootFromInclusionProof(hashLeaf(entries[i]!), i, n, path);
        expect(bytesToHex(recomputed)).toBe(bytesToHex(root));
      }
    }
  });

  it("matches an independent hand-built tree for n=4 and n=5 (shape check)", () => {
    // n=4 is balanced: root = H( H(L0,L1), H(L2,L3) ).
    const e = Array.from({ length: 5 }, (_, i) => new Uint8Array([i]));
    const L = e.map(hashLeaf);
    const root4 = hashNode(hashNode(L[0]!, L[1]!), hashNode(L[2]!, L[3]!));
    expect(bytesToHex(merkleRoot(e.slice(0, 4)))).toBe(bytesToHex(root4));
    // n=5 (RFC 9162 §2.1.1 example shape): k=4, so
    //   root = H( MTH(0..3), MTH(4) ) = H( root4, L4 ).
    const root5 = hashNode(root4, L[4]!);
    expect(bytesToHex(merkleRoot(e))).toBe(bytesToHex(root5));
    // Inclusion proof for the lone rightmost leaf (index 4) is just [root4].
    expect(inclusionProof(e, 4).map(bytesToHex)).toEqual([bytesToHex(root4)]);
  });

  it("rejects an inclusion proof of the wrong length", () => {
    const entries = Array.from({ length: 5 }, (_, i) => new Uint8Array([i]));
    const path = inclusionProof(entries, 0);
    // Too short.
    expect(() =>
      rootFromInclusionProof(hashLeaf(entries[0]!), 0, 5, path.slice(0, -1))
    ).toThrow(/shorter/);
    // Too long.
    expect(() =>
      rootFromInclusionProof(hashLeaf(entries[0]!), 0, 5, [...path, path[0]!])
    ).toThrow(/longer/);
  });

  it("a wrong leaf index or tampered path does not reproduce the root", () => {
    const entries = Array.from({ length: 7 }, (_, i) => new Uint8Array([i]));
    const root = merkleRoot(entries);
    const path = inclusionProof(entries, 3);
    // Tamper one path element.
    const bad = path.map((h) => h.slice());
    bad[0]![0] ^= 0xff;
    expect(bytesToHex(rootFromInclusionProof(hashLeaf(entries[3]!), 3, 7, bad))).not.toBe(
      bytesToHex(root)
    );
    // Wrong index (claim leaf 4 with leaf 3's path) → different root.
    expect(bytesToHex(rootFromInclusionProof(hashLeaf(entries[3]!), 4, 7, path))).not.toBe(
      bytesToHex(root)
    );
  });
});

// ════════════════════════════════════════════════════════════════════════════
// Signed Statement / Receipt / Transparent Statement assembly
// ════════════════════════════════════════════════════════════════════════════
describe("signed statement assembly (spec §2)", () => {
  it("builds the protected header with the spec's labels and values", () => {
    const stmt = encodeSignedStatement(SAMPLE_CONTENT, {
      keypair: issuer(),
      iss: "LEI:529900T8BM49AURSDO55",
      sub: SAMPLE_CONTENT.artifact_hash,
    });
    const decoded = decodeStatement(stmt);
    const p = decoded.protectedMap;
    expect(p.get(COSE_HEADER.alg)).toBe(ALG_EDDSA); // 1 : -8
    expect(p.get(COSE_HEADER.contentType)).toBe("application/ai-article-50+json");
    expect(p.get(COSE_HEADER.kid)).toEqual(issuer().publicKey()); // default kid
    expect(p.get(COSE_HEADER.typ)).toBe(TYP_SCITT_STATEMENT);
    const claims = p.get(COSE_HEADER.cwtClaims) as CborMap;
    expect(claims.get(CWT_CLAIM.iss)).toBe("LEI:529900T8BM49AURSDO55");
    expect(claims.get(CWT_CLAIM.sub)).toBe(SAMPLE_CONTENT.artifact_hash);
    // Unprotected header empty at issuance.
    expect(decoded.unprotected.entries.length).toBe(0);
    // Payload is the CBOR-encoded content map.
    const payloadMap = cbor.decode(decoded.payload!) as CborMap;
    expect(payloadMap.get("ai_system_id")).toBe("openai/gpt-4o");
    // Issuer signature verifies.
    expect(verifyCoseSign1(decoded, issuer().publicKey())).toBe(true);
  });

  it("honors a custom string kid and content_type", () => {
    const stmt = encodeSignedStatement(SAMPLE_CONTENT, {
      keypair: issuer(),
      iss: "did:key:zABC",
      sub: "artifact-1",
      kid: "key-2026",
      contentType: "application/custom+json",
    });
    const p = decodeStatement(stmt).protectedMap;
    expect(p.get(COSE_HEADER.kid)).toEqual(new TextEncoder().encode("key-2026"));
    expect(p.get(COSE_HEADER.contentType)).toBe("application/custom+json");
  });
});

describe("receipt assembly (spec §4)", () => {
  it("builds a detached receipt with vds and a bstr.cbor inclusion proof", () => {
    const entries = Array.from({ length: 5 }, (_, i) => new Uint8Array([i]));
    const root = merkleRoot(entries);
    const path = inclusionProof(entries, 2);
    const receipt = assembleReceipt(
      { merkleRoot: root, treeSize: 5, leafIndex: 2, inclusionPath: path },
      ts()
    );
    const decoded = decodeCoseSign1(receipt);
    // protected { 1:-8, 395:1 }
    expect(decoded.protectedMap.get(COSE_HEADER.alg)).toBe(ALG_EDDSA);
    expect(decoded.protectedMap.get(CODE_POINTS.vds)).toBe(CODE_POINTS.vdsAlg);
    // payload detached (nil)
    expect(decoded.payload).toBeNull();
    // unprotected { 396: { -1: [ bstr.cbor ] } }
    const proof = parseInclusionProof(decoded);
    expect(proof.treeSize).toBe(5);
    expect(proof.leafIndex).toBe(2);
    expect(proof.path.map(bytesToHex)).toEqual(path.map(bytesToHex));
    // Receipt signature verifies against the (detached) root.
    expect(verifyCoseSign1(decoded, ts().publicKey(), root)).toBe(true);
  });

  it("rejects malformed receipt inputs", () => {
    const root = sha256(new Uint8Array([1]));
    expect(() =>
      assembleReceipt(
        { merkleRoot: new Uint8Array(31), treeSize: 1, leafIndex: 0, inclusionPath: [] },
        ts()
      )
    ).toThrow(/32 bytes/);
    expect(() =>
      assembleReceipt(
        { merkleRoot: root, treeSize: 3, leafIndex: 5, inclusionPath: [] },
        ts()
      )
    ).toThrow(/out of range/);
  });
});

describe("transparent statement (spec §5)", () => {
  it("attaches the receipt at label 394 without disturbing the signed bytes", () => {
    const stmt = encodeSignedStatement(SAMPLE_CONTENT, {
      keypair: issuer(),
      iss: "iss-1",
      sub: "sub-1",
    });
    const before = decodeStatement(stmt);
    const leafBefore = statementLeafHash(stmt);

    const entries = [emptyUnprotectedBytes(stmt)];
    const root = merkleRoot(entries);
    const receipt = assembleReceipt(
      { merkleRoot: root, treeSize: 1, leafIndex: 0, inclusionPath: [] },
      ts()
    );
    const tsStmt = attachReceipt(stmt, receipt);
    const after = decodeStatement(tsStmt);

    // Protected header, payload, and signature are byte-identical.
    expect(bytesToHex(after.protected)).toBe(bytesToHex(before.protected));
    expect(bytesToHex(after.signature)).toBe(bytesToHex(before.signature));
    expect(bytesToHex(after.payload!)).toBe(bytesToHex(before.payload!));
    // Receipt now present at label 394.
    expect(extractReceipt(after)).toBeDefined();
    // Leaf hash unchanged because the unprotected header is emptied before hashing.
    expect(bytesToHex(statementLeafHash(tsStmt))).toBe(bytesToHex(leafBefore));
  });
});

// ════════════════════════════════════════════════════════════════════════════
// FULL ROUND-TRIP + negatives
// ════════════════════════════════════════════════════════════════════════════
describe("full round-trip", () => {
  const N = 6;

  function buildLog() {
    const issuerKp = issuer();
    const tsKp = ts();
    // N distinct signed statements.
    const statements = Array.from({ length: N }, (_, i) =>
      encodeSignedStatement(
        { ...SAMPLE_CONTENT, artifact_hash: bytesToHex(sha256(new Uint8Array([i]))) },
        { keypair: issuerKp, iss: `LEI:ISSUER${i}`, sub: `artifact-${i}` }
      )
    );
    // Leaves are the empty-unprotected statement bytes.
    const leaves = statements.map((s) => emptyUnprotectedBytes(s));
    const root = merkleRoot(leaves);
    // Build a TS-signed receipt per statement and attach it.
    const transparent = statements.map((s, i) => {
      const path = inclusionProof(leaves, i);
      const receipt = assembleReceipt(
        { merkleRoot: root, treeSize: N, leafIndex: i, inclusionPath: path },
        tsKp
      );
      return attachReceipt(s, receipt);
    });
    return { issuerKp, tsKp, statements, leaves, root, transparent };
  }

  it("every statement verifies end-to-end (steps 1–4 pass)", async () => {
    const { issuerKp, tsKp, transparent } = buildLog();
    for (const tsStmt of transparent) {
      const result = await verifyTransparentStatement(tsStmt, {
        issuerPublicKey: issuerKp.publicKey(),
        tsPublicKey: tsKp.publicKey(),
      });
      expect(result.issuerSignatureValid).toBe(true);
      expect(result.inclusionProofValid).toBe(true);
      expect(result.receiptSignatureValid).toBe(true);
      expect(result.valid).toBe(true);
      expect(result.recomputedRoot).toHaveLength(64);
    }
  });

  it("recomputed root matches the actual tree root", async () => {
    const { issuerKp, tsKp, transparent, root } = buildLog();
    const result = await verifyTransparentStatement(transparent[0]!, {
      issuerPublicKey: issuerKp.publicKey(),
      tsPublicKey: tsKp.publicKey(),
    });
    expect(result.recomputedRoot).toBe(bytesToHex(root));
  });

  it("resolves the issuer key via a kid resolver", async () => {
    const { issuerKp, tsKp, transparent } = buildLog();
    const result = await verifyTransparentStatement(transparent[2]!, {
      resolveIssuerKey: () => issuerKp.publicKey(),
      tsPublicKey: tsKp.publicKey(),
    });
    expect(result.valid).toBe(true);
  });

  // ── Negatives ──────────────────────────────────────────────────────────────
  it("NEGATIVE: tampered payload breaks issuer signature and inclusion", async () => {
    const { issuerKp, tsKp, statements, leaves, root } = buildLog();
    // Forge a statement: flip a byte in the signed payload of statement 0, then
    // re-attach the (now non-matching) receipt for index 0.
    const decoded = decodeStatement(statements[0]!);
    const tamperedPayload = decoded.payload!.slice();
    tamperedPayload[5] ^= 0xff;
    const forged = cbor.concatBytes(
      Uint8Array.from([0xc0 | 18]),
      cbor.encode([decoded.protected, new CborMap([]), tamperedPayload, decoded.signature])
    );
    const path = inclusionProof(leaves, 0);
    const receipt = assembleReceipt(
      { merkleRoot: root, treeSize: N, leafIndex: 0, inclusionPath: path },
      tsKp
    );
    const tsStmt = attachReceipt(forged, receipt);
    const result = await verifyTransparentStatement(tsStmt, {
      issuerPublicKey: issuerKp.publicKey(),
      tsPublicKey: tsKp.publicKey(),
    });
    expect(result.issuerSignatureValid).toBe(false); // signature no longer matches
    expect(result.inclusionProofValid).toBe(false); // leaf hash changed → wrong root
    expect(result.valid).toBe(false);
  });

  it("NEGATIVE: a receipt signed over the WRONG root fails the receipt signature", async () => {
    const { issuerKp, tsKp, statements, leaves } = buildLog();
    const path = inclusionProof(leaves, 1);
    const wrongRoot = sha256(new Uint8Array([0xab, 0xcd]));
    const receipt = assembleReceipt(
      { merkleRoot: wrongRoot, treeSize: N, leafIndex: 1, inclusionPath: path },
      tsKp
    );
    const tsStmt = attachReceipt(statements[1]!, receipt);
    const result = await verifyTransparentStatement(tsStmt, {
      issuerPublicKey: issuerKp.publicKey(),
      tsPublicKey: tsKp.publicKey(),
    });
    // The recomputed root is the REAL root; the receipt was signed over a bogus
    // root, so the detached-payload signature check fails.
    expect(result.issuerSignatureValid).toBe(true);
    expect(result.receiptSignatureValid).toBe(false);
    expect(result.valid).toBe(false);
  });

  it("NEGATIVE: a corrupted inclusion path yields a non-matching root → fails", async () => {
    const { issuerKp, tsKp, statements, leaves, root } = buildLog();
    const path = inclusionProof(leaves, 4).map((h) => h.slice());
    path[0]![0] ^= 0xff; // corrupt a sibling
    const receipt = assembleReceipt(
      { merkleRoot: root, treeSize: N, leafIndex: 4, inclusionPath: path },
      tsKp
    );
    const tsStmt = attachReceipt(statements[4]!, receipt);
    const result = await verifyTransparentStatement(tsStmt, {
      issuerPublicKey: issuerKp.publicKey(),
      tsPublicKey: tsKp.publicKey(),
    });
    // Recomputed root won't equal the signed root → receipt signature fails.
    expect(result.receiptSignatureValid).toBe(false);
    expect(result.valid).toBe(false);
  });

  it("NEGATIVE: wrong TS key fails the receipt signature", async () => {
    const { issuerKp, transparent } = buildLog();
    const result = await verifyTransparentStatement(transparent[0]!, {
      issuerPublicKey: issuerKp.publicKey(),
      tsPublicKey: issuer().publicKey(), // wrong key (issuer, not TS)
    });
    expect(result.receiptSignatureValid).toBe(false);
    expect(result.valid).toBe(false);
  });

  it("NEGATIVE: wrong issuer key fails step 1", async () => {
    const { tsKp, transparent } = buildLog();
    const result = await verifyTransparentStatement(transparent[0]!, {
      issuerPublicKey: ts().publicKey(), // wrong issuer key
      tsPublicKey: tsKp.publicKey(),
    });
    expect(result.issuerSignatureValid).toBe(false);
    expect(result.valid).toBe(false);
  });
});

// ════════════════════════════════════════════════════════════════════════════
// Bitcoin OP_RETURN witness (mocked fetch)
// ════════════════════════════════════════════════════════════════════════════
describe("bitcoin OP_RETURN witness (spec §7 step 5)", () => {
  const root = sha256(new Uint8Array([0x10, 0x20, 0x30]));

  function buildSingle() {
    const issuerKp = issuer();
    const tsKp = ts();
    const stmt = encodeSignedStatement(SAMPLE_CONTENT, {
      keypair: issuerKp,
      iss: "iss",
      sub: "sub",
    });
    const leaf = emptyUnprotectedBytes(stmt);
    const realRoot = merkleRoot([leaf]);
    const receipt = assembleReceipt(
      { merkleRoot: realRoot, treeSize: 1, leafIndex: 0, inclusionPath: [] },
      tsKp
    );
    const tsStmt = attachReceipt(stmt, receipt);
    return { issuerKp, tsKp, tsStmt, realRoot };
  }

  function opReturnScriptForData(data: Uint8Array): string {
    // 0x6a (OP_RETURN) + direct-length push + data.
    return "6a" + data.length.toString(16).padStart(2, "0") + bytesToHex(data);
  }

  /** Single-root (legacy) layout: LPR1 || root (36 bytes). */
  function opReturnScriptFor(r: Uint8Array): string {
    return opReturnScriptForData(
      cbor.concatBytes(new TextEncoder().encode("LPR1"), r)
    );
  }

  /** Combined layout: LPR1 || legacy_root || scitt_root (68 bytes). */
  function combinedOpReturnScript(
    legacyRoot: Uint8Array,
    scittRoot: Uint8Array
  ): string {
    return opReturnScriptForData(
      cbor.concatBytes(new TextEncoder().encode("LPR1"), legacyRoot, scittRoot)
    );
  }

  it("confirms when an OP_RETURN output equals LPR1 || root (legacy 36B)", async () => {
    const { issuerKp, tsKp, tsStmt, realRoot } = buildSingle();
    const mockFetch = async () =>
      ({
        ok: true,
        json: async () => ({
          vout: [
            { scriptpubkey_type: "v0_p2wpkh", scriptpubkey: "0014" + "ab".repeat(20) },
            { scriptpubkey_type: "op_return", scriptpubkey: opReturnScriptFor(realRoot) },
          ],
        }),
      }) as unknown as Response;
    const result = await verifyTransparentStatement(tsStmt, {
      issuerPublicKey: issuerKp.publicKey(),
      tsPublicKey: tsKp.publicKey(),
      bitcoinCheck: true,
      txid: "deadbeef",
      fetch: mockFetch as unknown as typeof fetch,
    });
    expect(result.valid).toBe(true);
    expect(result.bitcoinConfirmed).toBe(true);
  });

  it("confirms the SCITT root inside the COMBINED 68B OP_RETURN (offset 36)", async () => {
    const { issuerKp, tsKp, tsStmt, realRoot } = buildSingle();
    // A different legacy root occupies offset 4; the SCITT root sits at offset 36.
    const legacyRoot = sha256(new Uint8Array([0xaa, 0xbb]));
    const mockFetch = async () =>
      ({
        ok: true,
        json: async () => ({
          vout: [
            {
              scriptpubkey_type: "op_return",
              scriptpubkey: combinedOpReturnScript(legacyRoot, realRoot),
            },
          ],
        }),
      }) as unknown as Response;
    const result = await verifyTransparentStatement(tsStmt, {
      issuerPublicKey: issuerKp.publicKey(),
      tsPublicKey: tsKp.publicKey(),
      bitcoinCheck: true,
      txid: "deadbeef",
      fetch: mockFetch as unknown as typeof fetch,
    });
    expect(result.valid).toBe(true);
    expect(result.bitcoinConfirmed).toBe(true);
  });

  it("confirms the legacy root at offset 4 within the COMBINED layout too", () => {
    const legacyRoot = sha256(new Uint8Array([1]));
    const scittRoot = sha256(new Uint8Array([2]));
    const data = cbor.concatBytes(
      new TextEncoder().encode("LPR1"),
      legacyRoot,
      scittRoot
    );
    // Either root present in the combined data is locatable.
    expect(locateRootInOpReturn(data, legacyRoot)).toBe(true);
    expect(locateRootInOpReturn(data, scittRoot)).toBe(true);
  });

  it("does NOT confirm when the OP_RETURN root differs", async () => {
    const { issuerKp, tsKp, tsStmt } = buildSingle();
    const mockFetch = async () =>
      ({
        ok: true,
        json: async () => ({
          vout: [
            { scriptpubkey_type: "op_return", scriptpubkey: opReturnScriptFor(root) },
          ],
        }),
      }) as unknown as Response;
    const result = await verifyTransparentStatement(tsStmt, {
      issuerPublicKey: issuerKp.publicKey(),
      tsPublicKey: tsKp.publicKey(),
      bitcoinCheck: true,
      txid: "deadbeef",
      fetch: mockFetch as unknown as typeof fetch,
    });
    expect(result.valid).toBe(true); // steps 1–4 still pass
    expect(result.bitcoinConfirmed).toBe(false); // but no Bitcoin witness
  });

  it("returns bitcoinConfirmed=false on a network error", async () => {
    const { issuerKp, tsKp, tsStmt } = buildSingle();
    const mockFetch = async () => {
      throw new Error("network down");
    };
    const result = await verifyTransparentStatement(tsStmt, {
      issuerPublicKey: issuerKp.publicKey(),
      tsPublicKey: tsKp.publicKey(),
      bitcoinCheck: true,
      txid: "deadbeef",
      fetch: mockFetch as unknown as typeof fetch,
    });
    expect(result.bitcoinConfirmed).toBe(false);
  });
});

// ════════════════════════════════════════════════════════════════════════════
// locateRootInOpReturn — combined OP_RETURN layout (spec §6)
// ════════════════════════════════════════════════════════════════════════════
describe("locateRootInOpReturn (combined OP_RETURN, spec §6)", () => {
  const prefix = () => new TextEncoder().encode(BITCOIN_OP_RETURN_PREFIX);
  const legacyRoot = sha256(new Uint8Array([0x01]));
  const scittRoot = sha256(new Uint8Array([0x02]));

  it("exposes the layout offset constants", () => {
    expect(BITCOIN_OP_RETURN_PREFIX).toBe("LPR1");
    expect(ROOT_LEN).toBe(32);
    expect(LEGACY_ROOT_OFFSET).toBe(4);
    expect(SCITT_ROOT_OFFSET).toBe(36);
  });

  it("locates the root in the legacy single-root layout (offset 4)", () => {
    const data = cbor.concatBytes(prefix(), scittRoot);
    expect(data.length).toBe(36);
    expect(locateRootInOpReturn(data, scittRoot)).toBe(true);
  });

  it("locates either root in the combined layout (offsets 4 and 36)", () => {
    const data = cbor.concatBytes(prefix(), legacyRoot, scittRoot);
    expect(data.length).toBe(68);
    expect(locateRootInOpReturn(data, legacyRoot)).toBe(true);
    expect(locateRootInOpReturn(data, scittRoot)).toBe(true);
  });

  it("requires the LPR1 prefix (rejects an unframed root)", () => {
    // Root present but no prefix → reject (prevents false positives).
    const data = cbor.concatBytes(scittRoot, new Uint8Array(4));
    expect(locateRootInOpReturn(data, scittRoot)).toBe(false);
    // Wrong prefix (e.g. a future LPR2) → reject until supported.
    const wrong = cbor.concatBytes(new TextEncoder().encode("LPR2"), scittRoot);
    expect(locateRootInOpReturn(wrong, scittRoot)).toBe(false);
  });

  it("rejects a root that is present but NOT at a 32-byte-aligned slot", () => {
    // Place the root one byte past the legacy slot; alignment check must miss it.
    const data = cbor.concatBytes(
      prefix(),
      new Uint8Array([0x00]),
      scittRoot
    );
    expect(locateRootInOpReturn(data, scittRoot)).toBe(false);
  });

  it("rejects a non-matching root and a wrong-length target", () => {
    const data = cbor.concatBytes(prefix(), legacyRoot, scittRoot);
    expect(locateRootInOpReturn(data, sha256(new Uint8Array([0x99])))).toBe(false);
    expect(locateRootInOpReturn(data, new Uint8Array(31))).toBe(false);
    expect(locateRootInOpReturn(new Uint8Array(2), scittRoot)).toBe(false);
  });
});

// ════════════════════════════════════════════════════════════════════════════
// CODE_POINTS
// ════════════════════════════════════════════════════════════════════════════
describe("CODE_POINTS (spec §8)", () => {
  it("exposes the provisional config object", () => {
    expect(CODE_POINTS).toEqual({ receipts: 394, vds: 395, vdp: 396, vdsAlg: 1 });
  });
});

// ════════════════════════════════════════════════════════════════════════════
// Content constraints — 2^53 integer safety (spec §2.1)
// ════════════════════════════════════════════════════════════════════════════
describe("content integer safety (spec §2.1)", () => {
  it("exposes the safe-integer bound as 2^53-1", () => {
    expect(MAX_SAFE_CONTENT_INT).toBe(Number.MAX_SAFE_INTEGER);
    expect(MAX_SAFE_CONTENT_INT).toBe(9007199254740991);
  });

  it("accepts content whose integers are all within ±(2^53-1)", () => {
    const content = {
      lpr_version: 1,
      content_bytes: 1234,
      max_int: MAX_SAFE_CONTENT_INT,
      min_int: -MAX_SAFE_CONTENT_INT,
      nested: { a: [0, 1, 2, MAX_SAFE_CONTENT_INT] },
      // Big values correctly carried as strings are fine.
      big_id_as_string: "99999999999999999999999999",
      timestamp_iso: "2026-06-17T00:00:00.000000000Z",
    };
    expect(() => assertSafeContentIntegers(content)).not.toThrow();
    const stmt = encodeSignedStatement(content, {
      keypair: issuer(),
      iss: "iss",
      sub: "sub",
    });
    // Round-trips: the encoded statement decodes and the issuer sig verifies.
    expect(verifyCoseSign1(decodeStatement(stmt), issuer().publicKey())).toBe(true);
  });

  it("rejects a top-level integer above 2^53-1 with a path-named error", () => {
    const content = { lpr_version: 1, snowflake_id: MAX_SAFE_CONTENT_INT + 1 };
    expect(() =>
      encodeSignedStatement(content, { keypair: issuer(), iss: "i", sub: "s" })
    ).toThrow(/content\.snowflake_id/);
    // The message must name the bound and the remediation (use strings).
    expect(() => assertSafeContentIntegers(content)).toThrow(/2\^53-1/);
    expect(() => assertSafeContentIntegers(content)).toThrow(/string/i);
  });

  it("rejects an integer below -(2^53-1)", () => {
    const content = { v: -(MAX_SAFE_CONTENT_INT + 1) };
    expect(() => assertSafeContentIntegers(content)).toThrow(/'content\.v'/);
  });

  it("names the nested path of the offending field", () => {
    const content = {
      eu_ai_act_50: { training_tokens: 9_007_199_254_740_993 },
    };
    expect(() => assertSafeContentIntegers(content)).toThrow(
      /content\.eu_ai_act_50\.training_tokens/
    );
  });

  it("names the array index of the offending element", () => {
    const content = { counters: [1, 2, MAX_SAFE_CONTENT_INT + 5] };
    expect(() => assertSafeContentIntegers(content)).toThrow(/content\.counters\[2\]/);
  });

  it("rejects a BigInt field with the same string-encoding guidance", () => {
    // BigInt is not a supported content type; nanosecond timestamps must be
    // strings. (Cast through unknown since the content type is JSON-shaped.)
    const content = { timestamp_ns: BigInt("1718582400000000000") } as unknown as Record<
      string,
      unknown
    >;
    expect(() => assertSafeContentIntegers(content)).toThrow(/content\.timestamp_ns/);
    expect(() => assertSafeContentIntegers(content)).toThrow(/string/i);
  });
});

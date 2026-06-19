/**
 * RFC 9162 (Certificate Transparency v2) Merkle tree primitives, restricted to
 * what the SCITT profile needs: leaf hashing, tree construction, inclusion-proof
 * generation, and root recomputation from an inclusion proof (§2.1.3.1).
 *
 * Hashing (RFC 9162 §2.1.1), SHA-256:
 *   MTH({})        = SHA-256()                              (empty tree)
 *   leaf hash      = SHA-256(0x00 || entry)                 (this profile: entry = COSE_Sign1 bytes)
 *   interior node  = SHA-256(0x01 || left || right)
 *
 * Tree shape (§2.1): the left subtree of a node with n leaves holds the largest
 * power of two < n leaves (k = 2^floor(log2(n-1))), the right subtree the rest.
 */

import { sha256 } from "@noble/hashes/sha256";

import { concatBytes } from "./cbor.js";

const LEAF_PREFIX = 0x00;
const NODE_PREFIX = 0x01;

/** RFC 9162 §2.1.1 leaf hash: SHA-256(0x00 || entry). */
export function hashLeaf(entry: Uint8Array): Uint8Array {
  return sha256(concatBytes(Uint8Array.from([LEAF_PREFIX]), entry));
}

/** RFC 9162 §2.1.1 interior node hash: SHA-256(0x01 || left || right). */
export function hashNode(left: Uint8Array, right: Uint8Array): Uint8Array {
  return sha256(concatBytes(Uint8Array.from([NODE_PREFIX]), left, right));
}

/** Largest power of two strictly less than n (the §2.1 split point k). */
function largestPowerOfTwoLessThan(n: number): number {
  if (n < 2) throw new Error("merkle: split requires n >= 2");
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

/**
 * Compute the Merkle Tree Hash (root) over an ordered list of leaf *hashes*.
 * (Caller hashes the entries with {@link hashLeaf} first.)
 */
export function merkleRootFromLeafHashes(leaves: Uint8Array[]): Uint8Array {
  const n = leaves.length;
  if (n === 0) return sha256(new Uint8Array(0)); // MTH({}) = SHA-256()
  if (n === 1) return leaves[0]!;
  const k = largestPowerOfTwoLessThan(n);
  const left = merkleRootFromLeafHashes(leaves.slice(0, k));
  const right = merkleRootFromLeafHashes(leaves.slice(k));
  return hashNode(left, right);
}

/** Convenience: build the root directly from raw entries. */
export function merkleRoot(entries: Uint8Array[]): Uint8Array {
  return merkleRootFromLeafHashes(entries.map(hashLeaf));
}

/**
 * Generate an RFC 9162 §2.1.3.1 inclusion proof for the leaf at `index` in a
 * tree built over `leaves` (leaf *hashes*). Returns the audit path as an ordered
 * list of sibling hashes, bottom-up.
 */
export function inclusionProofFromLeafHashes(
  leaves: Uint8Array[],
  index: number
): Uint8Array[] {
  const n = leaves.length;
  if (index < 0 || index >= n) {
    throw new Error(`merkle: leaf index ${index} out of range [0, ${n})`);
  }
  if (n === 1) return [];
  const k = largestPowerOfTwoLessThan(n);
  if (index < k) {
    // Leaf is in the left subtree; sibling is the right subtree root.
    const sub = inclusionProofFromLeafHashes(leaves.slice(0, k), index);
    return [...sub, merkleRootFromLeafHashes(leaves.slice(k))];
  } else {
    // Leaf is in the right subtree; sibling is the left subtree root.
    const sub = inclusionProofFromLeafHashes(leaves.slice(k), index - k);
    return [...sub, merkleRootFromLeafHashes(leaves.slice(0, k))];
  }
}

/** Convenience: inclusion proof directly from raw entries. */
export function inclusionProof(entries: Uint8Array[], index: number): Uint8Array[] {
  return inclusionProofFromLeafHashes(entries.map(hashLeaf), index);
}

/**
 * Recompute the Merkle root from a leaf hash and an inclusion proof, per the
 * RFC 9162 §2.1.3.2 verification algorithm. This is the exact procedure a SCITT
 * verifier runs to recover the detached Receipt payload.
 *
 * The algorithm walks the path bottom-up. At each level the current node is
 * combined with the next path element; whether the current node is the left or
 * right child is determined by the bits of `leafIndex` within the remaining
 * subtree size (`size`), exactly as specified in §2.1.3.2.
 *
 * @param leafHash SHA-256(0x00 || entry) for the leaf being proven
 * @param leafIndex zero-based position of the leaf
 * @param treeSize total number of leaves in the tree
 * @param path ordered sibling hashes (bottom-up), as produced above
 * @returns the recomputed root hash
 */
export function rootFromInclusionProof(
  leafHash: Uint8Array,
  leafIndex: number,
  treeSize: number,
  path: Uint8Array[]
): Uint8Array {
  if (leafIndex < 0 || leafIndex >= treeSize) {
    throw new Error(`merkle: leaf index ${leafIndex} out of range [0, ${treeSize})`);
  }
  // RFC 9162 §2.1.3.2 verification algorithm, transcribed directly.
  //   fn = leaf_index, sn = tree_size - 1, r = leaf_hash
  //   for each sibling p in the proof:
  //     if LSB(fn) == 1 or fn == sn:            # current node is a right child
  //         r = HASH(0x01 || p || r)
  //         if LSB(fn) == 0:                    # entered via fn == sn (even fn)
  //             repeat fn >>= 1; sn >>= 1 until LSB(fn) == 1 or fn == 0
  //     else:                                   # current node is a left child
  //         r = HASH(0x01 || r || p)
  //     fn >>= 1; sn >>= 1
  //   afterwards sn MUST be 0 (proof had exactly the right length)
  let fn = leafIndex;
  let sn = treeSize - 1;
  let r = leafHash;
  for (const p of path) {
    if (sn === 0) {
      throw new Error("merkle: inclusion proof longer than tree depth");
    }
    if (fn % 2 === 1 || fn === sn) {
      r = hashNode(p, r);
      // If we took the right-child branch because fn === sn (fn even), advance
      // fn/sn down to the next significant bit before the common shift below.
      if (fn % 2 === 0) {
        do {
          fn = Math.floor(fn / 2);
          sn = Math.floor(sn / 2);
        } while (fn % 2 === 0 && fn !== 0);
      }
    } else {
      r = hashNode(r, p);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  if (sn !== 0) {
    throw new Error("merkle: inclusion proof shorter than tree depth");
  }
  return r;
}

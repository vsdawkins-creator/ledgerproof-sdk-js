# Contributing to `@ledgerproof/sdk`

Thanks for helping improve the LedgerProof TypeScript SDK.

## Development

Requires Node 18+.

```bash
npm ci            # install from the lockfile
npm run lint      # type-check (tsc --noEmit)
npm run build     # ESM + CJS + .d.ts via tsup
npm test          # the SDK test suite (vitest)
```

CI runs `lint`, `build`, and `test` on Node 18 / 20 / 22 for every push to `main`
and every pull request — keep all three green.

## Pull requests

- Branch off `main`; keep each PR focused on one change.
- Add or update tests for behavior changes. The canonical Witness Envelope
  serialization is **byte-identical to the Python reference** and is locked by a
  cross-language conformance test in the upstream service; do not change
  `src/witness/envelope.ts` canonicalization or the Ed25519 signing path without
  coordinating that contract.
- Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/)
  (`feat:`, `fix:`, `chore:`, `docs:`, …).

## Cryptography

All cryptographic primitives come from Cure53-audited noble packages
(`@noble/hashes` for SHA-256, `@noble/curves` for Ed25519). Keep it that way —
don't introduce other crypto dependencies without discussion.

## Releases (maintainers)

See [`RELEASING.md`](./RELEASING.md). Releases are published from CI with npm
build provenance; never publish from a laptop.

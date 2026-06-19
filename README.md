# @ledgerproof/sdk

EU AI Act Article 50 compliance for TypeScript / JavaScript. Works on Node 18+,
Bun, Deno, Cloudflare Workers, Vercel Edge, and modern browsers.

> **Public source for [`@ledgerproof/sdk`](https://www.npmjs.com/package/@ledgerproof/sdk).**
> Published from CI with npm [build provenance](https://docs.npmjs.com/generating-provenance-statements)
> via trusted publishing — every cryptographic primitive is Cure53-audited
> (`@noble/hashes`, `@noble/curves`). Release process: [`RELEASING.md`](./RELEASING.md).

## Install

```bash
npm install @ledgerproof/sdk
# or: pnpm add @ledgerproof/sdk
# or: bun add @ledgerproof/sdk
```

## Three-line attach() — OpenAI Node

```ts
import OpenAI from "openai";
import { attach } from "@ledgerproof/sdk/adapters/openai";

const client = new OpenAI();
attach(client, {
  publisherId: "LEI:5493001KJTIIGC8Y1R12",
  deployerCountry: "DE",
  deployerName: "Acme Corp",
});

// Every chat completion now auto-issues an LPR receipt.
const response = await client.chat.completions.create({
  model: "gpt-4o",
  messages: [{ role: "user", content: "Write a haiku." }],
});

// The receipt promise is attached to the response:
const receipt = await (response as any)._ledgerproofPromise;
console.log(receipt?.verify_url);
```

## Direct usage

```ts
import { LedgerProof } from "@ledgerproof/sdk";

const lp = new LedgerProof({
  publisherId: "LEI:5493001KJTIIGC8Y1R12",
  deployerCountry: "DE",
  // apiKey reads from LEDGERPROOF_API_KEY env var if omitted
});

const receipt = await lp.publishAiArticle50({
  artifact: "The generated text...",
  artifactContentType: "text/plain",
  aiSystemId: "openai/gpt-4o/2024-11-20",
  deployerName: "Acme Insurance AG",
  contentCategory: "SYNTHETIC_TEXT",
  generationType: "FULLY_GENERATED",
});

console.log(receipt.sequence, receipt.entry_hash, receipt.verify_url);
```

## Browser / edge verifier

For browser extensions, Provenance Search, and in-page widgets:

```ts
import { verifyReceipt, lookupByContentHash, hashArtifact } from "@ledgerproof/sdk/verifier";

// Verify by sequence:
const entry = await verifyReceipt(42);

// Look up by hash:
const hash = await hashArtifact(myImageBlob);
const matches = await lookupByContentHash(hash);
```

## License

Apache-2.0. See [LICENSE](LICENSE).

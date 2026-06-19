# Releasing `@ledgerproof/sdk`

This is the **public** source repository for `@ledgerproof/sdk`. Releases run
from CI (`.github/workflows/publish.yml`) via npm **trusted publishing** (OIDC)
with **build provenance** — no npm token lives on anyone's machine.

## One-time setup (npmjs.com web UI — cannot be scripted)

1. `@ledgerproof/sdk` → **Settings** → **Trusted Publisher** → **GitHub Actions**:
   - Organization: `vsdawkins-creator`
   - Repository: `ledgerproof-sdk-js`
   - Workflow filename: `publish.yml`
2. Account → **Two-Factor Authentication** → **Enable** ("Authorization and
   writes"); save the recovery codes. (2FA is device-bound — only a human with an
   authenticator app can enable it; a granular token cannot.)
3. Set the package to require **"two-factor authentication or trusted
   publishing"** for writes.
4. Revoke any legacy granular publish token and remove its `_authToken` line from
   `~/.npmrc` — CI no longer needs it.

## Cut a release

1. Bump `version` in `package.json`, update `CHANGELOG.md`, open a PR, merge to
   the default branch.
2. **Actions** → **Publish to npm (provenance)** → **Run workflow**:
   - `dry_run = true` first → confirm build, the 61-test suite, and a simulated
     publish are green.
   - then `dry_run = false` → publishes with provenance.
3. Verify: `npm view @ledgerproof/sdk dist-tags` shows the new version on
   `latest`, and the npmjs.com package page shows the **Provenance** panel.

> Because this repo is public, `npm publish --provenance` works here — npm only
> attests builds from public source repos. The canonical TS↔Python byte-identity
> contract is still gated upstream by the private monorepo's cross-language
> conformance test; this repo runs the self-contained 61-test SDK suite.

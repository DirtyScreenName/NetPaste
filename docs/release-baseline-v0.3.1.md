# NetPaste v0.3.1 Release Baseline

Captured on 2026-07-17 before NetPaste v0.4.0 Milestones 0 and 1.

## Toolchain

- Node.js: `v24.4.1`
- npm: `11.9.0`
- Vite: `8.0.16`
- Vitest: `4.1.9`
- TypeScript: `6.0.3`

## Verification

The following commands completed successfully from the repository root:

    npm install
    npm test
    npm run typecheck
    npm run build
    npm run build:extension
    npm run package:extension

Vitest reported 10 passing test files and 81 passing tests. npm reported zero
known vulnerabilities. The web build produced `dist/`, the Chromium build
produced `dist-extension/`, and packaging produced
`release/netpaste-chromium-0.3.1.zip`.

## Extension Boundary

`extension/public/manifest.json` is Manifest V3, targets Chrome 114 or later,
and requests only the `sidePanel` permission. It has no host permissions,
optional host permissions, content scripts, storage permission, tab access, or
scripting permission. Its extension content security policy permits local code
and styles and sets `connect-src 'none'`.

The side panel accepts only text that the user deliberately pastes. It does not
read active webpages. The web and side-panel surfaces share the same local core
and UI bootstrap.

## Protected File

`Prompts/Start.txt` had SHA-256 hash:

    2CD9007B84B7C19672211E80375E13E4EE80F2324AE9F7F3E6F46B632602048F

This hash is the v0.4.0 preservation baseline.

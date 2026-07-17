# NetPaste Agent Guide

## ExecPlans

When writing complex features or significant refactors, use an ExecPlan (as
described in `PLANS.md`) from design to implementation.

## Project mission

NetPaste helps network engineers and IT professionals clean and redact CLI
output, configs, tickets, and logs locally before sharing them in tickets,
documentation, GitHub issues, Slack, or AI tools. It may include minimal
Protocols & Packets attribution as its parent brand.

## v0.4 scope

Build and maintain a static browser-local web app and a Chromium Manifest V3
side-panel extension with:

- Raw CLI output textarea.
- Cleaned output textarea.
- Clean Output, Copy Text, Copy Markdown, Load Example, and Clear actions.
- Local redaction profiles, vendor rule packs, document modes, Safe Share Score,
  bulk finding review controls, filters, stable token mapping, Compare mode, and
  a Prepare for AI Markdown copy workflow.
- Sensitive-data findings with category, line number, severity, source,
  confidence, reason, rule ID, vendor, profile action, optional replacement
  token, and masked previews.
- Local-only privacy messaging and a privacy page.
- Store-ready Chromium extension packaging that is paste-only, side-panel based,
  and limited to the `sidePanel` permission.
- A versioned deterministic policy engine shared by the web app and side panel.
- Session-only custom regular-expression, protected-dictionary, and IPv4 CIDR
  rules with allow, review, replace, stable-alias, and block actions.
- Non-secret redaction receipts copied at the user's request.

## Build, test, and verification commands

```powershell
node --version
npm --version
npm install
npm test
npm run typecheck
npm run build
npm run build:extension
npm run package:extension
npm run preview
```

## Privacy constraints

- Process pasted content inside the browser.
- Do not add a backend, external network API calls, analytics, telemetry,
  cookies, uploads, localStorage, sessionStorage, or account features.
- Browser APIs may be used only for local interface functions such as
  user-initiated clipboard writes.
- Do not intentionally persist pasted content.
- Do not log pasted content to the console.
- Render user-controlled text through safe text APIs, not `innerHTML`.

## Prohibited features

Do not add accounts, authentication, payments, backend services, cloud storage,
analytics, AI service calls, automatic network discovery, configuration uploads,
vendor APIs, file import, PDF parsing, webpage-reading extension features,
Firefox or Safari support, multiple themes, internationalization, user
preference persistence, complex branding, a blog, or a database. Chromium
extension packaging is permitted only for the paste-only local side-panel
surface. Profile defaults may select local redactions, and users must be able to
review and change those selections. Minimal Protocols & Packets attribution is
permitted.

NetPaste AI Shield may share this repository's core engine in future work, but
it must use a separate manifest, build artifact, store listing, privacy
disclosure, threat model, permission rationale, and release gate. AI Shield
host permissions, content scripts, webpage access, and prompt interception are
not authorized in v0.4.

## Definition of done

- `npm install` succeeds.
- `npm test` succeeds.
- `npm run typecheck` succeeds.
- `npm run build` succeeds.
- `npm run build:extension` succeeds.
- `npm run package:extension` succeeds.
- The production preview works locally.
- The Chromium extension loads unpacked from `dist-extension/`.
- Core cleaning, detection, profile, scoring, token, compare, and copy behavior
  is covered by tests.
- Sensitive findings show category and line number.
- Copy Text and Copy Markdown use the current cleaned-output textarea contents.
- The app makes no intentional application network requests during normal use.
- The extension requests no host permissions and does not read webpages.
- No pasted content is intentionally persisted.
- The privacy page exists and accurately describes local-only behavior.
- `Prompts/Start.txt` remains unchanged.

# NetPaste Agent Guide

## Project mission

NetPaste helps network engineers clean messy CLI output locally before sharing it
in tickets, documentation, GitHub issues, Slack, or AI tools.

## Frozen v0.1 scope

Build and maintain a small static web app with:

- Raw CLI output textarea.
- Cleaned output textarea.
- Clean Output, Copy Text, Copy Markdown, Load Example, and Clear actions.
- Sensitive-data findings with category, line number, severity, source, and
  masked previews for high-priority credential-like findings.
- Local-only privacy messaging and a privacy page.

## Build, test, and verification commands

```powershell
node --version
npm --version
npm install
npm test
npm run typecheck
npm run build
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
analytics, AI features, automatic network discovery, configuration uploads,
vendor APIs, automatic redaction, PDF reports, browser-extension packaging,
Firefox or Safari support, multiple themes, internationalization, user
preference persistence, complex branding, a blog, or a database.

## Definition of done

- `npm install` succeeds.
- `npm test` succeeds.
- `npm run typecheck` succeeds.
- `npm run build` succeeds.
- The production preview works locally.
- Core cleaning behavior is covered by tests.
- Sensitive findings show category and line number.
- Copy Text and Copy Markdown use the current cleaned-output textarea contents.
- The app makes no intentional application network requests during normal use.
- No pasted content is intentionally persisted.
- The privacy page exists and accurately describes local-only behavior.
- `Prompts/Start.txt` remains unchanged.

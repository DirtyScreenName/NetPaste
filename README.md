# NetPaste

NetPaste is a small static web app for network engineers who need to clean messy
CLI output before placing it into tickets, documentation, GitHub issues, Slack,
or AI tools.

## What it does

- Normalizes line endings.
- Removes ANSI terminal color/control sequences.
- Removes common terminal pagination markers and backspace artifacts.
- Trims trailing line whitespace while preserving indentation.
- Flags common sensitive-looking patterns with category and line number.
- Copies cleaned output as plain text or as a Markdown code block.

## What it does not do

- It does not redact or rewrite cleaned output automatically.
- It does not guarantee that every confidential value is detected.
- It does not upload content or call a backend service.
- It does not include accounts, analytics, telemetry, AI features, storage,
  vendor APIs, or browser-extension packaging.

## Privacy model

Pasted content is processed locally in the browser. NetPaste application code
does not transmit or upload pasted content and does not intentionally persist
pasted content. NetPaste uses no analytics, telemetry, accounts, or external
network APIs. Copying places content on the system clipboard at the user's
request.

## Local development

```powershell
npm install
npm run dev
```

Open the printed local URL, normally `http://127.0.0.1:5173/`.

## Tests and checks

```powershell
npm test
npm run typecheck
```

## Production build

```powershell
npm run build
npm run preview
```

The production preview normally runs at `http://127.0.0.1:4173/`.

## Static deployment

Run `npm run build`, then deploy the generated `dist/` directory to any static
host. The privacy-page links are relative. Before deploying beneath a repository
or other URL subpath, verify that Vite's `base` configuration matches the
deployment path and test the generated `dist/` build at that path.

## Limitations

Sensitive-data detection is pattern based. It can miss confidential values and
can flag harmless text. Always review the cleaned output before sharing.

## Deferred Chrome-extension phase

The core cleaning, detection, and Markdown functions are structured under
`src/core/` so they can be reused by a future Manifest V3 Chrome extension.
Chrome-extension packaging is intentionally outside v0.1 scope.

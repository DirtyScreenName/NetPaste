# NetPaste Chromium Extension

NetPaste ships as a paste-only Chromium side panel for Chrome and Edge. The
extension uses the same local cleaning, detection, redaction, Safe Share Score,
Compare, and Prepare for AI workflow as the web app.

## Local behavior

- Pasted content is processed locally inside the extension page.
- NetPaste application code does not transmit or upload pasted content.
- NetPaste does not intentionally persist pasted content.
- NetPaste uses no analytics, telemetry, accounts, browser storage, cookies,
  backend services, or external network APIs.
- Copying places content on the system clipboard at the user's request.

## Permissions

The extension requests only the `sidePanel` permission so the toolbar action can
open NetPaste in a Chromium side panel. It does not request host permissions,
read webpages, inject content scripts, inspect tabs, or access browser storage.

## Build and load locally

```powershell
npm run build:extension
```

Then open Chromium's extension management page, enable Developer mode, choose
Load unpacked, and select the generated `dist-extension/` directory.

## Package for review

```powershell
npm run package:extension
```

The store-ready ZIP is written under `release/`.

The package script validates that the generated extension contains only the
expected manifest, side panel, service worker, local assets, and icons before it
writes the ZIP.

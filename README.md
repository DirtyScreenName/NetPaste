# NetPaste

NetPaste is a Protocols & Packets tool for network engineers and IT
professionals who need to clean and redact CLI output, configs, tickets, and
logs before placing them into tickets, documentation, GitHub issues, Slack, or
AI tools.

## What it does

- Normalizes line endings.
- Removes ANSI terminal color/control sequences.
- Removes common terminal pagination markers and backspace artifacts.
- Trims trailing line whitespace while preserving indentation.
- Flags common sensitive-looking patterns with category, line number, severity,
  source, confidence, reason, rule pack, and profile action.
- Provides Public, Vendor TAC, Internal Ticket, AI Prompt, and Custom Session
  redaction profiles.
- Suggests local rule packs for Cisco, Juniper, Arista, Palo Alto, Fortinet,
  Ciena, Linux, and Generic IT, with manual override.
- Detects topology-sensitive values such as public/private IPs, hostnames,
  interfaces, VRFs, VLANs, ASNs, serial numbers, circuit IDs, customer/site
  labels, cloud identifiers, and certificate/key material.
- Replaces selected sensitive-looking values with structure-preserving labels or
  stable tokens locally.
- Computes a Safe Share Score from the current profile and selected redactions.
- Supports pasted CLI/config, Markdown, JSON, YAML, CSV/log, and ticket/email
  text modes.
- Builds a local before/after text diff in Compare mode.
- Supports session-only protected dictionaries, IPv4 CIDR ranges, and bounded
  regular-expression rules with allow, review, replace, alias, and block
  actions.
- Copies a non-secret JSON redaction receipt with policy metadata, local
  SHA-256 hashes, classification counts, and review status.
- Copies cleaned output as plain text, as a Markdown code block, or through the
  local Prepare for AI Markdown workflow.
- Ships a Chromium Manifest V3 side-panel build that reuses the same local
  engine for Chrome and Edge-compatible browsers.

## What it does not do

- It does not guarantee that every confidential value is detected.
- It does not upload content or call a backend service.
- It does not call AI services. Prepare for AI is a local redaction profile and
  Markdown copy workflow.
- It does not include accounts, analytics, telemetry, storage, vendor APIs,
  external network APIs, file import, PDF parsing, or webpage-reading browser
  extension features.

## Privacy model

Pasted content is processed locally in the browser. NetPaste application code
does not transmit or upload pasted content and does not intentionally persist
pasted content. NetPaste uses no analytics, telemetry, accounts, or external
network APIs. Selected redactions are applied locally. Copying places content on
the system clipboard at the user's request. Custom session rules, protected
values, and alias mappings remain in memory and are cleared when the page or
side panel closes. Receipt generation hashes content locally and copies only
non-secret metadata when requested.

## Local development

```powershell
npm install
npm run dev
```

Open the printed local URL, normally `http://127.0.0.1:5173/`.

## Chromium extension

NetPaste can also be built as a paste-only Chromium side panel. The extension
requests only the `sidePanel` permission, does not request host permissions, and
does not read webpages, inject content scripts, use browser storage, or call
external network APIs.

```powershell
npm run build:extension
npm run package:extension
```

Load the generated `dist-extension/` directory through Chromium's extension
management page for local testing. The packaged ZIP is written under
`release/`.

## Tests and checks

```powershell
npm test
npm run typecheck
npm run build:extension
npm run package:extension
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

The public parent site for NetPaste is Protocols & Packets:
`https://protocolsandpackets.com/`.

## Operator guides

The static build includes crawlable guides for Cisco configuration redaction,
CLI-output cleanup, and preparing network logs for AI tools. Each guide uses
sanitized examples, links directly to the local workbench, and embeds its own
self-hosted recording of the actual NetPaste workflow without third-party
tracking.

## Limitations

Sensitive-data detection is pattern based. It can miss confidential values and
can flag harmless text. Profiles and scores are review aids, not a guarantee.
Always review the cleaned output before sharing.

## Design model

NetPaste uses a Fluent-inspired technical workbench design: clear hierarchy,
compact command surfaces, visible focus states, accessible contrast, and
predictable review controls. Behavioral design is limited to ethical clarity:
make the useful path obvious, reduce steps to the first cleaned output, and use
Safe Share Score as review feedback rather than telemetry or gamification.

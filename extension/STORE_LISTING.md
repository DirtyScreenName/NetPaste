# NetPaste Chrome Web Store Draft

## Summary

Clean CLI output and redact sensitive network configurations, logs, and tickets
locally before sharing.

## Description

NetPaste is a local network configuration redaction and CLI output cleaner for
network engineers, security teams, support engineers, and IT professionals.
Paste text into the Chromium side panel, remove terminal artifacts, review
sensitive-looking findings, apply selective redactions, and copy readable text
or Markdown.

Use NetPaste before sharing router and switch configurations, firewall output,
troubleshooting logs, support tickets, change records, GitHub issues, or prompts.
Vendor-aware rule packs support common Cisco, Juniper, Arista, Palo Alto,
Fortinet, Ciena, Linux, and generic IT patterns.

Key capabilities:

- Clean ANSI sequences, pagination markers, control artifacts, and excess space.
- Find credentials, keys, IP addresses, hostnames, interfaces, VLANs, VRFs,
  serial numbers, circuit IDs, cloud identifiers, email addresses, and URLs.
- Select individual redactions or apply purpose-built sharing profiles.
- Preserve useful configuration structure with consistent replacement tokens.
- Compare before-and-after text and prepare sanitized Markdown locally.
- Review a Safe Share Score before copying the editable result.

NetPaste is local-first. It does not read webpages, does not request host
permissions, does not upload pasted content, and does not use analytics,
telemetry, accounts, browser storage, cookies, backend services, or external
network APIs.

NetPaste is also available as a web app at
https://netpaste.protocolsandpackets.com/.

## Permission rationale

NetPaste requests the `sidePanel` permission so the toolbar action can open the
local NetPaste workspace in Chromium's side panel. No webpage access is
requested.

## Single purpose

NetPaste provides a local workbench for cleaning and redacting pasted network
text before the user copies it elsewhere.

## Data usage disclosure

NetPaste does not collect, sell, transfer, or use pasted content for any purpose
outside the local extension page. It does not read webpages, inspect tabs, call a
backend, use analytics, or persist pasted content in browser storage.

## Remote code and package review

All extension code, styles, icons, and HTML are packaged locally. The package
script validates the generated file list, Manifest V3 shape, approved
`sidePanel` permission, side-panel path, and content security policy before
writing the review ZIP.

## Privacy policy copy

Pasted content is processed locally. NetPaste application code does not transmit
or upload pasted content. NetPaste does not intentionally persist pasted content.
NetPaste uses no analytics, telemetry, accounts, browser storage, cookies,
backend services, or external network APIs. Copying places content on the system
clipboard at the user's request.

## Pre-submission checklist

- `npm test`
- `npm run typecheck`
- `npm run build`
- `npm run build:extension`
- `npm run package:extension`
- Load `dist-extension/` unpacked in Chromium.
- Confirm the permission warning only reflects the side panel.
- Confirm no unexpected outbound requests during normal use.

# Changelog

## Unreleased

- Added operator guides for Cisco configuration redaction, CLI-output cleanup,
  and preparing network logs for AI tools.
- Added a self-hosted, captioned product workflow video and updated the sitemap
  with the new discovery pages and video metadata.
- Added a compact homepage guide index linking the workbench to the new
  destination-specific workflows.

## 0.3.1 - 2026-07-17

- Added website search metadata, social sharing metadata, software-application
  structured data, crawler guidance, and a direct Chrome Web Store install path.
- Refined the Chrome Web Store description around network configuration
  redaction, CLI output cleaning, privacy, and supported workflows.
- Added the approved Protocols & Packets P mark and packet-forge visual system
  across the web app, Chromium extension, store assets, and social previews.
- Added a Chromium Manifest V3 side-panel extension build and package workflow.
- Refreshed the web and extension interface with a shared Fluent-inspired
  technical workbench design.
- Added extension privacy, permission, and store-listing documentation.
- Hardened PEM certificate/private-key block redaction so selected key-material
  findings cover marker and body lines.
- Added extension package validation for expected files, Manifest V3 shape,
  minimal permissions, and CSP before creating the review ZIP.

## 0.2.0 - 2026-06-28

- Added local redaction profiles for Public, Vendor TAC, Internal Ticket, AI
  Prompt, and Custom Session workflows.
- Added local vendor-aware rule packs for Cisco, Juniper, Arista, Palo Alto,
  Fortinet, Ciena, Linux, and Generic IT.
- Expanded sensitive-data findings with confidence, reason, rule ID, vendor,
  profile action, and optional stable replacement tokens.
- Added topology-sensitive categories including public/private IPs, hostnames,
  interfaces, VRFs, VLANs, ASNs, serial numbers, circuit IDs, site/customer
  labels, certificate/key material, cloud identifiers, and config comment
  metadata.
- Added Safe Share Score, finding filters, bulk review controls, document
  modes, Compare mode, and the local Prepare for AI Markdown workflow.
- Replace removed sensitive values with redaction labels so cleaned network
  configs preserve structure.
- Added live per-finding redaction checkboxes for the editable cleaned output.
- Selected high-priority cleaned-output findings for redaction by default.

## 0.1.1 - 2026-06-19

- Added minimal Protocols & Packets attribution and parent-site references.
- Added the GitHub Pages custom-domain CNAME file.
- Added the canonical URL for the custom domain.

## 0.1.0 - 2026-06-19

- Added the first static NetPaste web app.
- Added deterministic CLI-output cleaning functions.
- Added local sensitive-data pattern detection with masked high-priority
  previews.
- Added plain-text and Markdown copy actions.
- Added a local-only privacy page.
- Added unit tests for cleaning, detection, Markdown output, and analysis.

# Changelog

## Unreleased

- No unreleased changes.

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

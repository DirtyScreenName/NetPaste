# NetPaste 0.4.0 Store Upload Sheet

This release sheet mirrors the canonical copy in `extension/STORE_LISTING.md`.
Use it when the current Chrome Web Store review completes and version 0.4.0 can
be uploaded.

## Product name

NetPaste

## Summary

Clean CLI output and redact sensitive network configs, logs, and tickets locally before sharing.

## Detailed description

NetPaste is a local redaction workbench for network engineers, security teams,
support engineers, and IT professionals. Paste CLI output, configurations,
logs, or ticket text into the Chromium side panel, clean terminal artifacts,
review sensitive-looking findings, and copy an editable sanitized result.

Use NetPaste before sharing technical evidence in support cases, change
records, documentation, GitHub issues, chat, or AI prompts.

Key capabilities:

- Clean ANSI sequences, pagination markers, control artifacts, and excess
  whitespace while preserving useful line structure.
- Review credentials, key material, IP addresses, hostnames, interfaces, VLANs,
  VRFs, serial numbers, circuit IDs, cloud identifiers, email addresses, URLs,
  and other sensitive-looking values.
- Redact individual findings or apply destination-aware Public, Vendor TAC,
  Internal Ticket, AI Prompt, and Custom Session profiles.
- Preserve technical relationships with stable replacement tokens such as
  `<IP-1>` and `<HOST-1>`.
- Add memory-only protected dictionaries, IPv4 CIDR ranges, and bounded regular
  expressions with allow, review, replace, alias, or block-until-handled actions.
- Prevent copy actions while a blocking session-policy finding remains
  unhandled.
- Redact before-and-after text with one token map and produce a readable unified
  diff in Compare mode.
- Review a Safe Share Score and copy a non-secret receipt containing policy
  version, local hashes, classification counts, and review status.
- Prepare sanitized Markdown locally without connecting to an AI service.

Vendor-aware rule packs support common Cisco, Juniper, Arista, Palo Alto,
Fortinet, Ciena, Linux, and generic IT patterns. Findings are pattern-based
review aids; users remain in control of every redaction and should review output
before sharing.

NetPaste processes pasted content inside the extension page. It does not read
webpages, request host access, upload pasted content, use analytics or telemetry,
create accounts, call external network APIs, or persist pasted content in
browser storage. Custom rules, protected values, and alias mappings remain in
memory and are cleared when the side panel closes.

Web app: https://netpaste.protocolsandpackets.com/

## What's new

Version 0.4.0 adds memory-only Custom Session policies, protected dictionaries,
IPv4 CIDR matching, bounded regular expressions, explicit policy actions,
block-until-handled copy enforcement, and non-secret redaction receipts. The
release also adds policy precedence, unsupported-content notices, and local
receipt hashes while preserving NetPaste's paste-only, minimal-permission model.

## Store fields

- Category: Productivity
- Language: English (United States)
- Website: https://netpaste.protocolsandpackets.com/
- Privacy policy: https://netpaste.protocolsandpackets.com/privacy.html
- Support: https://github.com/DirtyScreenName/NetPaste/issues

## Single purpose

NetPaste provides a local workbench for cleaning and redacting pasted network
and IT text before the user copies it elsewhere.

## Permission rationale

NetPaste requests only the `sidePanel` permission. It is required so the toolbar
action can open NetPaste's packaged local workspace in Chromium's side panel.
The extension requests no host permissions and does not read webpages or inspect
tabs.

## Data use disclosure

NetPaste does not collect, sell, transfer, or use pasted content outside the
local extension page. It does not intentionally persist pasted content, custom
rules, protected values, or alias maps. It uses no analytics, telemetry,
accounts, cookies, browser storage, backend services, or external network APIs.
Copying places the current edited output on the system clipboard only after a
user action.

## Remote code declaration

NetPaste does not use remote code. All JavaScript, HTML, CSS, icons, and other
runtime assets are included in the extension package. The extension content
security policy denies network connections from extension pages.

## Reviewer test instructions

All values below are reserved or synthetic test data.

1. Install the package and click the NetPaste toolbar action. The NetPaste side
   panel opens without requesting access to the active webpage.
2. Select `Example`, then select `Clean Output`. Review the findings and confirm
   the cleaned result remains editable.
3. Select and clear individual `Redact` checkboxes. Confirm Cleaned Output
   updates immediately and the page does not jump to the top of the findings
   list.
4. Select `Use stable aliases`, then clean the example again. Confirm repeated
   values use consistent tokens such as `<IP-1>` and `<HOST-1>`.
5. Open `Custom session policy`. Add a protected-dictionary rule for
   `TRAINING-COMMUNITY`, choose `Block until handled`, and add the rule.
6. Paste `snmp-server community TRAINING-COMMUNITY ro` into Raw Text and select
   `Clean Output`. Confirm Copy Text, Copy Markdown, and Prepare for AI remain
   unavailable until the blocking finding is selected for redaction.
7. Select `Compare`, load or paste sanitized before-and-after text, then clean it.
   Confirm both sides use one stable token map in the unified diff.
8. Select `Copy Receipt`. The copied receipt contains metadata and local hashes,
   not pasted values.
9. Close and reopen the side panel. Custom session rules are cleared because the
   extension does not persist them.

## Store privacy-practices answers

- Personally identifiable information: Not collected
- Health information: Not collected
- Financial and payment information: Not collected
- Authentication information: Not collected
- Personal communications: Not collected
- Location: Not collected
- Web history: Not collected
- User activity: Not collected
- Website content: Not collected
- Data sold to third parties: No
- Data used or transferred for unrelated purposes: No
- Data used or transferred for creditworthiness or lending: No

## Screenshot upload order

1. `netpaste-v0.4.0-screenshot-01-session-policies-1280x800.png`
2. `netpaste-v0.4.0-screenshot-02-block-copy-1280x800.png`
3. `netpaste-v0.4.0-screenshot-03-stable-aliases-1280x800.png`
4. `netpaste-v0.4.0-screenshot-04-profile-review-1280x800.png`
5. `netpaste-v0.4.0-screenshot-05-compare-mode-1280x800.png`

## Upload gate

- Wait for the current Chrome Web Store review to complete.
- Upload `release/netpaste-chromium-0.4.0.zip`.
- Upload the five screenshots in the order above.
- Paste the listing copy and reviewer notes from this sheet.
- Repeat the release checks and load-unpacked review before submitting.

# NetPaste Threat Model

## Scope

This document covers the current NetPaste web workbench and paste-only
Chromium side panel, the authorized v0.4.0 session policy engine, and the
proposed but not authorized NetPaste AI Shield product boundary. NetPaste
processes technical text that may contain credentials, private keys, network
addresses, customer identities, topology, and operational metadata.

The security objective is data minimization: only the reviewed, sanitized
result should leave NetPaste at the user's explicit request. NetPaste is a
review aid and cannot guarantee that every sensitive value is detected.

## Current Data Flow

For the web app, the user pastes text into `index.html`. `src/ui/app.ts` passes
that text to pure functions under `src/core/` for cleaning, detection, profile
selection, token mapping, redaction, and scoring. The editable sanitized result
is rendered through text properties. A copy command writes the current result
to the system clipboard only after the user activates that command.

For the Chromium extension, the user opens `sidepanel.html` and deliberately
pastes text. The same core pipeline runs inside the extension page. The
extension does not read the active tab or any webpage. The manifest requests
only `sidePanel`, and the extension content security policy denies network
connections.

NetPaste does not intentionally persist pasted text, findings, policy values,
or alias mappings. It has no backend, account, analytics, telemetry, cookie,
browser storage, upload, or external network API.

## Authorized v0.4.0 Data Flow

Milestone 1 adds custom regular-expression patterns, protected dictionaries,
and IPv4 CIDR ranges that the user enters directly into the workbench. These
values remain in JavaScript memory for the current page or side-panel lifetime
and are destroyed by reload, close, or Clear Session Rules. They are not stored
in browser storage or written to logs.

The policy compiler validates rule structure and rejects unsafe or unsupported
patterns. Policy evaluation produces findings with opaque identifiers, masked
previews, non-secret reasons, and cleaned-text ranges. Original dictionary
values, matched values, regular-expression patterns, and CIDR ranges must not
appear in finding identifiers, previews, reasons, status messages, or receipts.

A redaction receipt is created only when the user requests it. The receipt
contains policy metadata, whole-document SHA-256 hashes, category counts,
review status, and an explicit statement that the original was not retained.
It never contains matched values or the alias map. Copying the receipt writes
it to the system clipboard at the user's request.

## Assets and Adversaries

Protected assets include pasted technical text, custom policy values, matched
values, original-to-alias mappings, cleaned output before review, and clipboard
contents. Relevant adversaries include a malicious pasted document, a person
with access to the same browser session, an extension or script with unrelated
page access, a dependency compromised upstream, and an accidental recipient of
insufficiently reviewed output.

NetPaste also protects against operator error, including copying the original
pane, assuming a Ready status guarantees safety, creating an overbroad rule
that destroys troubleshooting meaning, or creating a weak rule that misses a
critical value.

## Threats and Mitigations

### Raw-value leakage through the interface

Findings use masked previews and opaque identifiers. User-controlled content is
rendered with `textContent`, form values, or equivalent text APIs, never HTML
injection. Reasons describe the matcher class without repeating the pattern or
matched value. Tests search identifiers, previews, reasons, statuses, and
receipt JSON for protected fixtures.

### Persistence and recovery leakage

Session policy and alias data remain in memory. NetPaste does not use
`localStorage`, `sessionStorage`, IndexedDB, cookies, cache storage, extension
storage, or a backend. Reloading clears session rules. The application does not
attempt to recover them.

### Outbound transmission

The application makes no intentional content-bearing network request. The
extension content security policy keeps `connect-src 'none'`. Copying and
receipt copying are explicit local clipboard actions. Static hosting may
perform ordinary document and asset requests, so privacy language does not
claim that a hosted webpage performs no network activity.

### Regular-expression denial of service

Custom regular expressions can cause excessive CPU use through pathological
backtracking. The compiler limits length and flags and rejects backreferences,
lookarounds, nested quantifiers, repeated wildcard quantifiers, and other
unsupported constructs before constructing a `RegExp`. Evaluation limits input
size per rule and reports unsupported content rather than freezing the page.

### Rule collision and precedence

Custom rules have explicit priority and policy action. When a custom finding
covers the same cleaned-text category and range as a built-in finding, the
custom result wins so the user sees one decision. Overlapping replacements are
merged by the existing redaction engine. Conflicting replacement labels fall
back to the generic redaction label rather than exposing a value.

### False confidence

Ready means selected redactions satisfy the active policy defaults; it does not
mean the text is guaranteed safe. Block findings keep the result at High risk
until handled. Unsupported content and invalid rules are visible. Privacy and
review language continues to tell the user to inspect the complete output.

### Receipt misuse

Whole-document hashes can prove that content changed but do not prove legal
chain of custody or perfect sanitation. Receipts omit values, mappings, user
identity, and claims of automatic approval. Low-entropy isolated secrets are
never hashed separately.

### Dependency and build compromise

Milestone 1 adds no runtime dependency. npm audit, unit tests, typecheck, web
build, extension build, package validation, targeted prohibited-API search, and
manual production-preview checks remain release gates. The packaged manifest
must retain only the `sidePanel` permission.

## NetPaste AI Shield Boundary

NetPaste AI Shield is a future, separately approved extension product that may
reuse this repository's core engine. It must have a separate manifest, build
artifact, store listing, privacy disclosure, threat model, permission
rationale, tests, version, and release gate. Its content scripts and narrowly
scoped AI-site host permissions must never be added to the existing paste-only
NetPaste package.

AI Shield must read only the active prompt after an explicit user send intent.
It must not read conversation history, responses, attachments, cookies, or
unrelated page fields. Adapter failure must display Protection inactive. A
silent failure is unacceptable. AI Shield development is not authorized in
v0.4.0.

## Residual Risk

Pattern detection can miss sensitive data and can flag harmless text. A person
can bypass NetPaste, copy the original, close the extension, or use another
application. Stable aliases can alter technical meaning. Another installed
extension or compromised browser may observe page or clipboard content outside
NetPaste's control. These limits require review language, curated regression
fixtures, least privilege, and honest product claims rather than a guarantee of
perfect protection.

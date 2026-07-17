# Evolve NetPaste into a Production-Evidence Gateway and AI Shield

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. This document must be maintained in accordance with the ExecPlan rule in `AGENTS.md`.

## Purpose / Big Picture

NetPaste currently helps a person paste network text, clean terminal artifacts, review sensitive-looking findings, replace selected values, and copy the result. This plan evolves that useful local tool into a production-evidence gateway: raw operational material enters a NetPaste-controlled workflow, deterministic policy removes or substitutes sensitive information, and a useful sanitized result leaves with a receipt that explains which policy ran without revealing the removed values.

The first user-visible experiment is NetPaste Safe Prompt, marketed as “NetPaste AI Shield — production-safe prompts for every AI tool.” A network engineer using a supported browser-based AI interface will be able to review a prompt locally, replace credentials and production identifiers with stable aliases, and deliberately submit only the sanitized text. “Stable alias” means a replacement such as `FIREWALL_A` or `VPN_PEER_01` that is reused every time the same original value occurs, preserving technical relationships without sending the original identifier. The extension must clearly report when protection is active, when content is unsupported, and when review remains necessary. It must never imply perfect detection.

The longer product direction is an evidence pipeline that can capture selected text and, only in later authorized milestones, files or images; detect sensitive data through deterministic rules; transform values without destroying troubleshooting context; let the user review every decision; and package the sanitized output with hashes, policy metadata, and a redaction receipt. A “redaction receipt” is a non-secret record of the policy identifier and version, processing time, original and sanitized cryptographic hashes, finding counts, review result, and whether the original was retained. A cryptographic hash is a one-way fingerprint used to detect whether content changed; the receipt must not contain the sensitive values or a reversible mapping.

The work is successful when users can complete real troubleshooting tasks with sanitized material, curated tests show no bypass of critical deterministic rules, and the validation cohorts meet the adoption and willingness-to-pay thresholds stated below. This plan is a roadmap, not authorization to bypass the current constraints in `AGENTS.md`. Before a milestone adds host permissions, webpage access, storage, file import, a backend, or any other currently prohibited capability, the contributor must obtain explicit scope approval and update `AGENTS.md`, the privacy disclosures, and the threat model in the same reviewed change.

## Progress

- [x] (2026-07-17 19:49Z) Read the two supplied product strategy documents and the complete official Codex ExecPlan specification.
- [x] (2026-07-17 19:49Z) Inspected the current NetPaste core, shared web and extension bootstrap, Manifest V3 permissions, tests, build commands, and privacy constraints.
- [x] (2026-07-17 19:49Z) Reconciled the Safe Prompt and Evidence Package sequences into one gated roadmap.
- [x] (2026-07-17 20:02Z) Received authorization for Milestones 0 and 1 as NetPaste v0.4.0; Safe Prompt remains a separate approval gate.
- [x] (2026-07-17 20:07Z) Implemented Milestone 0 baseline evidence and the current, v0.4.0, and proposed AI Shield data-flow threat model; final unpacked-extension smoke proof remains part of release verification.
- [x] (2026-07-17 21:00Z) Implemented and validated Milestone 1 without new extension permissions. The operator confirmed the unpacked extension loaded and opened; the exact packaged side-panel artifact passed policy, redaction, receipt, copy-blocking, scroll-preservation, narrow-layout, and console checks.
- [x] (2026-07-17 21:18Z) Remediated the final pull-request review findings: findings now retain private rule identity during deduplication, unmatched built-in ranges remain reviewable, and edited output immediately suspends and revalidates send actions when an active session policy can block.
- [ ] Implement and validate Milestone 2, a Safe Prompt prototype for one supported AI site, behind explicit permission and privacy gates.
- [ ] Run the one-week Safe Prompt user validation and record the measured promotion or kill decision.
- [ ] Implement Milestone 3, local redaction receipts and evidence-package export, only if its validation gate is approved.
- [ ] Run the evidence-package cohort and record the measured promotion or kill decision.
- [ ] Prototype file and image sanitation in a desktop companion only after text workflows prove demand.
- [ ] Select and implement one native integration only after a design partner commits to a pilot.
- [ ] Evaluate team policy distribution and an enterprise gateway only after paid demand and governance requirements are documented.

## Surprises & Discoveries

- Observation: The current Chromium extension is intentionally paste-only and requests only the `sidePanel` permission; it has no host permissions or content scripts.
  Evidence: `extension/public/manifest.json` declares `permissions: ["sidePanel"]`, a local side panel, and an extension content security policy with `connect-src 'none'`.

- Observation: Much of the proposed technical foundation already exists in reusable pure TypeScript modules.
  Evidence: `src/core/detectSensitive.ts`, `src/core/profiles.ts`, `src/core/tokenMap.ts`, `src/core/redaction.ts`, and `src/core/shareScore.ts` already provide local detection, profile defaults, stable token mapping, selected redaction, and readiness scoring for both the web and extension surfaces.

- Observation: The two supplied strategies conflict on the first market experiment.
  Evidence: The evidence strategy recommends “rules engine → evidence package → browser adapters,” while the AI Shield strategy calls Safe Prompt more commercially direct and explicitly approves it as the next experiment.

- Observation: The proposed Safe Prompt experiment cannot be hidden inside the existing extension package without a material permission and privacy change.
  Evidence: Reading and changing text in `chatgpt.com` or `claude.ai` requires a content script and host access, both prohibited by the current `AGENTS.md` and absent from `extension/public/manifest.json`.

- Observation: The authorized baseline is healthy before policy-engine changes.
  Evidence: Node `v24.4.1`, npm `11.9.0`, 10 Vitest files and 81 tests, typecheck, web build, extension build, and extension packaging all passed; npm reported zero vulnerabilities and `Prompts/Start.txt` retained SHA-256 `2CD9007B84B7C19672211E80375E13E4EE80F2324AE9F7F3E6F46B632602048F`.

- Observation: A preview that masks only the current custom match can expose a second protected dictionary value on the same line.
  Evidence: The policy evaluator now masks the union of all custom match ranges in each preview line, including lower-priority overlapping matches, and a regression test uses two sanitized protected values on one line.

- Observation: The first responsive implementation placed the open policy builder beside its summary because a shared flex declaration also matched the `details` element.
  Evidence: Production-preview measurement at a 390-pixel device width showed 47 pixels of horizontal overflow. Setting the session-policy panel to block layout removed all visible overflow; the repeated measurement reported `scrollWidth` equal to `viewportWidth` at 375 CSS pixels.

- Observation: The controlled Chromium surface blocks navigation to `chrome://extensions` as a browser-security boundary.
  Evidence: The automated unpacked-install attempt was rejected before navigation. Package validation and the web surface are complete, but a human operator must load `dist-extension/` and open the side panel for the final interaction smoke test.

## Decision Log

- Decision: Build one shared, deterministic policy engine before adding any new product surface.
  Rationale: Both supplied strategies depend on the same rule matching, classification, transformation, stable alias, policy version, and receipt behavior. Keeping those functions pure and browser-local allows the current workbench, Safe Prompt, evidence packages, and later desktop or native integrations to share tested behavior.
  Date/Author: 2026-07-17 / Codex, based on the supplied CEO decisions.

- Decision: Run Safe Prompt before the mixed-evidence package experiment, but limit the first prototype to one AI site and text only.
  Rationale: The AI Shield document identifies immediate user value and approves Safe Prompt as the next experiment. Limiting the first adapter to one site reduces permission scope and makes interface health measurable. Claude support is added only after the first adapter passes its acceptance gate.
  Date/Author: 2026-07-17 / Codex.

- Decision: Treat all automatic interception as assistance, not guaranteed enforcement.
  Rationale: A user can disable an extension, use another browser or application, or encounter an unsupported interface. Consumer and Pro editions therefore warn, sanitize, and review. Enforceable enterprise control belongs in a managed browser, desktop control, or gateway milestone.
  Date/Author: 2026-07-17 / Codex.

- Decision: Keep original values and alias mappings in volatile memory during the first experiments.
  Rationale: The current product intentionally does not persist pasted content. Session-only mappings prove usefulness without introducing local storage, encryption key management, retention, or recovery risks. Any persisted mapping requires a separately approved threat model.
  Date/Author: 2026-07-17 / Codex.

- Decision: Use deterministic rules for automatic transformations and expose uncertain findings for human review.
  Rationale: Silent statistical or AI-driven transformation can leak data or change technical meaning. Approved suggestions may later become deterministic organization rules, but no AI service is required for the initial product and no uncertain match is silently submitted.
  Date/Author: 2026-07-17 / Codex.

- Decision: Defer native integrations, file and image processing, response rehydration, and enterprise infrastructure until measured gates are met.
  Rationale: Building six integrations before validating one buyer workflow would expand permissions, security review, and maintenance faster than the evidence supports. The first native integration will be Jira and Confluence through Forge unless a committed ServiceNow design partner changes the economics.
  Date/Author: 2026-07-17 / Codex.

- Decision: Develop NetPaste AI Shield in this repository but package, publish, and govern it as a separate Chromium extension product.
  Rationale: The shared repository prevents the policy engine, redaction behavior, stable aliases, and tests from drifting. A separate manifest, build artifact, store listing, privacy disclosure, threat model, permission rationale, and release gate keep AI-site host access and content scripts out of the existing paste-only NetPaste extension. Users who only need the side panel therefore retain its minimal `sidePanel` permission and local-only trust boundary.
  Date/Author: 2026-07-17 / User and Codex.

- Decision: Authorize Milestones 0 and 1 as NetPaste v0.4.0 and keep Milestone 2 behind a new approval gate.
  Rationale: The baseline, threat model, versioned deterministic policy engine, session-only custom regular expressions, dictionaries, CIDR ranges, stable aliases, and non-secret receipts can be built without webpage access, persistence, or new extension permissions. Safe Prompt materially changes the trust boundary and must not begin under this authorization.
  Date/Author: 2026-07-17 / User.

- Decision: Accept only bounded custom regular expressions in v0.4.0.
  Rationale: JavaScript regular expressions execute synchronously and provide no standard browser timeout. Rejecting unbounded, optional, nested, lookaround, backreference, and oversized repetition constructs gives session rules a conservative deterministic safety boundary without adding a runtime dependency.
  Date/Author: 2026-07-17 / Codex.

- Decision: Treat an unselected cleaned-output `block` finding as not send-ready.
  Rationale: The app cannot enforce policy outside its own UI, but it can keep Copy Text, Copy Markdown, and Prepare for AI unavailable until the blocking value is selected for transformation. Receipt export remains available and reports the review as pending.
  Date/Author: 2026-07-17 / Codex.

## Outcomes & Retrospective

Milestones 0 and 1 are complete. Milestone 1 provides a shared browser-local policy compiler and evaluator, memory-only dictionary, IPv4 CIDR, and bounded regular-expression rules, deterministic rule priority, allow/review/replace/alias/block actions, stable aliases, copy blocking for unhandled policy findings, and non-secret SHA-256 receipts. The existing web and paste-only extension surfaces share the implementation and the extension still requests only `sidePanel`.

Automated validation, web production-preview QA, package validation, operator-confirmed unpacked loading, and exact packaged-side-panel QA pass. Two responsive defects discovered during visible testing and three release-review correctness findings were corrected and reverified. Milestone 2 remains unauthorized and no AI-site host access, content script, persistence, backend, telemetry, or external API was added. The business questions about repeated Safe Prompt use and willingness to pay therefore remain unresolved and must not be inferred from Milestone 1 completion.

## Context and Orientation

The repository is a Vite and TypeScript static application. Run all commands in the repository root, `C:\Users\jsobe\PycharmProjects\NetPaste`. `package.json` defines the web, test, typecheck, extension, package, and preview commands. `index.html` and `src/main.ts` start the web surface. `sidepanel.html` and `src/extension/sidepanel.ts` start the Chromium side panel. Both call `initNetPasteApp` in `src/ui/app.ts`, so product behavior should remain shared rather than duplicated.

The current detector lives in `src/core/detectSensitive.ts`. It produces `SensitiveFinding` values defined in `src/core/types.ts`. A finding contains a non-secret opaque identifier, category, severity, masked preview, source location, ranges in cleaned text, confidence, reason, rule identifier, vendor, profile action, and optional replacement token. `src/core/redaction.ts` applies selected ranges, `src/core/tokenMap.ts` creates stable replacements, `src/core/profiles.ts` selects defaults for destinations such as a public post or AI prompt, and `src/core/shareScore.ts` reports whether unredacted findings require review. `src/core/analysis.ts` coordinates those functions. These modules are the foundation to preserve.

The current extension manifest is `extension/public/manifest.json`. It requests only `sidePanel`, contains no host permissions or content scripts, and denies network connections from extension pages. `vite.extension.config.ts` builds the extension into `dist-extension/`. `scripts/package-extension.mjs` validates and packages that build. Tests under `tests/` cover the core and extension package. The existing privacy posture prohibits a backend, external network calls, analytics, telemetry, cookies, uploads, browser storage, accounts, file import, webpage-reading extension features, and intentional content persistence. No later milestone may quietly weaken those promises.

In this plan, a “policy” is a versioned set of deterministic rules and default actions. A “rule” is a local instruction that recognizes a value or syntax and chooses allow, review, replace, or block. A “dictionary” is a user-supplied list of protected exact values or phrases. A “CIDR” is the standard notation for an IP address range, such as `10.0.0.0/8`. “Pseudonymization” means consistently replacing an original identifier with a non-secret alias while retaining a local mapping. “Format-preserving substitution” means replacing a value with another value of the same technical shape, such as one IPv4 address with a reserved example address. “Evidence package” means a local ZIP containing only sanitized evidence, a manifest, a receipt, and human-readable reports. “AI gateway” means a separately deployed service through which approved application programming interface traffic passes before reaching a model provider; it is not part of the current static app.

## Plan of Work

### Milestone 0: Governance and baseline evidence

Before product code changes, preserve the current release as the control group. Record the current package version, manifest permissions, test count, built file list, privacy language, `Prompts/Start.txt` hash, and an unpacked-extension smoke test. Create `docs/threat-model.md` describing data flows for the current side panel and proposed Safe Prompt adapter. The threat model must distinguish content merely present on a page from content the user explicitly asks NetPaste to sanitize. It must document bypass, interface drift, accidental submission, raw-value leakage through logs or DOM attributes, alias-map exposure, and failure behavior.

This milestone requires no new permission. Its acceptance is a clean baseline report and a threat model that names every trust boundary. If approval for later permissions is not granted, the repository remains a working paste-only product.

### Milestone 1: Versioned deterministic policy engine

Refactor the existing detector without changing visible behavior. Create `src/core/policy/types.ts`, `src/core/policy/builtins.ts`, `src/core/policy/compile.ts`, `src/core/policy/evaluate.ts`, and `src/core/policy/transform.ts`. Move built-in network, firewall and virtual private network, cloud and development, operational technology, and managed-service-provider knowledge into data-driven policy definitions. Preserve vendor rules for Cisco, Juniper, Arista, Palo Alto, Fortinet, Ciena, Linux, and Generic IT.

Add session-only custom regular-expression rules, protected dictionaries, and CIDR ranges to the web and side-panel workbench. A regular expression is a text pattern; invalid or catastrophically expensive patterns must be rejected before evaluation. Custom rule fields and raw dictionary values must never appear in finding identifiers, masked previews, reasons, or exported receipts. Implement deterministic actions for allow, review, typed substitution, stable alias, and block. “Block” means NetPaste refuses to produce a send-ready result until the finding is removed, replaced, or explicitly handled according to policy; it does not imply system-wide enforcement.

At the end of this milestone, a user can define a protected site name and network range for the current session, paste a configuration, see exact matches attributed to the custom policy, apply stable aliases, and export a non-secret JSON receipt. Reloading the page destroys custom values and mappings. Existing profiles and copy behavior remain compatible.

### Milestone 2: Safe Prompt prototype for one AI site

This milestone begins only after explicit authorization to change extension permissions and privacy language. Add a separate extension entry point under `src/extension/safePrompt/` with `adapter.ts`, `controller.ts`, `reviewModel.ts`, and `health.ts`. The first approved adapter targets one site, initially `chatgpt.com`; do not add Claude in the same milestone. Add the narrow host permission and content-script match required for that origin only. Keep the existing side panel and shared core engine.

The adapter must recognize the visible prompt editor and explicit send action, but it must fail closed when it cannot prove that the expected interface is present. “Fail closed” here means NetPaste visibly reports “Protection inactive” and does not claim the prompt was inspected; it must not break the website or silently submit content. When the user initiates sending, the controller reads only the current prompt, evaluates it locally, and chooses one of four visible outcomes: allow, sanitize and review, block, or require a justification. The prototype must not inspect conversation history, responses, unrelated page text, or attachments.

The review surface shows masked findings, proposed aliases, the provider-safe prompt, and Cancel, Review, and Sanitize and send commands. The original prompt must never be written into extension logs, element attributes, finding identifiers, analytics, or persisted storage. Submitting sanitized text is an external side effect, so automated tests must stop before final submission and manual tests must use sanitized fixtures and an explicit operator action.

At the end of this milestone, a tester can paste a fixture containing a VPN peer, hostname, and fake pre-shared key into the supported prompt editor, initiate send, review the blocked credential and stable aliases, and place only the sanitized prompt in the editor. If the site DOM changes, the extension visibly reports inactive protection.

### Milestone 2 validation gate: one-week Safe Prompt experiment

Distribute the prototype to five network engineers, three systems administrators, three developers, two security engineers, and two managed-service-provider technicians. Ask them to use it for real tasks for one week under an approved test protocol that forbids collecting their raw prompts. Record only participant-controlled aggregate outcomes.

Promote the feature only when at least ten users protect a real prompt, at least five create a custom rule, at least five use it repeatedly, at least three say they would pay, at least two request centralized team rules, no curated critical secret bypasses the deterministic suite, and sanitized prompts remain useful in at least eighty percent of scored tasks. Stop or revise if users habitually bypass the review, aliases consistently damage answers, users only value generic secret scanning, adapter maintenance is disproportionate, or nobody creates or requests custom rules. Record the result in `Decision Log` and `Outcomes & Retrospective` before starting another surface.

### Milestone 3: Local redaction receipts and evidence-package prototype

This milestone begins only after separate approval for local file generation and any selected input types. First implement text-only evidence objects in `src/core/evidence/types.ts`, `src/core/evidence/hash.ts`, `src/core/evidence/receipt.ts`, and `src/core/evidence/package.ts`. An evidence object identifies a case, source type, capture time, original and sanitized SHA-256 hashes, policy identifier and version, non-secret transformation counts, review status, and export target. It must not contain raw finding values. The original text remains in memory only, is hashed locally, and is excluded from the package.

Add a workbench mode that accepts one configuration, one terminal transcript, one log, and optional packet-summary text through explicit paste fields. Apply one shared policy and alias map across all items so repeated devices and addresses remain consistent. Show before-and-after review, create `manifest.json`, `provenance/redaction-log.json`, `provenance/hashes.json`, `provenance/policy-summary.json`, sanitized text files, a Markdown technical summary, and a vendor-TAC ZIP. ZIP means the standard compressed archive format. Use a proven local ZIP library only after dependency and license review; do not hand-roll the archive format.

At the end of this milestone, the user can build a local package from sanitized fixtures, inspect every archive entry, verify the sanitized hashes, confirm no original or alias map is present, and copy a ticket-ready summary. Screenshot, document, packet-capture, and archive import remain out of scope.

### Milestone 3 validation gate: evidence-package experiment

Test the prototype with five network engineers, three managed-service-provider technicians, two vendor support engineers, and two security engineers. Cap the experiment at two weekends, no paid integrations, no ServiceNow instance, no packet rewriting, no background Slack monitoring, and no enterprise administration console.

Promote evidence packaging only when at least eight users submit real or realistically structured evidence, at least five would use it monthly, at least three request organization-specific policies, median preparation time falls by at least fifty percent, no critical deterministic category is missed in the curated set, and at least two organizations express willingness to pay or run a pilot. If users value redaction but reject provenance and packaging, keep NetPaste focused and do not build the broader evidence platform.

### Milestone 4: Desktop companion for files and images

Start this milestone only after the text experiments demonstrate demand and a separate repository or workspace boundary is approved. Build a lightweight desktop companion that handles explicit user actions: a secure drop zone, a sanitize-and-paste hotkey, and deliberate clipboard review. Do not implement silent system-wide monitoring. Text files come first. Images follow through local optical character recognition, which converts visible text in an image into machine-readable spans. Approved masks must be flattened into output pixels so removing a cosmetic layer cannot reveal the original text.

Add archive handling only after individual file types are safe. Enumerate archive entries, reject encrypted archives unless explicitly approved, flag unsupported formats, omit hidden histories and backups, and build a new sanitized archive. Add packet-capture support last and initially produce a sanitized textual summary. Rewriting packet captures requires protocol-aware checksum and length repair; unsupported protocols must have payloads removed or truncated rather than being represented as analytically equivalent.

The desktop acceptance suite must prove that temporary sanitized copies are deleted according to policy, unsupported content is explicit, original files are never overwritten, and repeated runs do not accumulate secret-bearing artifacts.

### Milestone 5: One native integration

Choose one integration after a design partner commits to a pilot. Prefer a Jira and Confluence Forge application because it can expose explicit issue and page actions while reusing one product integration. Choose ServiceNow instead only when a partner supplies an authorized development environment and real workflow requirements. Microsoft 365, Slack, Wireshark, and Snagit remain deferred.

The integration must be user-initiated. It collects only selected content, presents the NetPaste review, and returns a sanitized replacement or evidence package. Do not build a bot that reads every Slack message, a ServiceNow rule that silently processes every record, or a native dependency on an undocumented Snagit interface. Any remote integration requires a new data-flow diagram, least-privilege permission review, retention policy, deletion behavior, and deployment-specific privacy notice.

### Milestone 6: Team policy and enterprise gateway research

Begin only after paid pilot demand establishes a need for centralized control. Prototype signed policy bundles, role-aware review, audit events that exclude raw values, and private deployment before considering a NetPaste-hosted cloud service. A signature is cryptographic proof that a policy bundle came from an approved publisher and was not modified.

Research an OpenAI-compatible and Anthropic-compatible gateway only as a separate service with its own threat model, authentication, deployment, incident response, and compliance work. The gateway may transform, block, require approval, route to approved providers, and emit non-secret security events. It must support zero-storage operation. Do not claim that commercial model providers are inherently unsafe; the product claim is that approved services should receive only the minimum production information needed for the task.

### Deferred and kill list

Do not build response rehydration, a native ChatGPT app, a Claude MCP server, mobile protection, a Firefox or Safari extension, full data-loss-prevention replacement, universal packet anonymization, long-term unredacted evidence storage, litigation-grade chain of custody, six simultaneous marketplace integrations, or AI-only secret detection as part of the initial sequence. “Response rehydration” means locally replacing aliases in an AI response with original identifiers; it is valuable but can reintroduce secrets when copied and therefore requires encrypted, time-limited mapping storage and a separate safety review.

If both Safe Prompt and evidence-package gates fail, stop the expansion and keep NetPaste a focused local redaction workbench. If users repeatedly pay for custom deterministic rules but not packaging, prioritize policy packs and professional rule development. If teams request centralized policy control, evaluate Team and Enterprise editions only after documenting buyer, deployment, and support requirements.

## Concrete Steps

Run all commands from `C:\Users\jsobe\PycharmProjects\NetPaste` in PowerShell. At the beginning of every milestone, confirm the branch and working tree before editing:

    git branch --show-current
    git status --short
    node --version
    npm --version

Expect a named feature branch, no unexplained tracked changes, a Node version supported by the installed Vite and Vitest versions, and an npm version that can install the lockfile. Never delete or overwrite unrelated work. Record the exact versions and any pre-existing changes in `Progress`.

Establish the baseline before Milestone 1:

    npm install
    npm test
    npm run typecheck
    npm run build
    npm run build:extension
    npm run package:extension
    Get-FileHash Prompts\Start.txt -Algorithm SHA256

The current expected test baseline is ten test files and eighty-one tests passing. If that count changes on the target branch, update this document with the new observed baseline rather than forcing an obsolete count. All commands must exit with code zero. The `Prompts/Start.txt` SHA-256 baseline is `2CD9007B84B7C19672211E80375E13E4EE80F2324AE9F7F3E6F46B632602048F` and must remain unchanged.

For each milestone, add focused tests first, implement the smallest pure core behavior, integrate it into one surface, then extend the shared UI only after the core tests pass. Re-run the full command set above before requesting review. When extension permissions change, also inspect the packaged manifest and ZIP:

    Get-Content -Raw dist-extension\manifest.json
    tar -tf release\netpaste-chromium-*.zip

The manifest must contain only the permissions explicitly approved for that milestone. The package must contain local code and assets only. Update `tests/extensionPackaging.test.ts` so an unapproved permission, remote script, unexpected content script, or missing protection-health signal fails the build.

Run targeted source review against implementation files, not documentation:

    rg -n --glob '*.{ts,js,mjs,html}' '\b(fetch|XMLHttpRequest|sendBeacon|localStorage|sessionStorage)\b|document\.cookie|\.innerHTML\s*=|https?://' src extension scripts index.html sidepanel.html

Every match must be classified. Allowed website links and metadata are not application transmission. Any active network, persistence, unsafe rendering, or remote-code use must be explicitly approved, documented, tested, and reflected in privacy text. Raw prompt, configuration, alias-map, dictionary, and receipt fixture values must not be logged.

Start the production preview after each web-facing milestone:

    npm run preview

Open the printed local URL, normally `http://127.0.0.1:4173/`. Exercise the exact acceptance scenario for the milestone. Load `dist-extension/` unpacked in Chromium and inspect the extension console. For Safe Prompt, use a dedicated test profile and sanitized fixtures. Do not send a real prompt during automated testing. Record the browser version, tested site version or adapter health signature, observed statuses, console result, and network result in `Artifacts and Notes`.

## Validation and Acceptance

Milestone 1 is accepted when existing fixtures still produce the same masked findings and redacted output, custom session rules detect exact dictionary, CIDR, and regular-expression matches, invalid rules fail with useful messages, stable aliases are consistent across repeated values, and a receipt contains no raw values. Reloading the app must remove custom values and mappings. Tests must include collision handling, reserved example addresses, catastrophic-pattern rejection, policy version changes, rule priority, and proof that no secret appears in identifiers, reasons, previews, or receipt JSON.

Milestone 2 is accepted when the supported AI site displays an active-protection signal, a sanitized fixture triggers the expected allow, review, block, and justification outcomes, cancellation leaves the original editor unchanged, and sanitization places only the provider-safe prompt in the editor. Breaking the adapter fixture must produce a visible inactive warning. The content script must not read prior conversation messages, page history, responses, attachments, cookies, or unrelated fields. The packaged extension must request access only to the approved origin. Keyboard operation, focus order, screen-reader names, and narrow-window usability must work. No console errors or unexpected outbound requests may occur.

The Safe Prompt release decision additionally requires the one-week cohort thresholds in the Milestone 2 validation gate. Passing automated tests alone does not authorize broader distribution or a second site adapter.

Milestone 3 is accepted when a sanitized multi-item fixture creates a ZIP with the documented paths, identical original input and policy produce deterministic aliases and receipt fields except for explicitly variable timestamps and identifiers, hash verification detects a modified sanitized file, and searching the extracted package finds none of the original protected values. A novice must be able to inspect the package and understand which policy ran, what categories were transformed, whether review occurred, and whether the original was retained.

Later milestones require their own committed fixtures, security tests, usability scripts, deletion checks, and explicit permission reviews before implementation begins. No milestone is complete merely because it compiles. The contributor must demonstrate the user-visible workflow, capture concise evidence, update all living sections, and compare the result with the success and kill criteria.

## Idempotence and Recovery

Core policy evaluation, transformation, receipt generation, and package construction must be deterministic for the same normalized input, policy version, and explicit options. Development commands may be repeated safely. Build outputs in `dist/` and `dist-extension/` are generated artifacts and may be recreated with the documented commands. Never delete `Prompts/Start.txt`, user fixtures, untracked work, or an existing release package to recover from a build failure.

Keep migrations additive. Introduce the policy engine beside the existing detector, prove equivalence with tests, switch one call site, and remove the old path only after the full suite passes. Introduce a site adapter behind an explicit build flag or separate manifest variant so the published paste-only extension remains recoverable during the experiment. If an adapter fails in production, disable that adapter and show protection inactive; do not silently fall back to unreviewed submission.

If a custom rule is invalid, preserve the user’s current text and reject only that rule. If package generation fails, retain the sanitized in-memory result, remove partial archives, and allow retry. If temporary desktop files are introduced later, write to a new path, verify the sanitized copy, and only then offer it to the user; never modify the source file. Rollback means reverting the milestone’s feature branch or disabling its separately packaged variant, then rebuilding and rerunning the full baseline.

## Artifacts and Notes

Keep concise proof here as the work proceeds. A successful baseline currently resembles:

    Test Files  10 passed (10)
    Tests       81 passed (81)
    npm run typecheck          exits 0
    npm run build              exits 0
    npm run build:extension    exits 0
    npm run package:extension  exits 0

Milestone 1 evidence captured on 2026-07-17:

    Test Files  11 passed (11)
    Tests       101 passed (101)
    npm run typecheck          exits 0
    npm run build              exits 0
    npm run build:extension    exits 0
    npm run package:extension  exits 0
    npm audit --omit=dev       found 0 vulnerabilities
    package                    release/netpaste-chromium-0.4.0.zip
    manifest permissions       sidePanel
    manifest host permissions  none
    manifest content scripts   none
    extension connect-src      none

The production-preview fixture proved a repeated protected site name maps to one stable alias, a blocking credential disables the send-ready copy actions when unselected, reselecting it restores a typed secret alias, manual cleaned-output edits are copied verbatim, and the copied receipt contains policy metadata and hashes but not protected values or mappings. Privacy and return links resolved from the generated build, navigating away cleared the session policy and text, the browser console had no warnings or errors, and the corrected open policy panel had no horizontal overflow at mobile width.

The operator confirmed `dist-extension/` loaded unpacked and the toolbar opened the side panel. Automated interaction against the exact generated `dist-extension/sidepanel.html` artifact repeated the alias, block, edited-copy, and receipt checks; rejected an unsafe regular expression without echoing it; preserved finding-review scroll position at 1911 CSS pixels; reported no console warnings or errors; and, after the responsive correction, reported `scrollWidth` equal to `viewportWidth` at a 360-pixel browser viewport with no visible overflow. Final pull-request review added regressions proving that same-value matches from different rules retain their own actions, partially overridden built-in findings retain unmatched ranges, original-only built-in findings remain visible, and edited output suspends send actions while an active blocking policy is re-evaluated. Targeted implementation search found no active `fetch`, `XMLHttpRequest`, `sendBeacon`, cookie, browser-storage, unsafe HTML, eval, or remote-code use. `Prompts/Start.txt` retained SHA-256 `2CD9007B84B7C19672211E80375E13E4EE80F2324AE9F7F3E6F46B632602048F`.

The first Safe Prompt acceptance fixture should use only reserved examples:

    Original fixture:
      HQ-EDGE-FW-01 peers with 198.51.100.27 using PSK TEST-ONLY-SECRET.

    Provider-safe result:
      FIREWALL_A peers with VPN_PEER_01 using PSK [REDACTED_PRESHARED_KEY].

The first receipt proof should resemble the following shape while using computed values:

    {
      "policy_id": "policy_network_ai_v1",
      "policy_version": "1.0.0",
      "original_sha256": "sha256:<computed>",
      "sanitized_sha256": "sha256:<computed>",
      "original_retained": false,
      "redaction_count": 3,
      "classifications": {
        "credential": 1,
        "public_ip": 1,
        "hostname": 1
      },
      "review_status": "approved"
    }

Do not add real customer names, production addresses, credentials, private keys, or confidential prompts to source control, test output, screenshots, issue descriptions, or this plan. Update this section with short command output, browser observations, package listings, and security-review conclusions that prove each milestone.

## Interfaces and Dependencies

Preserve `SensitiveFinding` compatibility while adding policy metadata through new types in `src/core/policy/types.ts`. At the end of Milestone 1, the core interfaces must be equivalent to:

    export type PolicyAction = 'allow' | 'review' | 'replace' | 'alias' | 'block';

    export type PolicyMatcher =
      | { kind: 'regex'; pattern: string; flags?: string }
      | { kind: 'dictionary'; values: readonly string[]; caseSensitive: boolean }
      | { kind: 'cidr'; ranges: readonly string[] }
      | { kind: 'syntax'; parser: string; rule: string };

    export interface PolicyRule {
      id: string;
      category: SensitiveCategory;
      description: string;
      matcher: PolicyMatcher;
      action: PolicyAction;
      severity: FindingSeverity;
      replacementLabel?: string;
      priority: number;
    }

    export interface RedactionPolicy {
      id: string;
      version: string;
      name: string;
      rules: readonly PolicyRule[];
    }

    export interface PolicyEvaluation {
      findings: SensitiveFinding[];
      policyId: string;
      policyVersion: string;
      unsupportedContent: string[];
    }

    export function compilePolicy(policy: RedactionPolicy): CompiledPolicy;

    export function evaluatePolicy(
      originalText: string,
      cleanedText: string,
      policy: CompiledPolicy,
      options?: AnalysisOptions
    ): PolicyEvaluation;

    export function transformWithPolicy(
      text: string,
      evaluation: PolicyEvaluation,
      selectedIds: ReadonlySet<string>,
      aliasMap: TokenMap
    ): string;

At the end of Milestone 2, `src/extension/safePrompt/adapter.ts` must expose a site-independent contract so ChatGPT-specific DOM logic cannot leak into the policy engine:

    export interface PromptSurfaceAdapter {
      readonly id: string;
      health(): PromptSurfaceHealth;
      readDraft(): PromptDraft;
      replaceDraft(providerSafeText: string): void;
      observeSendIntent(handler: () => void): () => void;
    }

    export type PromptSurfaceHealth =
      | { status: 'active'; editorDescription: string }
      | { status: 'inactive'; reason: string };

    export interface PromptDraft {
      text: string;
      sourceOrigin: string;
    }

At the end of Milestone 3, `src/core/evidence/types.ts` must define non-secret package records:

    export interface EvidenceObject {
      evidenceId: string;
      caseId?: string;
      capturedAt: string;
      sourceType: 'configuration' | 'terminal-output' | 'log' | 'packet-summary';
      originalSha256: string;
      sanitizedSha256: string;
      policyId: string;
      policyVersion: string;
      reviewStatus: 'pending' | 'approved' | 'rejected';
      originalRetained: false;
    }

    export interface RedactionReceipt {
      policyId: string;
      policyVersion: string;
      processedAt: string;
      originalSha256: string;
      sanitizedSha256: string;
      originalRetained: false;
      redactionCount: number;
      classifications: Readonly<Record<string, number>>;
      reviewStatus: EvidenceObject['reviewStatus'];
    }

Use standard browser cryptography for SHA-256 where available. Introduce no runtime dependency for regular expressions, dictionaries, CIDR matching, or JSON receipts unless a committed prototype proves the standard platform inadequate. For ZIP generation, evaluate a small, maintained, browser-compatible library with no network behavior and pin its version. Optical character recognition, document parsing, desktop packaging, native integrations, and gateway frameworks are separate dependency decisions that must be proven in isolated prototypes before adoption.

The intended commercial sequence, contingent on validation, is Individual Pro for local custom policies and evidence packages, Team for shared signed policies and review records, Enterprise for private deployment and integrations, paid specialist policy packs for network, firewall and virtual private network, cloud and development, operational technology, security, and managed-service-provider use cases, and professional services for customer-specific rule development. Product packaging and payment implementation are not authorized by this ExecPlan; the sequence exists to connect technical gates to buyer value.

Revision note (2026-07-17): Recorded the decision to keep AI Shield in the shared repository while releasing it as a separate extension product. Recorded authorization and completion evidence for Milestones 0 and 1 as NetPaste v0.4.0, added final pull-request review remediation evidence, and preserved Milestone 2 as a separate permission and privacy approval gate.

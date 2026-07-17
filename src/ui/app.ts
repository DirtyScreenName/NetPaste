import { analyzeCurrentText } from '../core/analysis';
import { prepareForAi } from '../core/aiPrep';
import { cleanText } from '../core/cleanText';
import { buildUnifiedDiff } from '../core/compare';
import { documentModes } from '../core/documentModes';
import { toMarkdownCodeBlock } from '../core/markdown';
import { applyProfileDefaults, getProfile, redactionProfiles } from '../core/profiles';
import { getVendorLabel, vendorDefinitions } from '../core/rulePacks';
import { createSessionPolicy } from '../core/policy/builtins';
import { compilePolicy } from '../core/policy/compile';
import {
  createRedactionReceipt,
  serializeRedactionReceipt
} from '../core/policy/receipt';
import type {
  CompiledPolicy,
  PolicyAction,
  PolicyMatcher,
  PolicyRule
} from '../core/policy/types';
import {
  applySelectedRedactions,
  getDefaultSelectedFindingIds,
  getFindingIds,
  isRedactableFinding,
  reconcileSelectedFindingIds
} from '../core/redaction';
import {
  type AnalysisResult,
  type ConfidenceLevel,
  type DocumentModeId,
  type FindingsSummary,
  type FindingSource,
  type RedactionProfileId,
  type SensitiveCategory,
  type SensitiveFinding,
  type VendorId,
  type VendorSelection,
  sensitiveCategories
} from '../core/types';
import { type AppSurfaceOptions, resolveAppSurface } from './surface';

const EXAMPLE_OUTPUT = `Switch01#show running-config interface GigabitEthernet1/0/10
\x1b[32mBuilding configuration...\x1b[0m

hostname Branch-Router-01
vrf definition CUSTOMER-A
interface GigabitEthernet1/0/10
 description Uplink to customer ACME circuit CKT-44512
 switchport mode trunk
 switchport trunk allowed vlan 10,20,30
 snmp-server community exampleCommunity RO
 ip address 10.14.22.5 255.255.255.0
 no shutdown
!
router bgp 65001
 neighbor 198.51.100.10 remote-as 64512
!
serial number FTX1234ABCD
Switch01#show ip interface brief
Interface              IP-Address      OK? Method Status                Protocol
Vlan10                 192.0.2.10      YES manual up                    up
GigabitEthernet1/0/10  unassigned      YES unset  up                    up
--More--
Switch01#`;

const EXAMPLE_AFTER_OUTPUT = `Switch01#show running-config interface GigabitEthernet1/0/10
hostname Branch-Router-01
vrf definition CUSTOMER-A
interface GigabitEthernet1/0/10
 description Uplink to customer ACME circuit CKT-44512
 switchport mode trunk
 switchport trunk allowed vlan 10,20,30,40
 snmp-server community exampleCommunity RO
 ip address 10.14.22.6 255.255.255.0
 no shutdown
!
router bgp 65001
 neighbor 198.51.100.10 remote-as 64512
!
Switch01#`;

const DEBOUNCE_MS = 250;
const RENDERED_FINDING_LIMIT = 200;

interface AppElements {
  rawOutput: HTMLTextAreaElement;
  rawOutputLabel: HTMLElement;
  afterPane: HTMLElement;
  afterOutput: HTMLTextAreaElement;
  cleanedOutput: HTMLTextAreaElement;
  profileSelect: HTMLSelectElement;
  documentModeSelect: HTMLSelectElement;
  vendorSelect: HTMLSelectElement;
  tokenMapToggle: HTMLInputElement;
  compareModeToggle: HTMLInputElement;
  vendorSuggestion: HTMLElement;
  cleanButton: HTMLButtonElement;
  copyTextButton: HTMLButtonElement;
  copyMarkdownButton: HTMLButtonElement;
  prepareAiButton: HTMLButtonElement;
  copyReceiptButton: HTMLButtonElement;
  exampleButton: HTMLButtonElement;
  clearButton: HTMLButtonElement;
  selectHighRiskButton: HTMLButtonElement;
  selectVisibleButton: HTMLButtonElement;
  clearSelectionButton: HTMLButtonElement;
  profileResetButton: HTMLButtonElement;
  severityFilter: HTMLSelectElement;
  categoryFilter: HTMLSelectElement;
  vendorFilter: HTMLSelectElement;
  sourceFilter: HTMLSelectElement;
  selectedFilter: HTMLSelectElement;
  confidenceFilter: HTMLSelectElement;
  statusMessage: HTMLElement;
  findingsTotal: HTMLElement;
  safeScore: HTMLElement;
  safeScoreStatus: HTMLElement;
  safeScoreReasons: HTMLElement;
  categoryCounts: HTMLElement;
  findingsList: HTMLOListElement;
  customRuleKind: HTMLSelectElement;
  customRuleCategory: HTMLSelectElement;
  customRuleAction: HTMLSelectElement;
  customRuleValue: HTMLInputElement;
  customRuleReplacement: HTMLInputElement;
  customRuleCaseSensitive: HTMLInputElement;
  addCustomRuleButton: HTMLButtonElement;
  clearCustomRulesButton: HTMLButtonElement;
  customPolicyStatus: HTMLElement;
  customRuleList: HTMLUListElement;
}

interface FindingFilters {
  severity: 'all' | SensitiveFinding['severity'];
  category: 'all' | SensitiveCategory;
  vendor: 'all' | VendorId;
  source: 'all' | FindingSource;
  selected: 'all' | 'selected' | 'unselected';
  confidence: 'all' | ConfidenceLevel;
}

type RedactionChangeHandler = (findingId: string, selected: boolean) => void;

interface ViewportScrollPosition {
  left: number;
  top: number;
}

export function initNetPasteApp(
  rootDocument: Document,
  options: AppSurfaceOptions = {}
): void {
  const surfaceConfig = resolveAppSurface(options);
  rootDocument.documentElement.dataset.netpasteSurface = surfaceConfig.surface;
  rootDocument.body.classList.add(surfaceConfig.rootClassName);

  const elements = getAppElements(rootDocument);
  populateSelects(elements, rootDocument);

  let cleanedSourceText = '';
  let selectedFindingIds = new Set<string>();
  let knownFindingIds = new Set<string>();
  let profileId: RedactionProfileId = 'custom-session';
  let documentMode: DocumentModeId = 'cli-config';
  let vendorSelection: VendorSelection = 'auto';
  let useTokenMapping = getProfile(profileId).useTokenMappingByDefault;
  let compareMode = false;
  let editDetectionTimer: number | undefined;
  let sessionPolicyRules: PolicyRule[] = [];
  let sessionPolicyRevision = 0;
  let nextSessionRuleNumber = 1;
  let activeSessionPolicy: CompiledPolicy | undefined;
  let sendBlockedByPolicy = false;

  elements.profileSelect.value = profileId;
  elements.documentModeSelect.value = documentMode;
  elements.vendorSelect.value = vendorSelection;
  elements.tokenMapToggle.checked = useTokenMapping;
  syncPolicyBuilderFields(elements);
  renderSessionPolicy(elements, rootDocument, sessionPolicyRules, undefined);

  const analyzeSourceText = (
    selectedIds: ReadonlySet<string> = selectedFindingIds
  ): AnalysisResult => {
    return analyzeCurrentText(
      getDetectionRawText(elements, compareMode),
      cleanedSourceText,
      RENDERED_FINDING_LIMIT,
      {
        profileId,
        documentMode,
        vendorId: vendorSelection,
        useTokenMapping,
        selectedIds,
        policy: activeSessionPolicy
      }
    );
  };

  const renderCurrentState = (analysis = analyzeSourceText()): AnalysisResult => {
    elements.cleanedOutput.value = applySelectedRedactions(
      cleanedSourceText,
      analysis.findings,
      selectedFindingIds
    );
    renderAnalysis(elements, analysis, rootDocument, selectedFindingIds, handleRedactionChange);
    knownFindingIds = getFindingIds(analysis.findings);
    sendBlockedByPolicy = hasUnhandledPolicyBlock(
      analysis.findings,
      selectedFindingIds
    );
    updateCopyButtons(elements, sendBlockedByPolicy);
    return analysis;
  };

  const resetSelectionsForProfile = (): AnalysisResult => {
    const analysis = analyzeSourceText(new Set());
    selectedFindingIds = getDefaultSelectedFindingIds(analysis.findings, profileId);
    return renderCurrentState(analyzeSourceText(selectedFindingIds));
  };

  const handleRedactionChange: RedactionChangeHandler = (findingId, selected) => {
    const scrollPosition = getViewportScrollPosition(rootDocument);

    if (selected) {
      selectedFindingIds.add(findingId);
    } else {
      selectedFindingIds.delete(findingId);
    }

    const analysis = renderCurrentState();
    setStatus(
      elements,
      hasUnhandledPolicyBlock(analysis.findings, selectedFindingIds)
        ? 'A blocking session-policy finding is unhandled. Copy actions remain unavailable.'
        : `Redaction selection updated. ${formatRedactionCount(
            selectedFindingIds.size
          )} selected.`
    );
    restoreFindingInteraction(elements, rootDocument, findingId, scrollPosition);
  };

  elements.cleanButton.addEventListener('click', () => {
    cleanedSourceText = buildCleanedSourceText(elements, compareMode);
    const analysis = resetSelectionsForProfile();
    setStatus(
      elements,
      `Output prepared. ${formatFindingCount(
        analysis.findings.length
      )} found. ${formatRedactionCount(selectedFindingIds.size)} selected.`
    );
  });

  elements.cleanedOutput.addEventListener('input', () => {
    cleanedSourceText = elements.cleanedOutput.value;
    window.clearTimeout(editDetectionTimer);
    editDetectionTimer = window.setTimeout(() => {
      const previousKnownFindingIds = knownFindingIds;
      const analysis = analyzeSourceText();
      selectedFindingIds = reconcileSelectedFindingIds(
        analysis.findings,
        selectedFindingIds,
        previousKnownFindingIds,
        profileId
      );
      renderCurrentState(analyzeSourceText(selectedFindingIds));
    }, DEBOUNCE_MS);
  });

  elements.rawOutput.addEventListener('input', () => {
    updateCopyButtons(elements, sendBlockedByPolicy);
  });

  elements.afterOutput.addEventListener('input', () => {
    updateCopyButtons(elements, sendBlockedByPolicy);
  });

  elements.profileSelect.addEventListener('change', () => {
    profileId = elements.profileSelect.value as RedactionProfileId;
    useTokenMapping = getProfile(profileId).useTokenMappingByDefault;
    elements.tokenMapToggle.checked = useTokenMapping;
    const analysis = resetSelectionsForProfile();
    setStatus(
      elements,
      `${getProfile(profileId).label} profile applied. ${formatRedactionCount(
        selectedFindingIds.size
      )} selected. Share status: ${analysis.shareScore.status}.`
    );
  });

  elements.documentModeSelect.addEventListener('change', () => {
    documentMode = elements.documentModeSelect.value as DocumentModeId;
    renderCurrentState();
  });

  elements.vendorSelect.addEventListener('change', () => {
    vendorSelection = elements.vendorSelect.value as VendorSelection;
    renderCurrentState();
  });

  elements.tokenMapToggle.addEventListener('change', () => {
    useTokenMapping = elements.tokenMapToggle.checked;
    renderCurrentState();
  });

  elements.compareModeToggle.addEventListener('change', () => {
    compareMode = elements.compareModeToggle.checked;
    elements.afterPane.classList.toggle('is-hidden', !compareMode);
    elements.rawOutputLabel.textContent = compareMode ? 'Before text' : 'Raw CLI output';
    if (compareMode && elements.afterOutput.value.length === 0 && elements.rawOutput.value === EXAMPLE_OUTPUT) {
      elements.afterOutput.value = EXAMPLE_AFTER_OUTPUT;
    }
    renderCurrentState();
  });

  const rerenderForFilters = (): void => {
    renderCurrentState();
  };
  elements.severityFilter.addEventListener('change', rerenderForFilters);
  elements.categoryFilter.addEventListener('change', rerenderForFilters);
  elements.vendorFilter.addEventListener('change', rerenderForFilters);
  elements.sourceFilter.addEventListener('change', rerenderForFilters);
  elements.selectedFilter.addEventListener('change', rerenderForFilters);
  elements.confidenceFilter.addEventListener('change', rerenderForFilters);

  elements.customRuleKind.addEventListener('change', () => {
    syncPolicyBuilderFields(elements);
  });

  elements.customRuleAction.addEventListener('change', () => {
    syncPolicyBuilderFields(elements);
  });

  elements.addCustomRuleButton.addEventListener('click', () => {
    try {
      const rule = buildSessionRule(elements, nextSessionRuleNumber);
      const candidateRules = [...sessionPolicyRules, rule];
      const candidateRevision = sessionPolicyRevision + 1;
      const compiled = compilePolicy(
        createSessionPolicy(candidateRules, candidateRevision)
      );

      sessionPolicyRules = candidateRules;
      sessionPolicyRevision = candidateRevision;
      nextSessionRuleNumber += 1;
      activeSessionPolicy = compiled;
      elements.customRuleValue.value = '';
      elements.customRuleReplacement.value = '';
      renderSessionPolicy(
        elements,
        rootDocument,
        sessionPolicyRules,
        activeSessionPolicy
      );
      const analysis = resetSelectionsForProfile();
      setStatus(
        elements,
        `Session rule added. ${formatFindingCount(analysis.findings.length)} found.`
      );
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unable to add the session rule.';
      elements.customPolicyStatus.textContent = message;
      setStatus(elements, 'Session rule was not added. Review the policy message.');
    }
  });

  elements.clearCustomRulesButton.addEventListener('click', () => {
    sessionPolicyRules = [];
    sessionPolicyRevision = 0;
    activeSessionPolicy = undefined;
    renderSessionPolicy(elements, rootDocument, sessionPolicyRules, undefined);
    const analysis = resetSelectionsForProfile();
    setStatus(
      elements,
      `Session rules cleared. ${formatFindingCount(analysis.findings.length)} found.`
    );
  });

  elements.selectHighRiskButton.addEventListener('click', () => {
    const analysis = analyzeSourceText();
    for (const finding of analysis.findings) {
      if (
        isRedactableFinding(finding) &&
        (finding.severity === 'High review priority' ||
          finding.profileAction === 'redact')
      ) {
        selectedFindingIds.add(finding.id);
      }
    }
    renderCurrentState(analyzeSourceText(selectedFindingIds));
    setStatus(elements, 'High-risk and profile-recommended findings selected.');
  });

  elements.selectVisibleButton.addEventListener('click', () => {
    const analysis = analyzeSourceText();
    const visibleFindings = getFilteredFindings(
      analysis.findings,
      getFindingFilters(elements),
      selectedFindingIds
    ).slice(0, RENDERED_FINDING_LIMIT);

    for (const finding of visibleFindings) {
      if (isRedactableFinding(finding)) {
        selectedFindingIds.add(finding.id);
      }
    }

    renderCurrentState(analyzeSourceText(selectedFindingIds));
    setStatus(elements, 'Visible redactable findings selected.');
  });

  elements.clearSelectionButton.addEventListener('click', () => {
    selectedFindingIds = new Set();
    renderCurrentState(analyzeSourceText(selectedFindingIds));
    setStatus(elements, 'All redaction selections cleared.');
  });

  elements.profileResetButton.addEventListener('click', () => {
    const analysis = resetSelectionsForProfile();
    setStatus(
      elements,
      `Profile defaults restored. ${formatRedactionCount(
        selectedFindingIds.size
      )} selected. Share status: ${analysis.shareScore.status}.`
    );
  });

  elements.copyTextButton.addEventListener('click', () => {
    copyToClipboard(
      getPlainTextCopyPayload(elements.cleanedOutput.value),
      rootDocument
    )
      .then(() => {
        setStatus(elements, 'Cleaned output copied as plain text.');
      })
      .catch(() => {
        setStatus(
          elements,
          'Unable to copy automatically. Select the cleaned output and copy it manually.'
        );
      });
  });

  elements.copyMarkdownButton.addEventListener('click', () => {
    copyToClipboard(
      getMarkdownCopyPayload(elements.cleanedOutput.value),
      rootDocument
    )
      .then(() => {
        setStatus(elements, 'Cleaned output copied as a Markdown code block.');
      })
      .catch(() => {
        setStatus(
          elements,
          'Unable to copy Markdown automatically. Select the cleaned output and copy it manually.'
        );
      });
  });

  elements.prepareAiButton.addEventListener('click', () => {
    profileId = 'ai-prompt';
    useTokenMapping = true;
    elements.profileSelect.value = profileId;
    elements.tokenMapToggle.checked = true;

    if (cleanedSourceText.length === 0) {
      cleanedSourceText = buildCleanedSourceText(elements, compareMode);
    }

    const analysis = resetSelectionsForProfile();
    const payload = getAiCopyPayload(elements.cleanedOutput.value, analysis);

    copyToClipboard(payload, rootDocument)
      .then(() => {
        setStatus(
          elements,
          `AI prompt Markdown copied. Share status: ${analysis.shareScore.status}.`
        );
      })
      .catch(() => {
        setStatus(
          elements,
          'Unable to copy AI prompt automatically. Select the cleaned output and copy it manually.'
        );
      });
  });

  elements.copyReceiptButton.addEventListener('click', () => {
    const analysis = analyzeSourceText(selectedFindingIds);
    createRedactionReceipt(
      getDetectionRawText(elements, compareMode),
      elements.cleanedOutput.value,
      analysis,
      selectedFindingIds
    )
      .then((receipt) =>
        copyToClipboard(serializeRedactionReceipt(receipt), rootDocument)
      )
      .then(() => {
        setStatus(elements, 'Non-secret redaction receipt copied as JSON.');
      })
      .catch(() => {
        setStatus(
          elements,
          'Unable to copy the receipt automatically. Review browser clipboard permissions.'
        );
      });
  });

  elements.exampleButton.addEventListener('click', () => {
    elements.rawOutput.value = EXAMPLE_OUTPUT;
    if (compareMode) {
      elements.afterOutput.value = EXAMPLE_AFTER_OUTPUT;
    }
    cleanedSourceText = buildCleanedSourceText(elements, compareMode);
    const analysis = resetSelectionsForProfile();
    setStatus(
      elements,
      `Example loaded. ${formatFindingCount(
        analysis.findings.length
      )} found. ${formatRedactionCount(selectedFindingIds.size)} selected.`
    );
  });

  elements.clearButton.addEventListener('click', () => {
    window.clearTimeout(editDetectionTimer);
    elements.rawOutput.value = '';
    elements.afterOutput.value = '';
    cleanedSourceText = '';
    selectedFindingIds = new Set();
    knownFindingIds = new Set();
    renderCurrentState(analyzeSourceText(selectedFindingIds));
    setStatus(elements, 'Input and output cleared.');
    elements.rawOutput.focus();
  });

  renderCurrentState();
  setStatus(elements, surfaceConfig.initialStatus);
}

export function getPlainTextCopyPayload(currentCleanedOutput: string): string {
  return currentCleanedOutput;
}

export function getMarkdownCopyPayload(currentCleanedOutput: string): string {
  return toMarkdownCodeBlock(currentCleanedOutput);
}

export function getAiCopyPayload(
  currentCleanedOutput: string,
  analysis: AnalysisResult
): string {
  return prepareForAi(currentCleanedOutput, analysis);
}

function getAppElements(rootDocument: Document): AppElements {
  return {
    rawOutput: getElement(rootDocument, 'raw-output', HTMLTextAreaElement),
    rawOutputLabel: getElement(rootDocument, 'raw-output-label', HTMLElement),
    afterPane: getElement(rootDocument, 'after-pane', HTMLElement),
    afterOutput: getElement(rootDocument, 'after-output', HTMLTextAreaElement),
    cleanedOutput: getElement(rootDocument, 'cleaned-output', HTMLTextAreaElement),
    profileSelect: getElement(rootDocument, 'profile-select', HTMLSelectElement),
    documentModeSelect: getElement(rootDocument, 'document-mode-select', HTMLSelectElement),
    vendorSelect: getElement(rootDocument, 'vendor-select', HTMLSelectElement),
    tokenMapToggle: getElement(rootDocument, 'token-map-toggle', HTMLInputElement),
    compareModeToggle: getElement(rootDocument, 'compare-mode-toggle', HTMLInputElement),
    vendorSuggestion: getElement(rootDocument, 'vendor-suggestion', HTMLElement),
    cleanButton: getElement(rootDocument, 'clean-button', HTMLButtonElement),
    copyTextButton: getElement(rootDocument, 'copy-text-button', HTMLButtonElement),
    copyMarkdownButton: getElement(
      rootDocument,
      'copy-markdown-button',
      HTMLButtonElement
    ),
    prepareAiButton: getElement(rootDocument, 'prepare-ai-button', HTMLButtonElement),
    copyReceiptButton: getElement(
      rootDocument,
      'copy-receipt-button',
      HTMLButtonElement
    ),
    exampleButton: getElement(rootDocument, 'example-button', HTMLButtonElement),
    clearButton: getElement(rootDocument, 'clear-button', HTMLButtonElement),
    selectHighRiskButton: getElement(
      rootDocument,
      'select-high-risk-button',
      HTMLButtonElement
    ),
    selectVisibleButton: getElement(
      rootDocument,
      'select-visible-button',
      HTMLButtonElement
    ),
    clearSelectionButton: getElement(
      rootDocument,
      'clear-selection-button',
      HTMLButtonElement
    ),
    profileResetButton: getElement(
      rootDocument,
      'profile-reset-button',
      HTMLButtonElement
    ),
    severityFilter: getElement(rootDocument, 'severity-filter', HTMLSelectElement),
    categoryFilter: getElement(rootDocument, 'category-filter', HTMLSelectElement),
    vendorFilter: getElement(rootDocument, 'vendor-filter', HTMLSelectElement),
    sourceFilter: getElement(rootDocument, 'source-filter', HTMLSelectElement),
    selectedFilter: getElement(rootDocument, 'selected-filter', HTMLSelectElement),
    confidenceFilter: getElement(
      rootDocument,
      'confidence-filter',
      HTMLSelectElement
    ),
    statusMessage: getElement(rootDocument, 'status-message', HTMLElement),
    findingsTotal: getElement(rootDocument, 'findings-total', HTMLElement),
    safeScore: getElement(rootDocument, 'safe-score', HTMLElement),
    safeScoreStatus: getElement(rootDocument, 'safe-score-status', HTMLElement),
    safeScoreReasons: getElement(rootDocument, 'safe-score-reasons', HTMLElement),
    categoryCounts: getElement(rootDocument, 'category-counts', HTMLElement),
    findingsList: getElement(rootDocument, 'findings-list', HTMLOListElement),
    customRuleKind: getElement(rootDocument, 'custom-rule-kind', HTMLSelectElement),
    customRuleCategory: getElement(
      rootDocument,
      'custom-rule-category',
      HTMLSelectElement
    ),
    customRuleAction: getElement(
      rootDocument,
      'custom-rule-action',
      HTMLSelectElement
    ),
    customRuleValue: getElement(rootDocument, 'custom-rule-value', HTMLInputElement),
    customRuleReplacement: getElement(
      rootDocument,
      'custom-rule-replacement',
      HTMLInputElement
    ),
    customRuleCaseSensitive: getElement(
      rootDocument,
      'custom-rule-case-sensitive',
      HTMLInputElement
    ),
    addCustomRuleButton: getElement(
      rootDocument,
      'add-custom-rule-button',
      HTMLButtonElement
    ),
    clearCustomRulesButton: getElement(
      rootDocument,
      'clear-custom-rules-button',
      HTMLButtonElement
    ),
    customPolicyStatus: getElement(
      rootDocument,
      'custom-policy-status',
      HTMLElement
    ),
    customRuleList: getElement(rootDocument, 'custom-rule-list', HTMLUListElement)
  };
}

function getElement<T extends HTMLElement>(
  rootDocument: Document,
  id: string,
  constructor: { new (...args: never[]): T }
): T {
  const element = rootDocument.getElementById(id);

  if (!(element instanceof constructor)) {
    throw new Error(`Missing required element: ${id}`);
  }

  return element;
}

function populateSelects(elements: AppElements, rootDocument: Document): void {
  elements.profileSelect.replaceChildren(
    ...redactionProfiles.map((profile) =>
      createOption(rootDocument, profile.id, profile.label)
    )
  );
  elements.documentModeSelect.replaceChildren(
    ...documentModes.map((mode) => createOption(rootDocument, mode.id, mode.label))
  );
  elements.vendorSelect.replaceChildren(
    createOption(rootDocument, 'auto', 'Auto-suggest'),
    ...vendorDefinitions.map((vendor) =>
      createOption(rootDocument, vendor.id, vendor.label)
    )
  );
  elements.categoryFilter.replaceChildren(
    createOption(rootDocument, 'all', 'All'),
    ...sensitiveCategories.map((category) =>
      createOption(rootDocument, category, category)
    )
  );
  elements.customRuleCategory.replaceChildren(
    ...sensitiveCategories.map((category) =>
      createOption(rootDocument, category, category)
    )
  );
  elements.vendorFilter.replaceChildren(
    createOption(rootDocument, 'all', 'All'),
    ...vendorDefinitions.map((vendor) =>
      createOption(rootDocument, vendor.id, vendor.label)
    )
  );
}

function createOption(
  rootDocument: Document,
  value: string,
  label: string
): HTMLOptionElement {
  const option = rootDocument.createElement('option');
  option.value = value;
  option.textContent = label;
  return option;
}

function buildSessionRule(
  elements: AppElements,
  ruleNumber: number
): PolicyRule {
  const rawValue = elements.customRuleValue.value.trim();
  if (!rawValue) {
    throw new Error('Enter a protected value, IPv4 CIDR range, or regular expression.');
  }

  const action = elements.customRuleAction.value as PolicyAction;
  const replacementLabel = elements.customRuleReplacement.value.trim();
  const matcher = buildPolicyMatcher(elements, rawValue);

  return {
    id: `session-rule-${ruleNumber}`,
    category: elements.customRuleCategory.value as SensitiveCategory,
    description: `Session ${matcher.kind} policy rule.`,
    matcher,
    action,
    severity: action === 'block' ? 'High review priority' : 'Review',
    replacementLabel:
      action === 'replace' && replacementLabel ? replacementLabel : undefined,
    priority: Math.max(1, 1000 - ruleNumber)
  };
}

function buildPolicyMatcher(
  elements: AppElements,
  rawValue: string
): PolicyMatcher {
  switch (elements.customRuleKind.value) {
    case 'regex':
      return {
        kind: 'regex',
        pattern: rawValue,
        flags: elements.customRuleCaseSensitive.checked ? '' : 'i'
      };
    case 'cidr':
      return {
        kind: 'cidr',
        ranges: splitSessionValues(rawValue)
      };
    case 'dictionary':
    default:
      return {
        kind: 'dictionary',
        values: splitSessionValues(rawValue),
        caseSensitive: elements.customRuleCaseSensitive.checked
      };
  }
}

function splitSessionValues(rawValue: string): string[] {
  return rawValue
    .split(',')
    .map((value) => value.trim())
    .filter(Boolean);
}

function syncPolicyBuilderFields(elements: AppElements): void {
  const kind = elements.customRuleKind.value;
  elements.customRuleValue.placeholder =
    kind === 'regex'
      ? 'Safe regular expression, up to 160 characters'
      : kind === 'cidr'
        ? 'Comma-separated IPv4 ranges, for example 10.31.0.0/16'
        : 'Comma-separated protected values';
  elements.customRuleCaseSensitive.disabled = kind === 'cidr';
  if (kind === 'cidr') elements.customRuleCaseSensitive.checked = false;

  const usesReplacement = elements.customRuleAction.value === 'replace';
  elements.customRuleReplacement.disabled = !usesReplacement;
  if (!usesReplacement) elements.customRuleReplacement.value = '';
}

function renderSessionPolicy(
  elements: AppElements,
  rootDocument: Document,
  rules: readonly PolicyRule[],
  compiledPolicy: CompiledPolicy | undefined
): void {
  elements.clearCustomRulesButton.disabled = rules.length === 0;
  elements.customPolicyStatus.textContent = compiledPolicy
    ? `${rules.length} ${rules.length === 1 ? 'rule' : 'rules'} active; ${compiledPolicy.version}. Values and aliases remain in memory only.`
    : 'No custom session rules.';

  const items = rules.map((rule) => {
    const item = rootDocument.createElement('li');
    item.textContent = `${formatMatcherSummary(rule.matcher)}; ${rule.category}; ${formatPolicyAction(rule.action)}`;
    return item;
  });
  elements.customRuleList.replaceChildren(...items);
}

function formatMatcherSummary(matcher: PolicyMatcher): string {
  switch (matcher.kind) {
    case 'regex':
      return 'Regular expression';
    case 'dictionary':
      return `Protected dictionary (${matcher.values.length} ${matcher.values.length === 1 ? 'value' : 'values'})`;
    case 'cidr':
      return `IPv4 CIDR (${matcher.ranges.length} ${matcher.ranges.length === 1 ? 'range' : 'ranges'})`;
    case 'syntax':
      return 'Syntax matcher';
  }
}

function buildCleanedSourceText(elements: AppElements, compareMode: boolean): string {
  if (!compareMode) {
    return cleanText(elements.rawOutput.value);
  }

  return buildUnifiedDiff(
    cleanText(elements.rawOutput.value),
    cleanText(elements.afterOutput.value),
    'before',
    'after'
  );
}

function getDetectionRawText(elements: AppElements, compareMode: boolean): string {
  if (!compareMode) {
    return elements.rawOutput.value;
  }

  return `${elements.rawOutput.value}\n${elements.afterOutput.value}`;
}

function renderAnalysis(
  elements: AppElements,
  analysis: AnalysisResult,
  rootDocument: Document,
  selectedFindingIds: ReadonlySet<string>,
  onRedactionChange: RedactionChangeHandler
): void {
  elements.findingsTotal.textContent = formatFindingCount(analysis.findings.length);
  renderVendorSuggestion(elements, analysis);
  renderSafeScore(elements, analysis);
  renderCategoryCounts(elements.categoryCounts, analysis.categoryCounts, rootDocument);
  renderFindings(
    elements.findingsList,
    analysis,
    rootDocument,
    selectedFindingIds,
    getFindingFilters(elements),
    onRedactionChange
  );
}

function renderVendorSuggestion(
  elements: AppElements,
  analysis: AnalysisResult
): void {
  const suggested = getVendorLabel(analysis.vendorSuggestion.vendor);
  const active = getVendorLabel(analysis.activeVendor);

  elements.vendorSuggestion.textContent =
    elements.vendorSelect.value === 'auto'
      ? `Suggested rule pack: ${suggested} (${analysis.vendorSuggestion.confidence}).`
      : `Using ${active}. Suggested: ${suggested} (${analysis.vendorSuggestion.confidence}).`;
}

function renderSafeScore(elements: AppElements, analysis: AnalysisResult): void {
  elements.safeScore.dataset.status = analysis.shareScore.status;
  elements.safeScoreStatus.textContent = analysis.shareScore.status;
  elements.safeScoreReasons.textContent = [
    ...analysis.shareScore.reasons,
    ...analysis.unsupportedContent
  ].join(' ');
}

function renderCategoryCounts(
  container: HTMLElement,
  counts: FindingsSummary,
  rootDocument: Document
): void {
  const visibleCategories = sensitiveCategories.filter(
    (category) => counts[category] > 0
  );
  const categories =
    visibleCategories.length > 0 ? visibleCategories : sensitiveCategories.slice(0, 6);
  const fragments = categories.map((category) => {
    const item = rootDocument.createElement('div');
    item.className = 'category-count';

    const value = rootDocument.createElement('strong');
    value.textContent = String(counts[category]);

    const label = rootDocument.createElement('span');
    label.textContent = category;

    item.append(value, label);
    return item;
  });

  container.replaceChildren(...fragments);
}

function renderFindings(
  list: HTMLOListElement,
  analysis: AnalysisResult,
  rootDocument: Document,
  selectedFindingIds: ReadonlySet<string>,
  filters: FindingFilters,
  onRedactionChange: RedactionChangeHandler
): void {
  const filteredFindings = getFilteredFindings(
    analysis.findings,
    filters,
    selectedFindingIds
  );
  const renderedFindings = filteredFindings.slice(0, RENDERED_FINDING_LIMIT);

  if (renderedFindings.length === 0) {
    const emptyItem = rootDocument.createElement('li');
    emptyItem.className = 'empty-finding';
    emptyItem.textContent =
      analysis.findings.length === 0
        ? 'No common sensitive patterns found.'
        : 'No findings match the active filters.';
    list.replaceChildren(emptyItem);
    return;
  }

  const renderedItems = renderedFindings.map((finding) =>
    createFindingItem(
      finding,
      rootDocument,
      selectedFindingIds,
      onRedactionChange
    )
  );
  const hiddenCount = Math.max(0, filteredFindings.length - renderedFindings.length);

  if (hiddenCount > 0 || analysis.hiddenFindingCount > 0) {
    const cappedItem = rootDocument.createElement('li');
    cappedItem.className = 'empty-finding';
    cappedItem.textContent = `${Math.max(
      hiddenCount,
      analysis.hiddenFindingCount
    )} additional findings are not shown. Category counts include all findings.`;
    renderedItems.push(cappedItem);
  }

  list.replaceChildren(...renderedItems);
}

function getFilteredFindings(
  findings: SensitiveFinding[],
  filters: FindingFilters,
  selectedFindingIds: ReadonlySet<string>
): SensitiveFinding[] {
  return findings.filter((finding) => {
    if (filters.severity !== 'all' && finding.severity !== filters.severity) {
      return false;
    }

    if (filters.category !== 'all' && finding.category !== filters.category) {
      return false;
    }

    if (filters.vendor !== 'all' && finding.vendor !== filters.vendor) {
      return false;
    }

    if (filters.source !== 'all' && finding.source !== filters.source) {
      return false;
    }

    if (filters.confidence !== 'all' && finding.confidence !== filters.confidence) {
      return false;
    }

    if (
      filters.selected === 'selected' &&
      !selectedFindingIds.has(finding.id)
    ) {
      return false;
    }

    if (
      filters.selected === 'unselected' &&
      selectedFindingIds.has(finding.id)
    ) {
      return false;
    }

    return true;
  });
}

function getFindingFilters(elements: AppElements): FindingFilters {
  return {
    severity: elements.severityFilter.value as FindingFilters['severity'],
    category: elements.categoryFilter.value as FindingFilters['category'],
    vendor: elements.vendorFilter.value as FindingFilters['vendor'],
    source: elements.sourceFilter.value as FindingFilters['source'],
    selected: elements.selectedFilter.value as FindingFilters['selected'],
    confidence: elements.confidenceFilter.value as FindingFilters['confidence']
  };
}

function createFindingItem(
  finding: SensitiveFinding,
  rootDocument: Document,
  selectedFindingIds: ReadonlySet<string>,
  onRedactionChange: RedactionChangeHandler
): HTMLLIElement {
  const item = rootDocument.createElement('li');
  item.className =
    finding.severity === 'High review priority'
      ? 'finding-item high-priority'
      : 'finding-item';

  const meta = rootDocument.createElement('div');
  meta.className = 'finding-meta';

  const category = rootDocument.createElement('strong');
  category.textContent = finding.category;

  const severity = rootDocument.createElement('span');
  severity.textContent = finding.severity;

  const location = rootDocument.createElement('span');
  location.textContent = formatLocation(finding);

  const confidence = rootDocument.createElement('span');
  confidence.textContent = `${finding.confidence} confidence`;

  const vendor = rootDocument.createElement('span');
  vendor.textContent = getVendorLabel(finding.vendor);

  const action = rootDocument.createElement('span');
  action.textContent = finding.policyAction
    ? formatPolicyAction(finding.policyAction)
    : formatProfileAction(finding.profileAction);

  const token = rootDocument.createElement('span');
  token.textContent =
    finding.replacementLabel ??
    finding.replacementToken ??
    getFallbackTokenLabel(finding.category);

  const redactControl = createRedactionControl(
    finding,
    rootDocument,
    selectedFindingIds,
    onRedactionChange
  );

  meta.append(
    category,
    severity,
    location,
    confidence,
    vendor,
    action,
    token,
    redactControl
  );

  const preview = rootDocument.createElement('p');
  preview.className = 'finding-preview';
  preview.textContent = finding.preview;

  const reason = rootDocument.createElement('p');
  reason.className = 'finding-reason';
  reason.textContent = `${finding.ruleId}: ${finding.reason}`;

  item.append(meta, preview, reason);
  return item;
}

function createRedactionControl(
  finding: SensitiveFinding,
  rootDocument: Document,
  selectedFindingIds: ReadonlySet<string>,
  onRedactionChange: RedactionChangeHandler
): HTMLLabelElement {
  const label = rootDocument.createElement('label');
  label.className = 'finding-redact-control';

  const checkbox = rootDocument.createElement('input');
  checkbox.type = 'checkbox';
  checkbox.dataset.findingId = finding.id;
  checkbox.checked =
    isRedactableFinding(finding) && selectedFindingIds.has(finding.id);
  checkbox.disabled = !isRedactableFinding(finding);
  checkbox.setAttribute(
    'aria-label',
    checkbox.disabled
      ? `Cannot redact ${finding.category}; no cleaned-output match`
      : `Redact ${finding.category}`
  );
  checkbox.addEventListener('change', () => {
    onRedactionChange(finding.id, checkbox.checked);
  });

  label.append(checkbox, checkbox.disabled ? 'Original only' : 'Redact');

  return label;
}

function getViewportScrollPosition(
  rootDocument: Document
): ViewportScrollPosition | undefined {
  const view = rootDocument.defaultView;

  if (!view) {
    return undefined;
  }

  return {
    left: view.scrollX,
    top: view.scrollY
  };
}

function restoreFindingInteraction(
  elements: AppElements,
  rootDocument: Document,
  findingId: string,
  scrollPosition: ViewportScrollPosition | undefined
): void {
  restoreViewportScroll(rootDocument, scrollPosition);
  findRedactionCheckbox(elements.findingsList, findingId)?.focus({
    preventScroll: true
  });
  rootDocument.defaultView?.requestAnimationFrame(() => {
    restoreViewportScroll(rootDocument, scrollPosition);
  });
}

function restoreViewportScroll(
  rootDocument: Document,
  scrollPosition: ViewportScrollPosition | undefined
): void {
  if (!scrollPosition) {
    return;
  }

  rootDocument.defaultView?.scrollTo(scrollPosition.left, scrollPosition.top);
}

function findRedactionCheckbox(
  list: HTMLOListElement,
  findingId: string
): HTMLInputElement | undefined {
  return [...list.querySelectorAll<HTMLInputElement>('input[data-finding-id]')].find(
    (checkbox) => checkbox.dataset.findingId === findingId
  );
}

function formatLocation(finding: SensitiveFinding): string {
  if (finding.source === 'both') {
    return `Original line ${finding.originalLine}, cleaned line ${finding.cleanedLine}`;
  }

  if (finding.source === 'original') {
    return `Original line ${finding.originalLine}`;
  }

  return `Cleaned line ${finding.cleanedLine}`;
}

function formatProfileAction(action: SensitiveFinding['profileAction']): string {
  switch (action) {
    case 'redact':
      return 'Profile redacts';
    case 'allow':
      return 'Profile allows';
    case 'review':
    default:
      return 'Profile reviews';
  }
}

function formatPolicyAction(action: PolicyAction): string {
  switch (action) {
    case 'allow':
      return 'Policy allows';
    case 'review':
      return 'Policy reviews';
    case 'replace':
      return 'Policy replaces';
    case 'alias':
      return 'Policy aliases';
    case 'block':
      return 'Policy blocks';
  }
}

function getFallbackTokenLabel(category: SensitiveCategory): string {
  return category === 'Credential or secret' ? '<REDACTED:SECRET>' : '<REDACTED>';
}

function formatFindingCount(count: number): string {
  return count === 1 ? '1 finding' : `${count} findings`;
}

function formatRedactionCount(count: number): string {
  return count === 1 ? '1 redaction' : `${count} redactions`;
}

function setStatus(elements: AppElements, message: string): void {
  elements.statusMessage.textContent = message;
}

function updateCopyButtons(
  elements: AppElements,
  sendBlockedByPolicy = false
): void {
  const hasOutput = elements.cleanedOutput.value.length > 0;
  elements.copyTextButton.disabled = !hasOutput || sendBlockedByPolicy;
  elements.copyMarkdownButton.disabled = !hasOutput || sendBlockedByPolicy;
  elements.copyReceiptButton.disabled = !hasOutput;
  elements.prepareAiButton.disabled =
    sendBlockedByPolicy || (!hasOutput && elements.rawOutput.value.length === 0);
}

function hasUnhandledPolicyBlock(
  findings: readonly SensitiveFinding[],
  selectedIds: ReadonlySet<string>
): boolean {
  return findings.some(
    (finding) =>
      finding.policyAction === 'block' &&
      finding.redactionRanges.length > 0 &&
      !selectedIds.has(finding.id)
  );
}

async function copyToClipboard(
  text: string,
  rootDocument: Document
): Promise<void> {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(text);
    return;
  }

  const fallback = rootDocument.createElement('textarea');
  fallback.value = text;
  fallback.setAttribute('readonly', 'true');
  fallback.style.position = 'fixed';
  fallback.style.left = '-9999px';
  rootDocument.body.append(fallback);
  fallback.select();

  try {
    const copied = rootDocument.execCommand('copy');
    if (!copied) {
      throw new Error('Clipboard fallback failed');
    }
  } finally {
    fallback.remove();
  }
}

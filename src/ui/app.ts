import { analyzeCurrentText } from '../core/analysis';
import { cleanText } from '../core/cleanText';
import { toMarkdownCodeBlock } from '../core/markdown';
import {
  applySelectedRedactions,
  getDefaultSelectedFindingIds,
  getFindingIds,
  isRedactableFinding,
  reconcileSelectedFindingIds
} from '../core/redaction';
import {
  type AnalysisResult,
  type FindingsSummary,
  type SensitiveFinding,
  sensitiveCategories
} from '../core/types';

const EXAMPLE_OUTPUT = `Switch01#show running-config interface GigabitEthernet1/0/10
\x1b[32mBuilding configuration...\x1b[0m

interface GigabitEthernet1/0/10
 description Uplink to core
 switchport mode trunk
 switchport trunk allowed vlan 10,20,30
 snmp-server community exampleCommunity RO
 no shutdown
!
Switch01#show ip interface brief
Interface              IP-Address      OK? Method Status                Protocol
Vlan10                 192.0.2.10      YES manual up                    up
GigabitEthernet1/0/10  unassigned      YES unset  up                    up
--More--
Switch01#`;

const DEBOUNCE_MS = 250;
const RENDERED_FINDING_LIMIT = 200;

interface AppElements {
  rawOutput: HTMLTextAreaElement;
  cleanedOutput: HTMLTextAreaElement;
  cleanButton: HTMLButtonElement;
  copyTextButton: HTMLButtonElement;
  copyMarkdownButton: HTMLButtonElement;
  exampleButton: HTMLButtonElement;
  clearButton: HTMLButtonElement;
  statusMessage: HTMLElement;
  findingsTotal: HTMLElement;
  categoryCounts: HTMLElement;
  findingsList: HTMLOListElement;
}

type RedactionChangeHandler = (findingId: string, selected: boolean) => void;

export function initNetPasteApp(rootDocument: Document): void {
  const elements = getAppElements(rootDocument);
  let cleanedSourceText = '';
  let selectedFindingIds = new Set<string>();
  let knownFindingIds = new Set<string>();
  let editDetectionTimer: number | undefined;

  const analyzeSourceText = (): AnalysisResult => {
    return analyzeCurrentText(
      elements.rawOutput.value,
      cleanedSourceText,
      RENDERED_FINDING_LIMIT
    );
  };

  const renderCurrentState = (analysis = analyzeSourceText()): AnalysisResult => {
    elements.cleanedOutput.value = applySelectedRedactions(
      cleanedSourceText,
      analysis.findings,
      selectedFindingIds
    );
    renderAnalysis(elements, analysis, rootDocument);
    knownFindingIds = getFindingIds(analysis.findings);
    updateCopyButtons(elements);
    return analysis;
  };

  const handleRedactionChange: RedactionChangeHandler = (findingId, selected) => {
    if (selected) {
      selectedFindingIds.add(findingId);
    } else {
      selectedFindingIds.delete(findingId);
    }

    renderCurrentState();
    setStatus(
      elements,
      `Redaction selection updated. ${formatRedactionCount(
        selectedFindingIds.size
      )} selected.`
    );
  };

  elements.cleanButton.addEventListener('click', () => {
    cleanedSourceText = cleanText(elements.rawOutput.value);
    const analysis = analyzeSourceText();
    selectedFindingIds = getDefaultSelectedFindingIds(analysis.findings);
    renderCurrentState(analysis);
    setStatus(
      elements,
      `Output cleaned. ${formatFindingCount(
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
        previousKnownFindingIds
      );
      renderCurrentState(analysis);
    }, DEBOUNCE_MS);
  });

  elements.rawOutput.addEventListener('input', () => {
    updateCopyButtons(elements);
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

  elements.exampleButton.addEventListener('click', () => {
    elements.rawOutput.value = EXAMPLE_OUTPUT;
    cleanedSourceText = cleanText(EXAMPLE_OUTPUT);
    const analysis = analyzeSourceText();
    selectedFindingIds = getDefaultSelectedFindingIds(analysis.findings);
    renderCurrentState(analysis);
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
    cleanedSourceText = '';
    selectedFindingIds = new Set();
    knownFindingIds = new Set();
    renderCurrentState();
    setStatus(elements, 'Input and output cleared.');
    elements.rawOutput.focus();
  });

  renderCurrentState();

  function renderAnalysis(
    currentElements: AppElements,
    analysis: AnalysisResult,
    currentDocument: Document
  ): void {
    currentElements.findingsTotal.textContent = formatFindingCount(
      analysis.findings.length
    );
    renderCategoryCounts(
      currentElements.categoryCounts,
      analysis.categoryCounts,
      currentDocument
    );
    renderFindings(
      currentElements.findingsList,
      analysis,
      currentDocument,
      selectedFindingIds,
      handleRedactionChange
    );
  }
}

export function getPlainTextCopyPayload(currentCleanedOutput: string): string {
  return currentCleanedOutput;
}

export function getMarkdownCopyPayload(currentCleanedOutput: string): string {
  return toMarkdownCodeBlock(currentCleanedOutput);
}

function getAppElements(rootDocument: Document): AppElements {
  return {
    rawOutput: getElement(rootDocument, 'raw-output', HTMLTextAreaElement),
    cleanedOutput: getElement(rootDocument, 'cleaned-output', HTMLTextAreaElement),
    cleanButton: getElement(rootDocument, 'clean-button', HTMLButtonElement),
    copyTextButton: getElement(rootDocument, 'copy-text-button', HTMLButtonElement),
    copyMarkdownButton: getElement(
      rootDocument,
      'copy-markdown-button',
      HTMLButtonElement
    ),
    exampleButton: getElement(rootDocument, 'example-button', HTMLButtonElement),
    clearButton: getElement(rootDocument, 'clear-button', HTMLButtonElement),
    statusMessage: getElement(rootDocument, 'status-message', HTMLElement),
    findingsTotal: getElement(rootDocument, 'findings-total', HTMLElement),
    categoryCounts: getElement(rootDocument, 'category-counts', HTMLElement),
    findingsList: getElement(rootDocument, 'findings-list', HTMLOListElement)
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

function renderCategoryCounts(
  container: HTMLElement,
  counts: FindingsSummary,
  rootDocument: Document
): void {
  const fragments = sensitiveCategories.map((category) => {
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
  onRedactionChange: RedactionChangeHandler
): void {
  if (analysis.renderedFindings.length === 0) {
    const emptyItem = rootDocument.createElement('li');
    emptyItem.className = 'empty-finding';
    emptyItem.textContent = 'No common sensitive patterns found.';
    list.replaceChildren(emptyItem);
    return;
  }

  const renderedItems = analysis.renderedFindings.map((finding) =>
    createFindingItem(
      finding,
      rootDocument,
      selectedFindingIds,
      onRedactionChange
    )
  );

  if (analysis.hiddenFindingCount > 0) {
    const cappedItem = rootDocument.createElement('li');
    cappedItem.className = 'empty-finding';
    cappedItem.textContent = `${analysis.hiddenFindingCount} additional findings are not shown. Category counts include all findings.`;
    renderedItems.push(cappedItem);
  }

  list.replaceChildren(...renderedItems);
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

  const redactControl = createRedactionControl(
    finding,
    rootDocument,
    selectedFindingIds,
    onRedactionChange
  );

  meta.append(category, severity, location, redactControl);

  const preview = rootDocument.createElement('p');
  preview.className = 'finding-preview';
  preview.textContent = finding.preview;

  item.append(meta, preview);
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

  label.append(
    checkbox,
    checkbox.disabled ? 'Original only' : 'Redact'
  );

  return label;
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

function formatFindingCount(count: number): string {
  return count === 1 ? '1 finding' : `${count} findings`;
}

function formatRedactionCount(count: number): string {
  return count === 1 ? '1 redaction' : `${count} redactions`;
}

function setStatus(elements: AppElements, message: string): void {
  elements.statusMessage.textContent = message;
}

function updateCopyButtons(elements: AppElements): void {
  const hasOutput = elements.cleanedOutput.value.length > 0;
  elements.copyTextButton.disabled = !hasOutput;
  elements.copyMarkdownButton.disabled = !hasOutput;
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

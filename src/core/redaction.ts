import { applyProfileDefaults } from './profiles';
import type {
  RedactionProfileId,
  SensitiveCategory,
  SensitiveFinding,
  TextRange
} from './types';

interface RedactionReplacement extends TextRange {
  label: string;
}

const GENERIC_REDACTION_LABEL = '<REDACTED>';

const CREDENTIAL_LABEL_RULES = [
  {
    pattern: /\bsnmp-server\s+community\b|\bcommunity\b/gi,
    label: '<REDACTED:COMMUNITY>'
  },
  {
    pattern: /\b(?:authorization|bearer|token|api[-_ ]?key)\b/gi,
    label: '<REDACTED:TOKEN>'
  },
  {
    pattern:
      /\b(?:enable\s+secret|secret|private\s+key|pre-shared\s+key|preshared\s+key|key-string|authentication\s+key|crypto\s+isakmp\s+key)\b/gi,
    label: '<REDACTED:SECRET>'
  },
  {
    pattern: /\b(?:password|passwd|username)\b/gi,
    label: '<REDACTED:CREDENTIAL>'
  }
] as const;

export function applySelectedRedactions(
  cleanedText: string,
  findings: SensitiveFinding[],
  selectedIds: ReadonlySet<string>,
  replacementLabels: ReadonlyMap<string, string> = new Map()
): string {
  const replacements = findings
    .filter((finding) => selectedIds.has(finding.id))
    .flatMap((finding) =>
      finding.redactionRanges.map((range) => ({
        ...range,
        label:
          replacementLabels.get(finding.id) ??
          finding.replacementLabel ??
          finding.replacementToken ??
          getRedactionLabel(finding, cleanedText, range)
      }))
    );

  return replaceRanges(cleanedText, mergeReplacements(replacements));
}

export function getDefaultSelectedFindingIds(
  findings: SensitiveFinding[],
  profileId: RedactionProfileId = 'custom-session'
): Set<string> {
  return applyProfileDefaults(findings, profileId);
}

export function reconcileSelectedFindingIds(
  findings: SensitiveFinding[],
  selectedIds: ReadonlySet<string>,
  previouslyKnownIds: ReadonlySet<string>,
  profileId: RedactionProfileId = 'custom-session'
): Set<string> {
  const currentIds = new Set(findings.map((finding) => finding.id));
  const nextSelectedIds = new Set(
    [...selectedIds].filter((id) => currentIds.has(id))
  );

  for (const finding of findings) {
    if (
      !previouslyKnownIds.has(finding.id) &&
      isDefaultSelectedFinding(finding, profileId)
    ) {
      nextSelectedIds.add(finding.id);
    }
  }

  return nextSelectedIds;
}

export function getFindingIds(findings: SensitiveFinding[]): Set<string> {
  return new Set(findings.map((finding) => finding.id));
}

export function isRedactableFinding(finding: SensitiveFinding): boolean {
  return finding.redactionRanges.length > 0;
}

function isDefaultSelectedFinding(
  finding: SensitiveFinding,
  profileId: RedactionProfileId
): boolean {
  return (
    isRedactableFinding(finding) &&
    (finding.profileAction === 'redact' ||
      applyProfileDefaults([finding], profileId).has(finding.id))
  );
}

function replaceRanges(
  text: string,
  replacements: RedactionReplacement[]
): string {
  let redactedText = text;

  for (const replacement of [...replacements].sort(
    (left, right) => right.start - left.start
  )) {
    redactedText = replaceRange(redactedText, replacement);
  }

  return redactedText;
}

function replaceRange(text: string, replacement: RedactionReplacement): string {
  const range = clampRange(text, replacement);

  if (!range) {
    return text;
  }

  return `${text.slice(0, range.start)}${replacement.label}${text.slice(range.end)}`;
}

function clampRange(text: string, range: TextRange): TextRange | undefined {
  const start = Math.max(0, Math.min(range.start, text.length));
  const end = Math.max(start, Math.min(range.end, text.length));

  if (end <= start) {
    return undefined;
  }

  return { start, end };
}

function mergeReplacements(
  replacements: RedactionReplacement[]
): RedactionReplacement[] {
  const sortedReplacements = replacements
    .filter((replacement) => replacement.end > replacement.start)
    .sort((left, right) => {
      return (
        left.start - right.start ||
        right.end - left.end ||
        left.label.localeCompare(right.label)
      );
    });
  const mergedReplacements: RedactionReplacement[] = [];

  for (const replacement of sortedReplacements) {
    const lastReplacement = mergedReplacements.at(-1);

    if (!lastReplacement || replacement.start > lastReplacement.end) {
      mergedReplacements.push({ ...replacement });
      continue;
    }

    if (replacement.label !== lastReplacement.label) {
      lastReplacement.label = GENERIC_REDACTION_LABEL;
    }

    if (replacement.end > lastReplacement.end) {
      lastReplacement.end = replacement.end;
    }
  }

  return mergedReplacements;
}

function getRedactionLabel(
  finding: SensitiveFinding,
  text: string,
  range: TextRange
): string {
  if (finding.category === 'Credential or secret') {
    return getCredentialRedactionLabel(text, range);
  }

  return getCategoryRedactionLabel(finding.category);
}

function getCategoryRedactionLabel(category: SensitiveCategory): string {
  switch (category) {
    case 'IPv4 address':
    case 'IPv6 address':
    case 'Public IP address':
    case 'Private IP address':
      return '<REDACTED:IP>';
    case 'MAC address':
      return '<REDACTED:MAC>';
    case 'Email address':
      return '<REDACTED:EMAIL>';
    case 'URL':
      return '<REDACTED:URL>';
    case 'Hostname prompt':
    case 'Hostname':
      return '<REDACTED:HOST>';
    case 'Interface name':
      return '<REDACTED:IFACE>';
    case 'VRF name':
      return '<REDACTED:VRF>';
    case 'VLAN identifier':
      return '<REDACTED:VLAN>';
    case 'BGP ASN':
      return '<REDACTED:ASN>';
    case 'Serial number':
      return '<REDACTED:SERIAL>';
    case 'Circuit ID':
      return '<REDACTED:CIRCUIT>';
    case 'Site or customer label':
      return '<REDACTED:SITE>';
    case 'Certificate or key material':
      return '<REDACTED:KEY-MATERIAL>';
    case 'Cloud identifier':
      return '<REDACTED:CLOUD>';
    case 'Config comment metadata':
      return '<REDACTED:COMMENT>';
    default:
      return GENERIC_REDACTION_LABEL;
  }
}

function getCredentialRedactionLabel(text: string, range: TextRange): string {
  const lineStart = Math.max(text.lastIndexOf('\n', range.start - 1) + 1, 0);
  const prefix = text.slice(lineStart, range.start).toLowerCase();
  let nearestLabel:
    | {
        index: number;
        label: string;
      }
    | undefined;

  for (const rule of CREDENTIAL_LABEL_RULES) {
    rule.pattern.lastIndex = 0;

    for (const match of prefix.matchAll(rule.pattern)) {
      const index = match.index ?? 0;

      if (!nearestLabel || index > nearestLabel.index) {
        nearestLabel = { index, label: rule.label };
      }
    }
  }

  return nearestLabel?.label ?? '<REDACTED:CREDENTIAL>';
}

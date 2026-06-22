import {
  type FindingsSummary,
  type SensitiveCategory,
  type SensitiveFinding,
  type TextRange,
  sensitiveCategories
} from './types';
import { normalizeLineEndings, removeAnsiSequences } from './cleanText';
import { maskSensitiveText } from './maskSensitive';

type FindingSource = 'original' | 'cleaned';

interface RawFinding {
  category: SensitiveCategory;
  severity: SensitiveFinding['severity'];
  preview: string;
  source: FindingSource;
  line: number;
  canonical: string;
  redactionRanges: TextRange[];
}

interface MergedFinding extends SensitiveFinding {
  canonical: string;
  order: number;
}

const MAX_PREVIEW_LENGTH = 160;

const IPV4_CANDIDATE_PATTERN =
  /(^|[^\d.])((?:\d{1,3}\.){3}\d{1,3})(?![\d.])/g;
const MAC_STANDARD_PATTERN =
  /(^|[^0-9A-Fa-f])((?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2})(?![0-9A-Fa-f])/g;
const MAC_CISCO_PATTERN =
  /(^|[^0-9A-Fa-f])([0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4})(?![0-9A-Fa-f])/g;
const EMAIL_PATTERN =
  /(^|[^A-Z0-9._%+-])([A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,})(?![A-Z0-9._%+-])/gi;
const URL_PATTERN = /\bhttps?:\/\/[^\s<>"']+/gi;
const HOSTNAME_PROMPT_PATTERN =
  /^\s*([A-Za-z][A-Za-z0-9._-]{1,63}(?:\([A-Za-z0-9_.:/-]+\))*[>#])(?:\s?.*)?$/;

const CREDENTIAL_PATTERNS = [
  /\benable\s+secret\b/i,
  /\bsnmp-server\s+community\b/i,
  /\bprivate\s+key\b/i,
  /\bpre-shared\s+key\b/i,
  /\bpreshared\s+key\b/i,
  /\bkey-string\b/i,
  /\bcrypto\s+isakmp\s+key\b/i,
  /\bapi[-_ ]?key\b/i,
  /\bauthentication\s+key\b/i,
  /\bpassword\b/i,
  /\bpasswd\b/i,
  /\bsecret\b/i,
  /\busername\b/i,
  /\bcommunity\b/i,
  /\btoken\b/i,
  /\bbearer\b/i,
  /\bauthorization\b/i
];

export function detectSensitive(
  originalText: string,
  cleanedText: string
): SensitiveFinding[] {
  const rawFindings = [
    ...detectInText(originalText, 'original'),
    ...detectInText(cleanedText, 'cleaned')
  ];

  const merged = mergeEquivalentFindings(rawFindings);

  return merged.map(({ canonical: _canonical, order: _order, ...finding }) => finding);
}

export function summarizeFindings(
  findings: SensitiveFinding[]
): FindingsSummary {
  const summary = Object.fromEntries(
    sensitiveCategories.map((category) => [category, 0])
  ) as FindingsSummary;

  for (const finding of findings) {
    summary[finding.category] += 1;
  }

  return summary;
}

export function getRenderedFindings(
  findings: SensitiveFinding[],
  limit = 200
): SensitiveFinding[] {
  return findings.slice(0, limit);
}

function detectInText(text: string, source: FindingSource): RawFinding[] {
  const normalizedText = normalizeLineEndings(text);
  const lines = normalizedText.split('\n');
  const findings: RawFinding[] = [];
  let lineStartOffset = 0;

  lines.forEach((line, index) => {
    const lineNumber = index + 1;

    if (line.length === 0) {
      lineStartOffset += 1;
      return;
    }

    if (isCredentialLine(line)) {
      findings.push({
        category: 'Credential or secret',
        severity: 'High review priority',
        preview: buildPreview(line, 'Credential or secret'),
        source,
        line: lineNumber,
        canonical: `credential:${canonicalizeLine(line)}`,
        redactionRanges: getCleanedRedactionRanges(
          source,
          lineStartOffset,
          collectCredentialValueRanges(line)
        )
      });
    }

    collectIpv4Findings(line, source, lineNumber, lineStartOffset, findings);
    collectIpv6Findings(line, source, lineNumber, lineStartOffset, findings);
    collectPatternFindings(
      line,
      source,
      lineNumber,
      lineStartOffset,
      MAC_STANDARD_PATTERN,
      'MAC address',
      (value) => canonicalizeMac(value),
      findings
    );
    collectPatternFindings(
      line,
      source,
      lineNumber,
      lineStartOffset,
      MAC_CISCO_PATTERN,
      'MAC address',
      (value) => canonicalizeMac(value),
      findings
    );
    collectPatternFindings(
      line,
      source,
      lineNumber,
      lineStartOffset,
      EMAIL_PATTERN,
      'Email address',
      (value) => value.toLowerCase(),
      findings
    );
    collectUrlFindings(line, source, lineNumber, lineStartOffset, findings);
    collectHostnamePromptFinding(
      line,
      source,
      lineNumber,
      lineStartOffset,
      findings
    );

    lineStartOffset += line.length + 1;
  });

  return findings;
}

function collectIpv4Findings(
  line: string,
  source: FindingSource,
  lineNumber: number,
  lineStartOffset: number,
  findings: RawFinding[]
): void {
  IPV4_CANDIDATE_PATTERN.lastIndex = 0;

  for (const match of line.matchAll(IPV4_CANDIDATE_PATTERN)) {
    const candidate = match[2];
    const start = (match.index ?? 0) + match[1].length;

    if (!isValidIpv4(candidate)) {
      continue;
    }

    findings.push({
      category: 'IPv4 address',
      severity: 'Review',
      preview: buildPreview(line, 'IPv4 address'),
      source,
      line: lineNumber,
      canonical: candidate,
      redactionRanges: getCleanedRedactionRanges(source, lineStartOffset, [
        { start, end: start + candidate.length }
      ])
    });
  }
}

function collectIpv6Findings(
  line: string,
  source: FindingSource,
  lineNumber: number,
  lineStartOffset: number,
  findings: RawFinding[]
): void {
  const pattern = /[A-Fa-f0-9:]{2,}(?:%[A-Za-z0-9_.-]+)?/g;

  for (const match of line.matchAll(pattern)) {
    const candidate = match[0];

    if (/^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/.test(candidate)) {
      continue;
    }

    if (!candidate.includes(':') || !isLikelyIpv6(candidate)) {
      continue;
    }

    findings.push({
      category: 'IPv6 address',
      severity: 'Review',
      preview: buildPreview(line, 'IPv6 address'),
      source,
      line: lineNumber,
      canonical: candidate.toLowerCase(),
      redactionRanges: getCleanedRedactionRanges(source, lineStartOffset, [
        {
          start: match.index ?? 0,
          end: (match.index ?? 0) + candidate.length
        }
      ])
    });
  }
}

function collectPatternFindings(
  line: string,
  source: FindingSource,
  lineNumber: number,
  lineStartOffset: number,
  pattern: RegExp,
  category: SensitiveCategory,
  canonicalize: (value: string) => string,
  findings: RawFinding[]
): void {
  pattern.lastIndex = 0;

  for (const match of line.matchAll(pattern)) {
    const value = match[2] ?? match[0];
    const start = (match.index ?? 0) + (match[1]?.length ?? 0);

    findings.push({
      category,
      severity: 'Review',
      preview: buildPreview(line, category),
      source,
      line: lineNumber,
      canonical: canonicalize(value),
      redactionRanges: getCleanedRedactionRanges(source, lineStartOffset, [
        { start, end: start + value.length }
      ])
    });
  }
}

function collectUrlFindings(
  line: string,
  source: FindingSource,
  lineNumber: number,
  lineStartOffset: number,
  findings: RawFinding[]
): void {
  URL_PATTERN.lastIndex = 0;

  for (const match of line.matchAll(URL_PATTERN)) {
    const value = match[0];

    findings.push({
      category: 'URL',
      severity: 'Review',
      preview: buildPreview(line, 'URL'),
      source,
      line: lineNumber,
      canonical: stripUrlQueryAndFragment(value).toLowerCase(),
      redactionRanges: getCleanedRedactionRanges(source, lineStartOffset, [
        {
          start: match.index ?? 0,
          end: (match.index ?? 0) + value.length
        }
      ])
    });
  }
}

function collectHostnamePromptFinding(
  line: string,
  source: FindingSource,
  lineNumber: number,
  lineStartOffset: number,
  findings: RawFinding[]
): void {
  const trimmed = line.trim();
  const match = trimmed.match(HOSTNAME_PROMPT_PATTERN);

  if (!match) {
    return;
  }

  const prompt = match[1];

  findings.push({
    category: 'Hostname prompt',
    severity: 'Review',
      preview: buildPreview(trimmed, 'Hostname prompt'),
      source,
      line: lineNumber,
      canonical: prompt.toLowerCase(),
      redactionRanges: getCleanedRedactionRanges(
        source,
        lineStartOffset,
        collectHostnamePromptRanges(line)
      )
    });
}

function getCleanedRedactionRanges(
  source: FindingSource,
  lineStartOffset: number,
  lineRanges: TextRange[]
): TextRange[] {
  if (source !== 'cleaned') {
    return [];
  }

  return lineRanges
    .filter((range) => range.end > range.start)
    .map((range) => ({
      start: lineStartOffset + range.start,
      end: lineStartOffset + range.end
    }));
}

function collectCredentialValueRanges(line: string): TextRange[] {
  const ranges: TextRange[] = [];

  addCapturedValueRanges(
    line,
    /\b(authorization\s*:\s*bearer)\s+("[^"]+"|'[^']+'|\S+)/gi,
    ranges
  );
  addCapturedValueRanges(
    line,
    /\b(authorization\s*:)\s*(?!bearer\b)("[^"]+"|'[^']+'|\S+(?:\s+\S+)*)/gi,
    ranges
  );
  addCapturedValueRanges(
    line,
    /\b(bearer)\s+("[^"]+"|'[^']+'|\S+)/gi,
    ranges
  );
  addCapturedValueRanges(
    line,
    /\b(snmp-server\s+community)\s+("[^"]+"|'[^']+'|\S+)/gi,
    ranges
  );
  addCapturedValueRanges(
    line,
    /\b(username\s+(?:"[^"]+"|'[^']+'|\S+)\s+(?:password|secret)(?:\s+(?:0|5|7|8|9))?)\s+("[^"]+"|'[^']+'|\S+)/gi,
    ranges
  );
  addCapturedValueRanges(
    line,
    /\b(enable\s+secret(?:\s+(?:0|5|7|8|9))?)\s+(.+)$/gi,
    ranges
  );
  addCapturedValueRanges(
    line,
    /\b(crypto\s+isakmp\s+key)\s+("[^"]+"|'[^']+'|\S+)/gi,
    ranges
  );
  addCapturedValueRanges(
    line,
    /\b(api[-_ ]?key|token)\b\s*[:=]\s*("[^"]+"|'[^']+'|[^\s]+)/gi,
    ranges
  );

  if (ranges.length > 0) {
    return mergeRanges(ranges);
  }

  addCapturedValueRanges(
    line,
    /\b(password|passwd|secret|private\s+key|pre-shared\s+key|preshared\s+key|key-string|token|authentication\s+key)\b(?:\s*[:=])?(?:\s+(?:0|5|7|8|9))?\s+(.+)$/gi,
    ranges
  );

  return mergeRanges(ranges);
}

function addCapturedValueRanges(
  line: string,
  pattern: RegExp,
  ranges: TextRange[]
): void {
  pattern.lastIndex = 0;

  for (const match of line.matchAll(pattern)) {
    const value = match[2];

    if (!value) {
      continue;
    }

    const searchStart = (match.index ?? 0) + match[1].length;
    const start = line.indexOf(value, searchStart);

    if (start < 0) {
      continue;
    }

    ranges.push({ start, end: start + value.length });
  }
}

function collectHostnamePromptRanges(line: string): TextRange[] {
  const match = line.match(
    /^(\s*)([A-Za-z][A-Za-z0-9._-]{1,63})((?:\([A-Za-z0-9_.:/-]+\))*)([>#])/
  );

  if (!match) {
    return [];
  }

  const start = match[1].length;
  return [{ start, end: start + match[2].length }];
}

function mergeEquivalentFindings(rawFindings: RawFinding[]): MergedFinding[] {
  const byKey = new Map<string, MergedFinding>();
  let order = 0;

  for (const rawFinding of rawFindings) {
    const key = `${rawFinding.category}:${rawFinding.canonical}`;
    const existing = byKey.get(key);

    if (!existing) {
      byKey.set(key, {
        id: buildFindingId(key),
        category: rawFinding.category,
        severity: rawFinding.severity,
        preview: rawFinding.preview,
        source: rawFinding.source,
        originalLine:
          rawFinding.source === 'original' ? rawFinding.line : undefined,
        cleanedLine: rawFinding.source === 'cleaned' ? rawFinding.line : undefined,
        redactionRanges: [...rawFinding.redactionRanges],
        canonical: rawFinding.canonical,
        order
      });
      order += 1;
      continue;
    }

    if (existing.source !== rawFinding.source) {
      existing.source = 'both';
    }

    if (rawFinding.source === 'original' && existing.originalLine === undefined) {
      existing.originalLine = rawFinding.line;
    }

    if (rawFinding.source === 'cleaned' && existing.cleanedLine === undefined) {
      existing.cleanedLine = rawFinding.line;
    }

    existing.redactionRanges.push(...rawFinding.redactionRanges);

    if (
      existing.severity === 'Review' &&
      rawFinding.severity === 'High review priority'
    ) {
      existing.severity = rawFinding.severity;
      existing.preview = rawFinding.preview;
    }
  }

  return Array.from(byKey.values()).sort((left, right) => {
    const severityDelta =
      severityRank(right.severity) - severityRank(left.severity);

    if (severityDelta !== 0) {
      return severityDelta;
    }

    const lineDelta = firstLine(left) - firstLine(right);

    if (lineDelta !== 0) {
      return lineDelta;
    }

    return left.order - right.order;
  }).map((finding) => ({
    ...finding,
    redactionRanges: mergeRanges(finding.redactionRanges)
  }));
}

function mergeRanges(ranges: TextRange[]): TextRange[] {
  const sortedRanges = ranges
    .filter((range) => range.end > range.start)
    .sort((left, right) => left.start - right.start || left.end - right.end);
  const merged: TextRange[] = [];

  for (const range of sortedRanges) {
    const last = merged.at(-1);

    if (!last || range.start > last.end) {
      merged.push({ ...range });
      continue;
    }

    last.end = Math.max(last.end, range.end);
  }

  return merged;
}

function buildFindingId(key: string): string {
  return `finding-${hashString(key)}`;
}

function hashString(input: string): string {
  let hash = 0x811c9dc5;

  for (let index = 0; index < input.length; index += 1) {
    hash ^= input.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193);
  }

  return (hash >>> 0).toString(36);
}

function severityRank(severity: SensitiveFinding['severity']): number {
  return severity === 'High review priority' ? 1 : 0;
}

function firstLine(finding: SensitiveFinding): number {
  return Math.min(
    finding.originalLine ?? Number.POSITIVE_INFINITY,
    finding.cleanedLine ?? Number.POSITIVE_INFINITY
  );
}

function isCredentialLine(line: string): boolean {
  return CREDENTIAL_PATTERNS.some((pattern) => pattern.test(line));
}

function isValidIpv4(candidate: string): boolean {
  return candidate.split('.').every((octet) => {
    if (!/^\d{1,3}$/.test(octet)) {
      return false;
    }

    const value = Number(octet);
    return value >= 0 && value <= 255;
  });
}

function isLikelyIpv6(candidate: string): boolean {
  const zoneIndex = candidate.indexOf('%');
  const address = zoneIndex >= 0 ? candidate.slice(0, zoneIndex) : candidate;
  const parts = address.split(':');

  if (parts.length < 3 || parts.length > 8) {
    return false;
  }

  const compressedSections = address.match(/::/g)?.length ?? 0;

  if (compressedSections > 1) {
    return false;
  }

  return parts.every((part) => part === '' || /^[A-Fa-f0-9]{1,4}$/.test(part));
}

function canonicalizeMac(value: string): string {
  return value.replace(/[^0-9A-Fa-f]/g, '').toLowerCase();
}

function canonicalizeLine(line: string): string {
  return removeAnsiSequences(line)
    .replace(/[\x00-\x1F\x7F]/g, '')
    .replace(/\s+/g, ' ')
    .trim()
    .toLowerCase();
}

function buildPreview(line: string, _category: SensitiveCategory): string {
  let preview = removeAnsiSequences(line)
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '')
    .replace(/\s+/g, ' ')
    .trim();

  preview = maskSensitiveText(preview);

  if (preview.length > MAX_PREVIEW_LENGTH) {
    preview = `${preview.slice(0, MAX_PREVIEW_LENGTH - 3)}...`;
  }

  return escapePreview(preview);
}

function stripUrlQueryAndFragment(url: string): string {
  const firstSensitiveIndex = Math.min(
    ...[url.indexOf('?'), url.indexOf('#')].filter((index) => index >= 0)
  );

  if (Number.isFinite(firstSensitiveIndex)) {
    return url.slice(0, firstSensitiveIndex);
  }

  return url;
}

function escapePreview(input: string): string {
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

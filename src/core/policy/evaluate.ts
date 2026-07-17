import { maskSensitiveText } from '../maskSensitive';
import { normalizeLineEndings } from '../cleanText';
import { detectSensitive } from '../detectSensitive';
import type {
  AnalysisOptions,
  FindingSource,
  ProfileAction,
  SensitiveFinding,
  TextRange
} from '../types';
import { BUILTIN_POLICY_ID } from './builtins';
import { parseIpv4 } from './compile';
import type {
  CompiledPolicy,
  CompiledPolicyRule,
  PolicyAction,
  PolicyEvaluation,
  PolicyMatch
} from './types';

const MAX_POLICY_INPUT_LENGTH = 1_000_000;
const MAX_PREVIEW_LENGTH = 160;
const IPV4_PATTERN = /(^|[^\d.])((?:\d{1,3}\.){3}\d{1,3})(?![\d.])/g;

interface RawPolicyFinding {
  canonical: string;
  ruleIdentity: string;
  source: Exclude<FindingSource, 'both'>;
  lineNumber: number;
  redactionRanges: TextRange[];
  finding: SensitiveFinding;
  priority: number;
}

interface MergedPolicyFinding extends SensitiveFinding {
  canonical: string;
  priority: number;
}

interface AcceptedPolicyMatch {
  match: PolicyMatch;
  rule: CompiledPolicyRule;
}

export function evaluatePolicy(
  originalText: string,
  cleanedText: string,
  policy: CompiledPolicy,
  options: AnalysisOptions = {}
): PolicyEvaluation {
  if (policy.id === BUILTIN_POLICY_ID) {
    return evaluateBuiltInPolicy(originalText, cleanedText, policy, options);
  }

  const unsupportedContent: string[] = [];
  const rawFindings = [
    ...evaluateText(originalText, 'original', policy, unsupportedContent),
    ...evaluateText(cleanedText, 'cleaned', policy, unsupportedContent)
  ];

  return {
    findings: mergeEquivalentFindings(rawFindings),
    policyId: policy.id,
    policyVersion: policy.version,
    unsupportedContent: [...new Set(unsupportedContent)]
  };
}

function evaluateBuiltInPolicy(
  originalText: string,
  cleanedText: string,
  policy: CompiledPolicy,
  options: AnalysisOptions
): PolicyEvaluation {
  const findings = detectSensitive(originalText, cleanedText, options).map(
    (finding) => ({
      ...finding,
      policyId: policy.id,
      policyVersion: policy.version
    })
  );

  return {
    findings,
    policyId: policy.id,
    policyVersion: policy.version,
    unsupportedContent: []
  };
}

export function mergePolicyFindings(
  builtInFindings: SensitiveFinding[],
  policyFindings: SensitiveFinding[]
): SensitiveFinding[] {
  const policyRangeKeys = new Set(
    policyFindings.flatMap((finding) =>
      finding.redactionRanges.map((range) => rangeKey(range))
    )
  );
  const remainingBuiltIns = builtInFindings.flatMap((finding) => {
    if (finding.redactionRanges.length === 0) {
      return [finding];
    }
    const remainingRanges = finding.redactionRanges.filter(
      (range) => !policyRangeKeys.has(rangeKey(range))
    );
    return remainingRanges.length > 0
      ? [{ ...finding, redactionRanges: remainingRanges }]
      : [];
  });

  return [...policyFindings, ...remainingBuiltIns].sort((left, right) => {
    if (left.severity !== right.severity) {
      return left.severity === 'High review priority' ? -1 : 1;
    }
    return left.id.localeCompare(right.id);
  });
}

function evaluateText(
  text: string,
  source: Exclude<FindingSource, 'both'>,
  policy: CompiledPolicy,
  unsupportedContent: string[]
): RawPolicyFinding[] {
  if (!text) return [];
  if (text.length > MAX_POLICY_INPUT_LENGTH) {
    unsupportedContent.push(
      `Custom session policy skipped ${source} text larger than ${MAX_POLICY_INPUT_LENGTH.toLocaleString()} characters.`
    );
    return [];
  }

  const findings: RawPolicyFinding[] = [];
  const lines = normalizeLineEndings(text).split('\n');
  let lineStartOffset = 0;

  lines.forEach((line, index) => {
    const acceptedMatches: AcceptedPolicyMatch[] = [];
    const previewRanges: TextRange[] = [];

    for (const rule of policy.rules) {
      if (rule.matcher.kind === 'syntax') {
        if (!unsupportedContent.includes('Custom syntax matchers are not available in session policies.')) {
          unsupportedContent.push('Custom syntax matchers are not available in session policies.');
        }
        continue;
      }

      for (const match of findMatches(line, rule)) {
        previewRanges.push(match.range);
        if (
          acceptedMatches.some((accepted) =>
            rangesOverlap(accepted.match.range, match.range)
          )
        ) {
          continue;
        }
        acceptedMatches.push({ match, rule });
      }
    }

    for (const { match, rule } of acceptedMatches) {
      const absoluteRange = {
        start: lineStartOffset + match.range.start,
        end: lineStartOffset + match.range.end
      };
      const redactionRanges = source === 'cleaned' ? [absoluteRange] : [];
      findings.push({
        canonical: match.canonical,
        ruleIdentity: rule.id,
        source,
        lineNumber: index + 1,
        redactionRanges,
        priority: rule.priority,
        finding: {
          id: opaqueFindingId(policy.id, rule.id, match.canonical),
          category: rule.category,
          severity: rule.action === 'block' ? 'High review priority' : rule.severity,
          preview: buildMaskedPreview(line, previewRanges),
          source,
          ...(source === 'original'
            ? { originalLine: index + 1 }
            : { cleanedLine: index + 1 }),
          redactionRanges,
          confidence: match.confidence,
          reason: getReason(rule),
          ruleId: `session.${rule.matcher.kind}`,
          vendor: 'generic-it',
          profileAction: getProfileAction(rule.action),
          policyAction: rule.action,
          policyId: policy.id,
          policyVersion: policy.version,
          replacementLabel: rule.replacementLabel
        }
      });
    }

    lineStartOffset += line.length + 1;
  });

  return findings;
}

function findMatches(line: string, rule: CompiledPolicyRule): PolicyMatch[] {
  switch (rule.matcher.kind) {
    case 'regex':
      return findRegexMatches(line, rule.matcher.expression);
    case 'dictionary':
      return findDictionaryMatches(line, rule.matcher.values, rule.matcher.caseSensitive);
    case 'cidr':
      return findCidrMatches(line, rule.matcher.ranges);
    case 'syntax':
      return [];
  }
}

function findRegexMatches(line: string, expression: RegExp): PolicyMatch[] {
  const matches: PolicyMatch[] = [];
  expression.lastIndex = 0;

  for (const match of line.matchAll(expression)) {
    const value = match[0];
    if (!value) continue;
    const start = match.index ?? 0;
    matches.push({
      canonical: value.toLowerCase(),
      line,
      lineNumber: 0,
      range: { start, end: start + value.length },
      confidence: 'Medium'
    });
  }

  return matches;
}

function findDictionaryMatches(
  line: string,
  values: readonly string[],
  caseSensitive: boolean
): PolicyMatch[] {
  const haystack = caseSensitive ? line : line.toLowerCase();
  const matches: PolicyMatch[] = [];

  for (const value of values) {
    const needle = caseSensitive ? value : value.toLowerCase();
    let fromIndex = 0;

    while (fromIndex <= haystack.length - needle.length) {
      const start = haystack.indexOf(needle, fromIndex);
      if (start < 0) break;
      matches.push({
        canonical: needle,
        line,
        lineNumber: 0,
        range: { start, end: start + value.length },
        confidence: 'High'
      });
      fromIndex = start + Math.max(1, value.length);
    }
  }

  return removeOverlappingMatches(matches);
}

function findCidrMatches(
  line: string,
  ranges: readonly { network: number; mask: number }[]
): PolicyMatch[] {
  const matches: PolicyMatch[] = [];
  IPV4_PATTERN.lastIndex = 0;

  for (const match of line.matchAll(IPV4_PATTERN)) {
    const value = match[2];
    const address = parseIpv4(value);
    if (address === undefined || !ranges.some((range) => (address & range.mask) === range.network)) {
      continue;
    }
    const start = (match.index ?? 0) + match[1].length;
    matches.push({
      canonical: value,
      line,
      lineNumber: 0,
      range: { start, end: start + value.length },
      confidence: 'High'
    });
  }

  return matches;
}

function removeOverlappingMatches(matches: PolicyMatch[]): PolicyMatch[] {
  const sorted = [...matches].sort(
    (left, right) => left.range.start - right.range.start || right.range.end - left.range.end
  );
  const accepted: PolicyMatch[] = [];

  for (const match of sorted) {
    if (!accepted.some((existing) => rangesOverlap(existing.range, match.range))) {
      accepted.push(match);
    }
  }
  return accepted;
}

function mergeEquivalentFindings(rawFindings: RawPolicyFinding[]): SensitiveFinding[] {
  const merged = new Map<string, MergedPolicyFinding>();

  for (const raw of rawFindings) {
    const key = `${raw.ruleIdentity}\u0000${raw.canonical}`;
    const existing = merged.get(key);
    if (!existing) {
      merged.set(key, { ...raw.finding, canonical: raw.canonical, priority: raw.priority });
      continue;
    }

    existing.source = existing.source === raw.source ? existing.source : 'both';
    if (raw.source === 'original' && existing.originalLine === undefined) {
      existing.originalLine = raw.lineNumber;
    }
    if (raw.source === 'cleaned') {
      existing.cleanedLine ??= raw.lineNumber;
      existing.redactionRanges = mergeRanges([
        ...existing.redactionRanges,
        ...raw.redactionRanges
      ]);
    }
  }

  const findings = [...merged.values()]
    .sort((left, right) => {
      if (left.severity !== right.severity) {
        return left.severity === 'High review priority' ? -1 : 1;
      }
      return right.priority - left.priority || left.id.localeCompare(right.id);
    })
    .map(({ canonical: _canonical, priority: _priority, ...finding }) => finding);

  return ensureUniqueFindingIds(findings);
}

function mergeRanges(ranges: TextRange[]): TextRange[] {
  const unique = new Map(ranges.map((range) => [`${range.start}:${range.end}`, range]));
  return [...unique.values()].sort((left, right) => left.start - right.start);
}

function buildMaskedPreview(line: string, ranges: readonly TextRange[]): string {
  let replaced = line;
  for (const range of mergePreviewRanges(ranges).sort((left, right) => right.start - left.start)) {
    replaced = `${replaced.slice(0, range.start)}[masked-value]${replaced.slice(range.end)}`;
  }
  const masked = maskSensitiveText(replaced);
  return masked.length <= MAX_PREVIEW_LENGTH
    ? masked
    : `${masked.slice(0, MAX_PREVIEW_LENGTH - 3)}...`;
}

function mergePreviewRanges(ranges: readonly TextRange[]): TextRange[] {
  const merged: TextRange[] = [];
  for (const range of [...ranges].sort(
    (left, right) => left.start - right.start || left.end - right.end
  )) {
    const previous = merged.at(-1);
    if (!previous || range.start > previous.end) {
      merged.push({ ...range });
    } else {
      previous.end = Math.max(previous.end, range.end);
    }
  }
  return merged;
}

function getReason(rule: CompiledPolicyRule): string {
  switch (rule.matcher.kind) {
    case 'regex':
      return 'Session regular-expression rule matched.';
    case 'dictionary':
      return 'Session protected-dictionary rule matched.';
    case 'cidr':
      return 'Session protected IPv4 range matched.';
    case 'syntax':
      return 'Session syntax rule matched.';
  }
}

function getProfileAction(action: PolicyAction): ProfileAction {
  switch (action) {
    case 'allow':
      return 'allow';
    case 'review':
      return 'review';
    case 'replace':
    case 'alias':
    case 'block':
      return 'redact';
  }
}

function opaqueFindingId(policyId: string, ruleId: string, canonical: string): string {
  let hash = 2166136261;
  for (const character of `${policyId}\u0000${ruleId}\u0000${canonical}`) {
    hash ^= character.charCodeAt(0);
    hash = Math.imul(hash, 16777619);
  }
  return `policy-${(hash >>> 0).toString(36)}`;
}

function ensureUniqueFindingIds(findings: SensitiveFinding[]): SensitiveFinding[] {
  const usedIds = new Map<string, number>();
  return findings.map((finding) => {
    const occurrence = (usedIds.get(finding.id) ?? 0) + 1;
    usedIds.set(finding.id, occurrence);
    return occurrence === 1
      ? finding
      : { ...finding, id: `${finding.id}-${occurrence}` };
  });
}

function rangeKey(range: TextRange): string {
  return `${range.start}:${range.end}`;
}

function rangesOverlap(left: TextRange, right: TextRange): boolean {
  return left.start < right.end && right.start < left.end;
}

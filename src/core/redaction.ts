import type { SensitiveFinding, TextRange } from './types';

export function applySelectedRedactions(
  cleanedText: string,
  findings: SensitiveFinding[],
  selectedIds: ReadonlySet<string>
): string {
  const ranges = findings
    .filter((finding) => selectedIds.has(finding.id))
    .flatMap((finding) => finding.redactionRanges);

  return removeRanges(cleanedText, mergeRanges(ranges));
}

export function getDefaultSelectedFindingIds(
  findings: SensitiveFinding[]
): Set<string> {
  return new Set(
    findings
      .filter((finding) => isDefaultSelectedFinding(finding))
      .map((finding) => finding.id)
  );
}

export function reconcileSelectedFindingIds(
  findings: SensitiveFinding[],
  selectedIds: ReadonlySet<string>,
  previouslyKnownIds: ReadonlySet<string>
): Set<string> {
  const currentIds = new Set(findings.map((finding) => finding.id));
  const nextSelectedIds = new Set(
    [...selectedIds].filter((id) => currentIds.has(id))
  );

  for (const finding of findings) {
    if (
      !previouslyKnownIds.has(finding.id) &&
      isDefaultSelectedFinding(finding)
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

function isDefaultSelectedFinding(finding: SensitiveFinding): boolean {
  return (
    finding.severity === 'High review priority' && isRedactableFinding(finding)
  );
}

function removeRanges(text: string, ranges: TextRange[]): string {
  let redactedText = text;

  for (const range of [...ranges].sort((left, right) => right.start - left.start)) {
    redactedText = removeRange(redactedText, range);
  }

  return redactedText;
}

function removeRange(text: string, range: TextRange): string {
  const start = Math.max(0, Math.min(range.start, text.length));
  const end = Math.max(start, Math.min(range.end, text.length));

  if (end <= start) {
    return text;
  }

  const leftWhitespaceStart = findHorizontalWhitespaceStart(text, start);
  const rightWhitespaceEnd = findHorizontalWhitespaceEnd(text, end);
  const hasLeftWhitespace = leftWhitespaceStart < start;
  const hasRightWhitespace = rightWhitespaceEnd > end;
  const leftBoundary =
    leftWhitespaceStart === 0 || isLineBreak(text[leftWhitespaceStart - 1]);
  const rightBoundary =
    rightWhitespaceEnd >= text.length || isLineBreak(text[rightWhitespaceEnd]);

  if (hasLeftWhitespace && hasRightWhitespace && !leftBoundary && !rightBoundary) {
    return `${text.slice(0, leftWhitespaceStart)} ${text.slice(rightWhitespaceEnd)}`;
  }

  if (hasLeftWhitespace && rightBoundary) {
    return `${text.slice(0, leftWhitespaceStart)}${text.slice(end)}`;
  }

  if (hasRightWhitespace && leftBoundary) {
    return `${text.slice(0, start)}${text.slice(rightWhitespaceEnd)}`;
  }

  return `${text.slice(0, start)}${text.slice(end)}`;
}

function mergeRanges(ranges: TextRange[]): TextRange[] {
  const sortedRanges = ranges
    .filter((range) => range.end > range.start)
    .sort((left, right) => left.start - right.start || left.end - right.end);
  const mergedRanges: TextRange[] = [];

  for (const range of sortedRanges) {
    const lastRange = mergedRanges.at(-1);

    if (!lastRange || range.start > lastRange.end) {
      mergedRanges.push({ ...range });
      continue;
    }

    lastRange.end = Math.max(lastRange.end, range.end);
  }

  return mergedRanges;
}

function findHorizontalWhitespaceStart(text: string, start: number): number {
  let index = start;

  while (index > 0 && isHorizontalWhitespace(text[index - 1])) {
    index -= 1;
  }

  return index;
}

function findHorizontalWhitespaceEnd(text: string, end: number): number {
  let index = end;

  while (index < text.length && isHorizontalWhitespace(text[index])) {
    index += 1;
  }

  return index;
}

function isHorizontalWhitespace(character: string | undefined): boolean {
  return character === ' ' || character === '\t';
}

function isLineBreak(character: string | undefined): boolean {
  return character === '\n' || character === '\r';
}

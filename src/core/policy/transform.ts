import { applySelectedRedactions } from '../redaction';
import type { SensitiveFinding } from '../types';
import type { TokenMap } from '../tokenMap';
import type { PolicyEvaluation } from './types';

export function transformWithPolicy(
  text: string,
  evaluation: PolicyEvaluation,
  selectedIds: ReadonlySet<string>,
  aliasMap: TokenMap = new Map()
): string {
  const labels = new Map<string, string>();
  for (const finding of evaluation.findings) {
    const label = aliasMap.get(finding.id) ?? finding.replacementLabel;
    if (label) labels.set(finding.id, label);
  }
  return applySelectedRedactions(text, evaluation.findings, selectedIds, labels);
}

export function getPolicyDefaultSelectedIds(
  findings: SensitiveFinding[]
): Set<string> {
  return new Set(
    findings
      .filter(
        (finding) =>
          finding.redactionRanges.length > 0 &&
          ['replace', 'alias', 'block'].includes(finding.policyAction ?? '')
      )
      .map((finding) => finding.id)
  );
}

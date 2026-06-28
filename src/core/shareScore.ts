import { getProfileActionForFinding } from './profiles';
import type {
  RedactionProfileId,
  SensitiveFinding,
  ShareReadiness
} from './types';

export function scoreShareReadiness(
  findings: SensitiveFinding[],
  selectedIds: ReadonlySet<string>,
  profileId: RedactionProfileId
): ShareReadiness {
  const reasons: string[] = [];
  const unredactedHighPriority = findings.filter((finding) => {
    return (
      finding.redactionRanges.length > 0 &&
      finding.severity === 'High review priority' &&
      !selectedIds.has(finding.id)
    );
  });
  const unredactedProfileDefaults = findings.filter((finding) => {
    return (
      finding.redactionRanges.length > 0 &&
      getProfileActionForFinding(finding, profileId) === 'redact' &&
      !selectedIds.has(finding.id)
    );
  });
  const originalOnlyHighPriority = findings.filter((finding) => {
    return (
      finding.redactionRanges.length === 0 &&
      finding.severity === 'High review priority'
    );
  });
  const lowConfidenceVisible = findings.filter((finding) => {
    return (
      finding.confidence === 'Low' &&
      finding.redactionRanges.length > 0 &&
      !selectedIds.has(finding.id)
    );
  });

  if (unredactedHighPriority.length > 0) {
    reasons.push('High-priority sensitive-looking values remain unredacted.');
  }

  if (originalOnlyHighPriority.length > 0) {
    reasons.push('Some high-priority values only appeared in the original input.');
  }

  if (unredactedProfileDefaults.length > 0) {
    reasons.push('The selected profile recommends more redactions.');
  }

  if (lowConfidenceVisible.length > 0) {
    reasons.push('Low-confidence findings should be reviewed manually.');
  }

  if (unredactedHighPriority.length > 0 || originalOnlyHighPriority.length > 0) {
    return {
      status: 'High risk',
      reasons
    };
  }

  if (unredactedProfileDefaults.length > 0 || lowConfidenceVisible.length > 0) {
    return {
      status: 'Review recommended',
      reasons
    };
  }

  return {
    status: findings.length === 0 ? 'Ready' : 'Ready',
    reasons:
      findings.length === 0
        ? ['No common sensitive patterns were detected.']
        : ['Selected redactions satisfy the current profile defaults.']
  };
}

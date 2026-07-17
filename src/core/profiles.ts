import type {
  ProfileAction,
  RedactionProfileId,
  SensitiveCategory,
  SensitiveFinding
} from './types';

export interface RedactionProfileDefinition {
  id: RedactionProfileId;
  label: string;
  description: string;
  scoreThreshold: 'strict' | 'balanced' | 'relaxed';
  useTokenMappingByDefault: boolean;
  hiddenCategories: SensitiveCategory[];
}

const credentialCategories = new Set<SensitiveCategory>([
  'Credential or secret',
  'Certificate or key material',
  'Cloud identifier'
]);

const topologyIdentityCategories = new Set<SensitiveCategory>([
  'Public IP address',
  'Private IP address',
  'IPv4 address',
  'IPv6 address',
  'Hostname prompt',
  'Hostname',
  'Email address',
  'URL',
  'MAC address',
  'Serial number',
  'Circuit ID',
  'Site or customer label'
]);

const operationalStructureCategories = new Set<SensitiveCategory>([
  'Interface name',
  'VRF name',
  'VLAN identifier',
  'BGP ASN',
  'Config comment metadata'
]);

export const redactionProfiles: RedactionProfileDefinition[] = [
  {
    id: 'public',
    label: 'Public',
    description: 'Highest caution for public posts, docs, and screenshots.',
    scoreThreshold: 'strict',
    useTokenMappingByDefault: true,
    hiddenCategories: []
  },
  {
    id: 'vendor-tac',
    label: 'Vendor TAC',
    description: 'Preserve troubleshooting structure while removing customer identity and secrets.',
    scoreThreshold: 'balanced',
    useTokenMappingByDefault: true,
    hiddenCategories: []
  },
  {
    id: 'internal-ticket',
    label: 'Internal Ticket',
    description: 'Keep most topology context, remove credentials and key material.',
    scoreThreshold: 'relaxed',
    useTokenMappingByDefault: false,
    hiddenCategories: []
  },
  {
    id: 'ai-prompt',
    label: 'AI Prompt',
    description: 'Aggressive local redaction for prompts with stable tokens.',
    scoreThreshold: 'strict',
    useTokenMappingByDefault: true,
    hiddenCategories: []
  },
  {
    id: 'custom-session',
    label: 'Custom Session',
    description: 'Start from high-priority defaults, then choose manually.',
    scoreThreshold: 'balanced',
    useTokenMappingByDefault: false,
    hiddenCategories: []
  }
];

export function getProfile(
  profileId: RedactionProfileId
): RedactionProfileDefinition {
  return (
    redactionProfiles.find((profile) => profile.id === profileId) ??
    redactionProfiles[0]
  );
}

export function getProfileActionForFinding(
  finding: SensitiveFinding,
  profileId: RedactionProfileId
): ProfileAction {
  if (finding.policyAction) {
    switch (finding.policyAction) {
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

  if (finding.severity === 'High review priority') {
    return 'redact';
  }

  switch (profileId) {
    case 'public':
      if (topologyIdentityCategories.has(finding.category)) {
        return 'redact';
      }

      return operationalStructureCategories.has(finding.category)
        ? 'review'
        : 'review';
    case 'vendor-tac':
      if (
        credentialCategories.has(finding.category) ||
        finding.category === 'Site or customer label' ||
        finding.category === 'Circuit ID' ||
        finding.category === 'Cloud identifier'
      ) {
        return 'redact';
      }

      return 'review';
    case 'internal-ticket':
      return credentialCategories.has(finding.category) ? 'redact' : 'review';
    case 'ai-prompt':
      return finding.category === 'Interface name' ||
        finding.category === 'VLAN identifier' ||
        finding.category === 'BGP ASN'
        ? 'review'
        : 'redact';
    case 'custom-session':
    default:
      return credentialCategories.has(finding.category) ? 'redact' : 'review';
  }
}

export function applyProfileDefaults(
  findings: SensitiveFinding[],
  profileId: RedactionProfileId
): Set<string> {
  return new Set(
    findings
      .filter((finding) => {
        return (
          finding.redactionRanges.length > 0 &&
          getProfileActionForFinding(finding, profileId) === 'redact'
        );
      })
      .map((finding) => finding.id)
  );
}

export function annotateFindingsForProfile(
  findings: SensitiveFinding[],
  profileId: RedactionProfileId
): SensitiveFinding[] {
  return findings.map((finding) => ({
    ...finding,
    profileAction: getProfileActionForFinding(finding, profileId)
  }));
}

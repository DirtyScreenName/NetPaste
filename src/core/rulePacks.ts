import type { ConfidenceLevel, VendorId, VendorSuggestion } from './types';

export interface VendorDefinition {
  id: VendorId;
  label: string;
  patterns: RegExp[];
}

export const vendorDefinitions: VendorDefinition[] = [
  {
    id: 'cisco',
    label: 'Cisco',
    patterns: [
      /\benable\s+secret\b/i,
      /\bsnmp-server\b/i,
      /\bcrypto\s+isakmp\b/i,
      /\bGigabitEthernet\b/i,
      /\bshow\s+running-config\b/i
    ]
  },
  {
    id: 'juniper',
    label: 'Juniper',
    patterns: [
      /\bset\s+system\b/i,
      /\bset\s+interfaces\b/i,
      /\bjunos\b/i,
      /\b(?:ge|xe|et)-\d+\/\d+\/\d+\b/i
    ]
  },
  {
    id: 'arista',
    label: 'Arista',
    patterns: [
      /\bmanagement\s+api\s+http-commands\b/i,
      /\bip\s+routing\b/i,
      /\bEthernet\d+(?:\/\d+)?\b/i,
      /\beos\b/i
    ]
  },
  {
    id: 'palo-alto',
    label: 'Palo Alto',
    patterns: [
      /\bset\s+deviceconfig\b/i,
      /\bsecurity-policy\b/i,
      /\bpan-os\b/i,
      /\bpalo\s+alto\b/i
    ]
  },
  {
    id: 'fortinet',
    label: 'Fortinet',
    patterns: [
      /\bconfig\s+system\b/i,
      /^\s*edit\s+"[^"]+"/im,
      /^\s*next\s*$/im,
      /\bFortiGate\b/i
    ]
  },
  {
    id: 'ciena',
    label: 'Ciena',
    patterns: [
      /\bsaos\b/i,
      /\bciena\b/i,
      /\blogical-port\b/i,
      /\bflow-point\b/i
    ]
  },
  {
    id: 'linux',
    label: 'Linux',
    patterns: [
      /\bjournalctl\b/i,
      /\bsystemd\b/i,
      /\bip\s+addr\b/i,
      /\/etc\//i,
      /\bsudo\b/i
    ]
  },
  {
    id: 'generic-it',
    label: 'Generic IT',
    patterns: []
  }
];

export function getVendorLabel(vendorId: VendorId): string {
  return vendorDefinitions.find((vendor) => vendor.id === vendorId)?.label ?? 'Generic IT';
}

export function suggestVendor(text: string): VendorSuggestion {
  const scores = vendorDefinitions
    .filter((vendor) => vendor.id !== 'generic-it')
    .map((vendor) => ({
      vendor,
      hits: vendor.patterns.filter((pattern) => pattern.test(text)).length
    }))
    .sort((left, right) => right.hits - left.hits);

  const top = scores[0];

  if (!top || top.hits === 0) {
    return {
      vendor: 'generic-it',
      confidence: 'Low',
      reason: 'No vendor-specific rule pack had a strong local signal.'
    };
  }

  const confidence: ConfidenceLevel =
    top.hits >= 3 ? 'High' : top.hits >= 2 ? 'Medium' : 'Low';

  return {
    vendor: top.vendor.id,
    confidence,
    reason: `${top.vendor.label} syntax matched local rule-pack hints.`
  };
}

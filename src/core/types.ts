export const sensitiveCategories = [
  'IPv4 address',
  'IPv6 address',
  'Public IP address',
  'Private IP address',
  'MAC address',
  'Email address',
  'URL',
  'Hostname prompt',
  'Credential or secret',
  'Hostname',
  'Interface name',
  'VRF name',
  'VLAN identifier',
  'BGP ASN',
  'Serial number',
  'Circuit ID',
  'Site or customer label',
  'Certificate or key material',
  'Cloud identifier',
  'Config comment metadata'
] as const;

export type SensitiveCategory = (typeof sensitiveCategories)[number];
export type FindingSeverity = 'Review' | 'High review priority';
export type FindingSource = 'original' | 'cleaned' | 'both';
export type ConfidenceLevel = 'High' | 'Medium' | 'Low';
export type ProfileAction = 'redact' | 'review' | 'allow';
export type RedactionProfileId =
  | 'public'
  | 'vendor-tac'
  | 'internal-ticket'
  | 'ai-prompt'
  | 'custom-session';
export type DocumentModeId =
  | 'cli-config'
  | 'markdown'
  | 'json'
  | 'yaml'
  | 'csv-log'
  | 'ticket-email';
export type VendorId =
  | 'generic-it'
  | 'cisco'
  | 'juniper'
  | 'arista'
  | 'palo-alto'
  | 'fortinet'
  | 'ciena'
  | 'linux';
export type VendorSelection = VendorId | 'auto';
export type ShareReadinessStatus =
  | 'Ready'
  | 'Review recommended'
  | 'High risk';

export interface TextRange {
  start: number;
  end: number;
}

export interface SensitiveFinding {
  id: string;
  category: SensitiveCategory;
  severity: FindingSeverity;
  preview: string;
  source: FindingSource;
  originalLine?: number;
  cleanedLine?: number;
  redactionRanges: TextRange[];
  confidence: ConfidenceLevel;
  reason: string;
  ruleId: string;
  vendor: VendorId;
  profileAction: ProfileAction;
  replacementToken?: string;
  replacementLabel?: string;
  policyAction?: import('./policy/types').PolicyAction;
  policyId?: string;
  policyVersion?: string;
}

export type FindingsSummary = Record<SensitiveCategory, number>;

export interface VendorSuggestion {
  vendor: VendorId;
  confidence: ConfidenceLevel;
  reason: string;
}

export interface ShareReadiness {
  status: ShareReadinessStatus;
  reasons: string[];
}

export interface AnalysisOptions {
  profileId?: RedactionProfileId;
  documentMode?: DocumentModeId;
  vendorId?: VendorSelection;
  useTokenMapping?: boolean;
  selectedIds?: ReadonlySet<string>;
  policy?: import('./policy/types').CompiledPolicy;
}

export interface AnalysisResult {
  findings: SensitiveFinding[];
  categoryCounts: FindingsSummary;
  renderedFindings: SensitiveFinding[];
  hiddenFindingCount: number;
  profileId: RedactionProfileId;
  documentMode: DocumentModeId;
  vendorSuggestion: VendorSuggestion;
  activeVendor: VendorId;
  shareScore: ShareReadiness;
  policyId: string;
  policyVersion: string;
  unsupportedContent: string[];
}

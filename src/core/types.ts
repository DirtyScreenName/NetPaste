export const sensitiveCategories = [
  'IPv4 address',
  'IPv6 address',
  'MAC address',
  'Email address',
  'URL',
  'Hostname prompt',
  'Credential or secret'
] as const;

export type SensitiveCategory = (typeof sensitiveCategories)[number];

export interface SensitiveFinding {
  category: SensitiveCategory;
  severity: 'Review' | 'High review priority';
  preview: string;
  source: 'original' | 'cleaned' | 'both';
  originalLine?: number;
  cleanedLine?: number;
}

export type FindingsSummary = Record<SensitiveCategory, number>;

export interface AnalysisResult {
  findings: SensitiveFinding[];
  categoryCounts: FindingsSummary;
  renderedFindings: SensitiveFinding[];
  hiddenFindingCount: number;
}

import type {
  AnalysisOptions,
  ConfidenceLevel,
  FindingSeverity,
  SensitiveCategory,
  SensitiveFinding,
  TextRange
} from '../types';

export type PolicyAction = 'allow' | 'review' | 'replace' | 'alias' | 'block';

export type PolicyMatcher =
  | { kind: 'regex'; pattern: string; flags?: string }
  | { kind: 'dictionary'; values: readonly string[]; caseSensitive: boolean }
  | { kind: 'cidr'; ranges: readonly string[] }
  | { kind: 'syntax'; parser: string; rule: string };

export interface PolicyRule {
  id: string;
  category: SensitiveCategory;
  description: string;
  matcher: PolicyMatcher;
  action: PolicyAction;
  severity: FindingSeverity;
  replacementLabel?: string;
  priority: number;
}

export interface RedactionPolicy {
  id: string;
  version: string;
  name: string;
  rules: readonly PolicyRule[];
}

export interface ParsedIpv4Cidr {
  network: number;
  mask: number;
  prefix: number;
}

export type CompiledPolicyMatcher =
  | { kind: 'regex'; expression: RegExp }
  | { kind: 'dictionary'; values: readonly string[]; caseSensitive: boolean }
  | { kind: 'cidr'; ranges: readonly ParsedIpv4Cidr[] }
  | { kind: 'syntax'; parser: string; rule: string };

export interface CompiledPolicyRule extends Omit<PolicyRule, 'matcher'> {
  matcher: CompiledPolicyMatcher;
}

export interface CompiledPolicy {
  id: string;
  version: string;
  name: string;
  rules: readonly CompiledPolicyRule[];
}

export interface PolicyEvaluation {
  findings: SensitiveFinding[];
  policyId: string;
  policyVersion: string;
  unsupportedContent: string[];
}

export interface PolicyMatch {
  canonical: string;
  line: string;
  lineNumber: number;
  range: TextRange;
  confidence: ConfidenceLevel;
}

export interface PolicyAnalysisOptions extends AnalysisOptions {
  policy?: CompiledPolicy;
}

export interface RedactionReceipt {
  policyId: string;
  policyVersion: string;
  processedAt: string;
  originalSha256: string;
  sanitizedSha256: string;
  originalRetained: false;
  redactionCount: number;
  classifications: Readonly<Record<string, number>>;
  reviewStatus: 'pending' | 'approved';
}

export class PolicyCompileError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PolicyCompileError';
  }
}

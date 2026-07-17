import { sensitiveCategories } from '../types';
import type { SensitiveCategory } from '../types';
import { compilePolicy } from './compile';
import type { PolicyRule, RedactionPolicy } from './types';

export const BUILTIN_POLICY_ID = 'netpaste-builtins';
export const BUILTIN_POLICY_VERSION = '0.4.0';

export const builtInPolicy: RedactionPolicy = {
  id: BUILTIN_POLICY_ID,
  version: BUILTIN_POLICY_VERSION,
  name: 'NetPaste built-in technical redaction policy',
  rules: sensitiveCategories.map(createBuiltInSyntaxRule)
};

export const compiledBuiltInPolicy = compilePolicy(builtInPolicy);

export function createSessionPolicy(
  rules: readonly PolicyRule[],
  revision = 1
): RedactionPolicy {
  const normalizedRevision = Math.max(1, Math.floor(revision));
  return {
    id: 'netpaste-custom-session',
    version: `0.4.0-session.${normalizedRevision}`,
    name: 'NetPaste custom session policy',
    rules: [...rules]
  };
}

function createBuiltInSyntaxRule(
  category: SensitiveCategory,
  index: number
): PolicyRule {
  const highPriority = isHighPriorityCategory(category);
  return {
    id: `builtin.${toRuleSlug(category)}`,
    category,
    description: `Built-in ${category.toLowerCase()} detector.`,
    matcher: {
      kind: 'syntax',
      parser: 'netpaste-detector',
      rule: toRuleSlug(category)
    },
    action: highPriority ? 'replace' : 'review',
    severity: highPriority ? 'High review priority' : 'Review',
    priority: 1000 - index
  };
}

function isHighPriorityCategory(category: SensitiveCategory): boolean {
  return [
    'Credential or secret',
    'Certificate or key material',
    'Cloud identifier'
  ].includes(category);
}

function toRuleSlug(category: SensitiveCategory): string {
  return category
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
}

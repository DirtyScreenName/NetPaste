import type {
  CompiledPolicy,
  CompiledPolicyMatcher,
  ParsedIpv4Cidr,
  PolicyMatcher,
  PolicyRule,
  RedactionPolicy
} from './types';
import { PolicyCompileError } from './types';

const MAX_REGEX_LENGTH = 160;
const MAX_REGEX_REPEAT = 100;
const MAX_DICTIONARY_VALUES = 200;
const MAX_VALUE_LENGTH = 256;
const SAFE_ID_PATTERN = /^[a-z][a-z0-9._-]{2,79}$/;
const SAFE_VERSION_PATTERN = /^[0-9A-Za-z][0-9A-Za-z._-]{0,39}$/;
const SAFE_REPLACEMENT_PATTERN = /^<[A-Z0-9][A-Z0-9:_-]{1,39}>$/;
const UNSAFE_REGEX_PATTERNS = [
  /\\[1-9]/,
  /\(\?<?[=!]/,
  /\([^)]*[+*][^)]*\)[+*{]/,
  /\.\*[+*{]|\.\+[+*{]/,
  /(?:\.\*|\.\+).*(?:\.\*|\.\+)/,
  /(?:\+|\*|\{\d+,?\d*\})(?:\+|\*|\{)/
];

export function compilePolicy(policy: RedactionPolicy): CompiledPolicy {
  validatePolicyMetadata(policy);
  const ruleIds = new Set<string>();
  const rules = [...policy.rules]
    .map((rule) => compileRule(rule, ruleIds))
    .sort((left, right) => right.priority - left.priority || left.id.localeCompare(right.id));

  return {
    id: policy.id,
    version: policy.version,
    name: policy.name,
    rules
  };
}

function validatePolicyMetadata(policy: RedactionPolicy): void {
  if (!SAFE_ID_PATTERN.test(policy.id)) {
    throw new PolicyCompileError('Policy ID must use lowercase letters, numbers, dots, dashes, or underscores.');
  }

  if (!SAFE_VERSION_PATTERN.test(policy.version)) {
    throw new PolicyCompileError('Policy version contains unsupported characters.');
  }

  if (policy.name.trim().length < 3 || policy.name.length > 100) {
    throw new PolicyCompileError('Policy name must be between 3 and 100 characters.');
  }
}

function compileRule(
  rule: PolicyRule,
  ruleIds: Set<string>
): Omit<PolicyRule, 'matcher'> & { matcher: CompiledPolicyMatcher } {
  if (!SAFE_ID_PATTERN.test(rule.id)) {
    throw new PolicyCompileError('Rule ID must use lowercase letters, numbers, dots, dashes, or underscores.');
  }

  if (ruleIds.has(rule.id)) {
    throw new PolicyCompileError(`Duplicate rule ID: ${rule.id}`);
  }
  ruleIds.add(rule.id);

  if (!Number.isSafeInteger(rule.priority) || rule.priority < 0 || rule.priority > 10000) {
    throw new PolicyCompileError(`Rule ${rule.id} has an invalid priority.`);
  }

  if (rule.description.trim().length < 3 || rule.description.length > 120) {
    throw new PolicyCompileError(`Rule ${rule.id} needs a short non-secret description.`);
  }

  if (rule.replacementLabel && !SAFE_REPLACEMENT_PATTERN.test(rule.replacementLabel)) {
    throw new PolicyCompileError(
      `Rule ${rule.id} replacement must be an uppercase placeholder such as <PROTECTED_VALUE>.`
    );
  }

  ensureRuleIdDoesNotContainProtectedValue(rule);

  return {
    ...rule,
    matcher: compileMatcher(rule.id, rule.matcher)
  };
}

function compileMatcher(ruleId: string, matcher: PolicyMatcher): CompiledPolicyMatcher {
  switch (matcher.kind) {
    case 'regex':
      return compileRegexMatcher(ruleId, matcher);
    case 'dictionary':
      return compileDictionaryMatcher(ruleId, matcher);
    case 'cidr':
      return compileCidrMatcher(ruleId, matcher);
    case 'syntax':
      if (!matcher.parser.trim() || !matcher.rule.trim()) {
        throw new PolicyCompileError(`Rule ${ruleId} has an incomplete syntax matcher.`);
      }
      return { kind: 'syntax', parser: matcher.parser, rule: matcher.rule };
    default:
      return assertNever(matcher);
  }
}

function compileRegexMatcher(
  ruleId: string,
  matcher: Extract<PolicyMatcher, { kind: 'regex' }>
): CompiledPolicyMatcher {
  const pattern = matcher.pattern.trim();
  const flags = matcher.flags ?? 'i';

  if (!pattern || pattern.length > MAX_REGEX_LENGTH) {
    throw new PolicyCompileError(`Rule ${ruleId} regular expression must be 1-${MAX_REGEX_LENGTH} characters.`);
  }

  if (!/^[imu]*$/.test(flags) || new Set(flags).size !== flags.length) {
    throw new PolicyCompileError(`Rule ${ruleId} uses unsupported regular-expression flags.`);
  }

  if (UNSAFE_REGEX_PATTERNS.some((unsafe) => unsafe.test(pattern))) {
    throw new PolicyCompileError(`Rule ${ruleId} uses a regular-expression construct that is unsafe for session matching.`);
  }

  validateRegexQuantifiers(ruleId, pattern);

  try {
    return { kind: 'regex', expression: new RegExp(pattern, `${flags}g`) };
  } catch {
    throw new PolicyCompileError(`Rule ${ruleId} contains an invalid regular expression.`);
  }
}

function validateRegexQuantifiers(ruleId: string, pattern: string): void {
  let escaped = false;
  let inCharacterClass = false;

  for (let index = 0; index < pattern.length; index += 1) {
    const character = pattern[index];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (character === '\\') {
      escaped = true;
      continue;
    }
    if (character === '[') {
      inCharacterClass = true;
      continue;
    }
    if (character === ']' && inCharacterClass) {
      inCharacterClass = false;
      continue;
    }
    if (inCharacterClass) continue;

    if (character === '*' || character === '+' || character === '?') {
      throw new PolicyCompileError(
        `Rule ${ruleId} uses an unbounded or optional quantifier that is unsafe for session matching.`
      );
    }

    if (character !== '{') continue;
    const quantifier = pattern.slice(index).match(/^\{(\d+)(?:,(\d*))?\}/);
    if (!quantifier) {
      throw new PolicyCompileError(`Rule ${ruleId} uses an unsupported repetition expression.`);
    }

    const minimum = Number(quantifier[1]);
    const maximum = quantifier[2] === undefined ? minimum : Number(quantifier[2]);
    if (
      quantifier[2] === '' ||
      minimum > maximum ||
      maximum > MAX_REGEX_REPEAT ||
      pattern[index - 1] === ')'
    ) {
      throw new PolicyCompileError(
        `Rule ${ruleId} uses an unsafe repetition; use ${MAX_REGEX_REPEAT} or fewer simple matches.`
      );
    }
    index += quantifier[0].length - 1;
  }
}

function compileDictionaryMatcher(
  ruleId: string,
  matcher: Extract<PolicyMatcher, { kind: 'dictionary' }>
): CompiledPolicyMatcher {
  const values = uniqueValues(matcher.values);
  validateValueCount(ruleId, values, 'dictionary');

  return {
    kind: 'dictionary',
    values: values.sort((left, right) => right.length - left.length),
    caseSensitive: matcher.caseSensitive
  };
}

function compileCidrMatcher(
  ruleId: string,
  matcher: Extract<PolicyMatcher, { kind: 'cidr' }>
): CompiledPolicyMatcher {
  const values = uniqueValues(matcher.ranges);
  validateValueCount(ruleId, values, 'CIDR');
  return { kind: 'cidr', ranges: values.map((value) => parseIpv4Cidr(ruleId, value)) };
}

function uniqueValues(values: readonly string[]): string[] {
  return [...new Set(values.map((value) => value.trim()).filter(Boolean))];
}

function validateValueCount(ruleId: string, values: readonly string[], label: string): void {
  if (values.length === 0 || values.length > MAX_DICTIONARY_VALUES) {
    throw new PolicyCompileError(
      `Rule ${ruleId} ${label} must contain 1-${MAX_DICTIONARY_VALUES} values.`
    );
  }

  if (values.some((value) => value.length > MAX_VALUE_LENGTH)) {
    throw new PolicyCompileError(`Rule ${ruleId} contains a value longer than ${MAX_VALUE_LENGTH} characters.`);
  }
}

function ensureRuleIdDoesNotContainProtectedValue(rule: PolicyRule): void {
  const protectedValues =
    rule.matcher.kind === 'dictionary'
      ? rule.matcher.values
      : rule.matcher.kind === 'cidr'
        ? rule.matcher.ranges
        : [];
  const normalizedId = rule.id.toLowerCase();

  if (
    protectedValues.some((value) => {
      const normalizedValue = value.trim().toLowerCase();
      return normalizedValue.length >= 3 && normalizedId.includes(normalizedValue);
    })
  ) {
    throw new PolicyCompileError(`Rule ${rule.id} ID must not contain a protected value.`);
  }
}

function parseIpv4Cidr(ruleId: string, value: string): ParsedIpv4Cidr {
  const [address, prefixText, ...extra] = value.split('/');
  const prefix = Number(prefixText);
  const addressNumber = parseIpv4(address);

  if (extra.length > 0 || addressNumber === undefined || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) {
    throw new PolicyCompileError(`Rule ${ruleId} contains an invalid IPv4 CIDR range.`);
  }

  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return { network: addressNumber & mask, mask, prefix };
}

export function parseIpv4(value: string): number | undefined {
  const octets = value.split('.');
  if (octets.length !== 4) return undefined;
  let result = 0;

  for (const octet of octets) {
    if (!/^\d{1,3}$/.test(octet)) return undefined;
    const number = Number(octet);
    if (number > 255) return undefined;
    result = ((result << 8) | number) >>> 0;
  }

  return result;
}

function assertNever(value: never): never {
  throw new PolicyCompileError(`Unsupported policy matcher: ${String(value)}`);
}

import { describe, expect, test } from 'vitest';
import { analyzeCurrentText } from '../src/core/analysis';
import { applyProfileDefaults } from '../src/core/profiles';
import { applySelectedRedactions } from '../src/core/redaction';
import {
  BUILTIN_POLICY_ID,
  BUILTIN_POLICY_VERSION,
  builtInPolicy,
  compiledBuiltInPolicy,
  createSessionPolicy
} from '../src/core/policy/builtins';
import { compilePolicy } from '../src/core/policy/compile';
import { evaluatePolicy } from '../src/core/policy/evaluate';
import {
  createRedactionReceipt,
  serializeRedactionReceipt
} from '../src/core/policy/receipt';
import { getPolicyDefaultSelectedIds } from '../src/core/policy/transform';
import type { PolicyAction, PolicyMatcher, PolicyRule } from '../src/core/policy/types';
import type { SensitiveCategory } from '../src/core/types';
import { sensitiveCategories } from '../src/core/types';

function buildRule(
  matcher: PolicyMatcher,
  options: {
    id?: string;
    action?: PolicyAction;
    category?: SensitiveCategory;
    replacementLabel?: string;
    priority?: number;
  } = {}
): PolicyRule {
  return {
    id: options.id ?? 'session-rule-1',
    category: options.category ?? 'Site or customer label',
    description: 'Session custom policy rule.',
    matcher,
    action: options.action ?? 'replace',
    severity: options.action === 'block' ? 'High review priority' : 'Review',
    replacementLabel: options.replacementLabel,
    priority: options.priority ?? 100
  };
}

describe('v0.4 deterministic policy engine', () => {
  test('routes every built-in category through the versioned policy evaluator', () => {
    const evaluation = evaluatePolicy(
      '',
      'hostname EDGE-TEST-01\nip address 192.0.2.10 255.255.255.0',
      compiledBuiltInPolicy,
      { vendorId: 'cisco' }
    );

    expect(builtInPolicy.rules.map((rule) => rule.category))
      .toEqual(sensitiveCategories);
    expect(evaluation.policyId).toBe(BUILTIN_POLICY_ID);
    expect(evaluation.policyVersion).toBe(BUILTIN_POLICY_VERSION);
    expect(evaluation.findings.length).toBeGreaterThan(0);
    expect(evaluation.findings.every((finding) => finding.policyId === BUILTIN_POLICY_ID))
      .toBe(true);
    expect(evaluation.findings.every((finding) => finding.policyVersion === BUILTIN_POLICY_VERSION))
      .toBe(true);
  });

  test('compiles and evaluates bounded session regex rules', () => {
    const policy = compilePolicy(
      createSessionPolicy([
        buildRule(
          { kind: 'regex', pattern: 'site-[a-z]{3}-\\d{2}', flags: 'i' },
          { action: 'alias' }
        )
      ])
    );
    const evaluation = evaluatePolicy('', 'description site-den-01 uplink', policy);

    expect(evaluation.findings).toHaveLength(1);
    expect(evaluation.findings[0]).toMatchObject({
      category: 'Site or customer label',
      policyAction: 'alias',
      policyId: 'netpaste-custom-session',
      source: 'cleaned',
      cleanedLine: 1
    });
    expect(evaluation.findings[0].preview).not.toContain('site-den-01');
    expect(evaluation.findings[0].reason).not.toContain('site-[a-z]');
    expect(evaluation.findings[0].id).not.toContain('site-den-01');
  });

  test('rejects unsafe, invalid, and oversized regular expressions', () => {
    for (const pattern of [
      '(a+)+',
      '(?=secret)',
      '(.)\\1',
      '.*value.*other.*',
      '[a-z]+',
      'a{1,101}',
      '(a|aa){20}'
    ]) {
      expect(() =>
        compilePolicy(
          createSessionPolicy([
            buildRule({ kind: 'regex', pattern, flags: 'i' })
          ])
        )
      ).toThrow(/unsafe/);
    }

    expect(() =>
      compilePolicy(
        createSessionPolicy([
          buildRule({ kind: 'regex', pattern: '[unterminated', flags: 'i' })
        ])
      )
    ).toThrow(/invalid regular expression/);
    expect(() =>
      compilePolicy(
        createSessionPolicy([
          buildRule({ kind: 'regex', pattern: 'a'.repeat(161), flags: 'i' })
        ])
      )
    ).toThrow(/1-160/);
  });

  test('matches protected dictionaries without exposing their values in metadata', () => {
    const protectedValue = 'Windsor-Production-Site';
    const policy = compilePolicy(
      createSessionPolicy([
        buildRule(
          { kind: 'dictionary', values: [protectedValue], caseSensitive: false },
          { action: 'block', id: 'session-rule-site' }
        )
      ])
    );
    const evaluation = evaluatePolicy(
      `ticket for ${protectedValue}`,
      `ticket for ${protectedValue}`,
      policy
    );
    const finding = evaluation.findings[0];
    const safeMetadata = `${finding.id} ${finding.preview} ${finding.reason} ${finding.ruleId}`;

    expect(evaluation.findings).toHaveLength(1);
    expect(finding.source).toBe('both');
    expect(finding.originalLine).toBe(1);
    expect(finding.cleanedLine).toBe(1);
    expect(finding.redactionRanges).toHaveLength(1);
    expect(finding.severity).toBe('High review priority');
    expect(safeMetadata).not.toContain(protectedValue);
  });

  test('masks every protected value when multiple custom matches share a preview line', () => {
    const firstValue = 'SITE-ONLY-ALPHA';
    const secondValue = 'CUSTOMER-ONLY-BRAVO';
    const policy = compilePolicy(
      createSessionPolicy([
        buildRule(
          { kind: 'dictionary', values: [firstValue], caseSensitive: true },
          { id: 'session-rule-first', priority: 200 }
        ),
        buildRule(
          { kind: 'dictionary', values: [secondValue], caseSensitive: true },
          { id: 'session-rule-second', priority: 100 }
        )
      ])
    );
    const findings = evaluatePolicy('', `${firstValue} peers with ${secondValue}`, policy).findings;

    expect(findings).toHaveLength(2);
    for (const finding of findings) {
      expect(finding.preview).not.toContain(firstValue);
      expect(finding.preview).not.toContain(secondValue);
      expect(finding.ruleId).toMatch(/^session\./);
    }
  });

  test('rejects rule IDs that contain protected dictionary values', () => {
    expect(() =>
      compilePolicy(
        createSessionPolicy([
          buildRule(
            { kind: 'dictionary', values: ['acme'], caseSensitive: false },
            { id: 'session-acme-rule' }
          )
        ])
      )
    ).toThrow(/must not contain a protected value/);
  });

  test('matches valid IPv4 CIDR ranges and rejects invalid ranges', () => {
    const policy = compilePolicy(
      createSessionPolicy([
        buildRule(
          { kind: 'cidr', ranges: ['10.31.0.0/16'] },
          { category: 'Private IP address', action: 'alias' }
        )
      ])
    );
    const evaluation = evaluatePolicy('', 'peer 10.31.24.2 and 10.32.24.2', policy);

    expect(evaluation.findings).toHaveLength(1);
    expect(evaluation.findings[0].redactionRanges).toEqual([{ start: 5, end: 15 }]);
    expect(() =>
      compilePolicy(
        createSessionPolicy([
          buildRule({ kind: 'cidr', ranges: ['10.31.999.0/33'] })
        ])
      )
    ).toThrow(/invalid IPv4 CIDR/);
  });

  test('uses rule priority to resolve overlapping custom matches', () => {
    const policy = compilePolicy(
      createSessionPolicy([
        buildRule(
          { kind: 'dictionary', values: ['SITE-ALPHA'], caseSensitive: true },
          { id: 'session-rule-review', action: 'review', priority: 10 }
        ),
        buildRule(
          { kind: 'regex', pattern: 'SITE', flags: '' },
          { id: 'session-rule-block', action: 'block', priority: 100 }
        )
      ])
    );
    const findings = evaluatePolicy('', 'SITE-ALPHA', policy).findings;

    expect(findings).toHaveLength(1);
    expect(findings[0].policyAction).toBe('block');
    expect(findings[0].preview).not.toContain('SITE-ALPHA');
  });

  test('keeps findings from different rules distinct when canonical values match', () => {
    const policy = compilePolicy(
      createSessionPolicy([
        buildRule(
          { kind: 'regex', pattern: '^SITE', flags: '' },
          { id: 'session-rule-allow', action: 'allow', priority: 200 }
        ),
        buildRule(
          { kind: 'regex', pattern: 'SITE', flags: '' },
          { id: 'session-rule-block', action: 'block', priority: 100 }
        )
      ])
    );
    const findings = evaluatePolicy('', 'SITE primary\nbackup SITE', policy).findings;

    expect(findings).toHaveLength(2);
    expect(findings.map((finding) => finding.policyAction)).toEqual(['block', 'allow']);
    expect(new Set(findings.map((finding) => finding.id)).size).toBe(2);
  });

  test('versions each session-policy revision independently', () => {
    const first = compilePolicy(createSessionPolicy([], 1));
    const second = compilePolicy(createSessionPolicy([], 2));

    expect(first.version).toBe('0.4.0-session.1');
    expect(second.version).toBe('0.4.0-session.2');
    expect(second.version).not.toBe(first.version);
  });

  test('deduplicates equivalent occurrences and preserves all cleaned ranges', () => {
    const policy = compilePolicy(
      createSessionPolicy([
        buildRule({ kind: 'dictionary', values: ['SITE-ALPHA'], caseSensitive: true })
      ])
    );
    const text = 'site SITE-ALPHA\nneighbor SITE-ALPHA';
    const finding = evaluatePolicy(text, text, policy).findings[0];

    expect(finding.source).toBe('both');
    expect(finding.originalLine).toBe(1);
    expect(finding.cleanedLine).toBe(1);
    expect(finding.redactionRanges).toEqual([
      { start: 5, end: 15 },
      { start: 25, end: 35 }
    ]);
  });

  test('lets custom policy ranges override equivalent built-in findings', () => {
    const policy = compilePolicy(
      createSessionPolicy([
        buildRule(
          { kind: 'cidr', ranges: ['10.31.0.0/16'] },
          { category: 'Private IP address', action: 'block' }
        )
      ])
    );
    const analysis = analyzeCurrentText('', 'ip address 10.31.24.2', 200, {
      policy,
      profileId: 'custom-session'
    });
    const matching = analysis.findings.filter(
      (finding) => finding.category === 'Private IP address'
    );

    expect(matching).toHaveLength(1);
    expect(matching[0].policyAction).toBe('block');
    expect(analysis.policyId).toBe(
      'netpaste-builtins+netpaste-custom-session'
    );
  });

  test('preserves built-in ranges not covered by a custom policy match', () => {
    const policy = compilePolicy(
      createSessionPolicy([
        buildRule(
          { kind: 'regex', pattern: '10\\.31\\.24\\.2$', flags: '' },
          {
            id: 'session-rule-first-ip',
            category: 'Private IP address',
            action: 'block'
          }
        )
      ])
    );
    const text = 'primary 10.31.24.2\nbackup 10.31.24.2 peer';
    const analysis = analyzeCurrentText('', text, 200, {
      policy,
      profileId: 'custom-session'
    });
    const matching = analysis.findings.filter(
      (finding) => finding.category === 'Private IP address'
    );

    expect(matching).toHaveLength(2);
    expect(matching.find((finding) => finding.policyAction === 'block')?.redactionRanges)
      .toEqual([{ start: 8, end: 18 }]);
    expect(matching.find((finding) => finding.policyAction === undefined)?.redactionRanges)
      .toEqual([{ start: 26, end: 36 }]);
  });

  test('preserves original-only built-in findings when a custom policy is active', () => {
    const policy = compilePolicy(
      createSessionPolicy([
        buildRule(
          { kind: 'dictionary', values: ['SITE-ALPHA'], caseSensitive: true },
          { id: 'session-rule-site', action: 'review' }
        )
      ])
    );
    const analysis = analyzeCurrentText(
      'source address 10.31.24.2',
      'cleaned output without an address',
      200,
      { policy, profileId: 'custom-session' }
    );

    expect(
      analysis.findings.some(
        (finding) =>
          finding.category === 'Private IP address' &&
          finding.source === 'original' &&
          finding.redactionRanges.length === 0
      )
    ).toBe(true);
  });

  test('applies replace and alias actions through the existing redaction pipeline', () => {
    const policy = compilePolicy(
      createSessionPolicy([
        buildRule(
          { kind: 'dictionary', values: ['CUSTOMER-RED'], caseSensitive: true },
          { action: 'replace', replacementLabel: '<CUSTOMER>' }
        ),
        buildRule(
          { kind: 'cidr', ranges: ['10.31.0.0/16'] },
          {
            id: 'session-rule-2',
            action: 'alias',
            category: 'Private IP address',
            priority: 90
          }
        )
      ])
    );
    const text = 'CUSTOMER-RED peer 10.31.24.2 and 10.31.24.2';
    const analysis = analyzeCurrentText('', text, 200, {
      policy,
      profileId: 'custom-session',
      useTokenMapping: false
    });
    const selectedIds = applyProfileDefaults(analysis.findings, 'custom-session');
    const output = applySelectedRedactions(text, analysis.findings, selectedIds);

    expect(output).toBe('<CUSTOMER> peer <IP-1> and <IP-1>');
  });

  test('assigns collision-free aliases to reserved example IPv4 addresses', () => {
    const policy = compilePolicy(
      createSessionPolicy([
        buildRule(
          { kind: 'cidr', ranges: ['192.0.2.0/24'] },
          {
            id: 'session-rule-example-a',
            action: 'alias',
            category: 'Public IP address',
            priority: 100
          }
        ),
        buildRule(
          { kind: 'cidr', ranges: ['198.51.100.0/24'] },
          {
            id: 'session-rule-example-b',
            action: 'alias',
            category: 'Public IP address',
            priority: 90
          }
        )
      ])
    );
    const text = 'peers 192.0.2.10 and 198.51.100.27 then 192.0.2.10';
    const analysis = analyzeCurrentText('', text, 200, {
      policy,
      profileId: 'custom-session',
      useTokenMapping: false
    });
    const selectedIds = applyProfileDefaults(analysis.findings, 'custom-session');
    const output = applySelectedRedactions(text, analysis.findings, selectedIds);

    expect(output).toBe('peers <IP-1> and <IP-2> then <IP-1>');
    expect(new Set(analysis.findings.map((finding) => finding.id)).size)
      .toBe(analysis.findings.length);
  });

  test('keeps allow and review findings unselected while selecting transform actions', () => {
    const actions: PolicyAction[] = ['allow', 'review', 'replace', 'alias', 'block'];
    const policy = compilePolicy(
      createSessionPolicy(
        actions.map((action, index) =>
          buildRule(
            {
              kind: 'dictionary',
              values: [`VALUE-${index}`],
              caseSensitive: true
            },
            { id: `session-rule-${index + 1}`, action, priority: 100 - index }
          )
        )
      )
    );
    const findings = evaluatePolicy('', actions.map((_, index) => `VALUE-${index}`).join(' '), policy).findings;
    const selected = getPolicyDefaultSelectedIds(findings);

    expect(findings.filter((finding) => selected.has(finding.id)).map((finding) => finding.policyAction))
      .toEqual(expect.arrayContaining(['replace', 'alias', 'block']));
    expect(findings.filter((finding) => selected.has(finding.id))).toHaveLength(3);
  });

  test('creates a non-secret receipt and reports unhandled blocks as pending', async () => {
    const secret = 'TEST-ONLY-SECRET';
    const policy = compilePolicy(
      createSessionPolicy([
        buildRule(
          { kind: 'dictionary', values: [secret], caseSensitive: true },
          { action: 'block', category: 'Credential or secret' }
        )
      ])
    );
    const original = `password ${secret}`;
    const analysis = analyzeCurrentText(original, original, 200, { policy });
    const pending = await createRedactionReceipt(
      original,
      original,
      analysis,
      new Set(),
      { processedAt: '2026-07-17T20:00:00.000Z' }
    );
    const selectedIds = applyProfileDefaults(analysis.findings, 'custom-session');
    const sanitized = applySelectedRedactions(original, analysis.findings, selectedIds);
    const approved = await createRedactionReceipt(
      original,
      sanitized,
      analysis,
      selectedIds,
      { processedAt: '2026-07-17T20:00:00.000Z' }
    );
    const serialized = serializeRedactionReceipt(approved);

    expect(pending.reviewStatus).toBe('pending');
    expect(approved.reviewStatus).toBe('approved');
    expect(approved.originalRetained).toBe(false);
    expect(approved.originalSha256).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(approved.sanitizedSha256).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(serialized).not.toContain(secret);
    expect(serialized).not.toContain('<REDACTED');
  });

  test('reports oversized input instead of evaluating custom session rules', () => {
    const policy = compilePolicy(
      createSessionPolicy([
        buildRule({ kind: 'dictionary', values: ['protected'], caseSensitive: true })
      ])
    );
    const evaluation = evaluatePolicy('', 'x'.repeat(1_000_001), policy);

    expect(evaluation.findings).toHaveLength(0);
    expect(evaluation.unsupportedContent).toEqual([
      'Custom session policy skipped cleaned text larger than 1,000,000 characters.'
    ]);
  });
});

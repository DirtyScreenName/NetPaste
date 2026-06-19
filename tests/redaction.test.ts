import { describe, expect, test } from 'vitest';
import { detectSensitive } from '../src/core/detectSensitive';
import {
  applySelectedRedactions,
  getDefaultSelectedFindingIds,
  reconcileSelectedFindingIds
} from '../src/core/redaction';
import type { SensitiveFinding, TextRange } from '../src/core/types';

describe('applySelectedRedactions', () => {
  test('removes a single selected value and trims created trailing whitespace', () => {
    const text = 'ip address 192.0.2.10';
    const finding = createFinding('ipv4', [rangeFor(text, '192.0.2.10')]);

    expect(applySelectedRedactions(text, [finding], new Set(['ipv4']))).toBe(
      'ip address'
    );
  });

  test('removes multiple selected values without changing unselected values', () => {
    const text = 'contact noc@example.com https://example.test/path';
    const email = createFinding('email', [rangeFor(text, 'noc@example.com')]);
    const url = createFinding('url', [rangeFor(text, 'https://example.test/path')]);

    expect(applySelectedRedactions(text, [email, url], new Set(['email']))).toBe(
      'contact https://example.test/path'
    );
  });

  test('merges overlapping ranges before removal', () => {
    const text = 'prefix secret-value suffix';
    const finding = createFinding('credential', [
      rangeFor(text, 'secret-value'),
      { start: text.indexOf('value'), end: text.indexOf('value') + 'value'.length }
    ]);

    expect(applySelectedRedactions(text, [finding], new Set(['credential']))).toBe(
      'prefix suffix'
    );
  });

  test('one deduplicated finding removes repeated equivalent occurrences', () => {
    const text = 'primary 192.0.2.10\nsecondary 192.0.2.10';
    const finding = createFinding('ipv4', [
      rangeFor(text, '192.0.2.10'),
      rangeFor(text, '192.0.2.10', text.indexOf('\n'))
    ]);

    expect(applySelectedRedactions(text, [finding], new Set(['ipv4']))).toBe(
      'primary\nsecondary'
    );
  });

  test('collapses only whitespace created by removal', () => {
    const text = 'ip address 192.0.2.10 255.255.255.0';
    const finding = createFinding('ipv4', [rangeFor(text, '192.0.2.10')]);

    expect(applySelectedRedactions(text, [finding], new Set(['ipv4']))).toBe(
      'ip address 255.255.255.0'
    );
  });
});

describe('selective redaction metadata', () => {
  test('detects cleaned redaction ranges for supported finding categories', () => {
    const cleanedText = [
      'Router01#show running-config',
      'ip address 192.0.2.10 255.255.255.0',
      'ipv6 address 2001:db8::1/64',
      'mac-address aabb.ccdd.eeff',
      'username admin secret 5 $1$abcdef',
      'contact noc@example.com https://example.test/path'
    ].join('\n');
    const findings = detectSensitive('', cleanedText);

    for (const category of [
      'Hostname prompt',
      'IPv4 address',
      'IPv6 address',
      'MAC address',
      'Credential or secret',
      'Email address',
      'URL'
    ] as const) {
      expect(
        findings.some(
          (finding) =>
            finding.category === category && finding.redactionRanges.length > 0
        )
      ).toBe(true);
    }
  });

  test('selects cleaned high-priority findings by default', () => {
    const findings = detectSensitive(
      '',
      'ip address 192.0.2.10 255.255.255.0\npassword 0 editedSecret'
    );
    const selectedIds = getDefaultSelectedFindingIds(findings);
    const credential = findings.find(
      (finding) => finding.category === 'Credential or secret'
    );
    const ipv4 = findings.find((finding) => finding.category === 'IPv4 address');

    expect(credential).toBeDefined();
    expect(ipv4).toBeDefined();
    expect(selectedIds.has(credential?.id ?? '')).toBe(true);
    expect(selectedIds.has(ipv4?.id ?? '')).toBe(false);
  });

  test('does not make original-only findings redaction-capable', () => {
    const findings = detectSensitive('password 0 originalSecret', '');
    const credential = findings.find(
      (finding) => finding.category === 'Credential or secret'
    );

    expect(credential?.redactionRanges).toHaveLength(0);
    expect(getDefaultSelectedFindingIds(findings).size).toBe(0);
  });

  test('reconciles selections after edited cleaned-output detection', () => {
    const initialFindings = detectSensitive('', 'password 0 firstSecret');
    const initialSelectedIds = getDefaultSelectedFindingIds(initialFindings);
    const editedFindings = detectSensitive(
      '',
      'password 0 firstSecret\nsecret 0 secondSecret'
    );
    const reconciledIds = reconcileSelectedFindingIds(
      editedFindings,
      initialSelectedIds,
      new Set(initialFindings.map((finding) => finding.id))
    );

    expect(reconciledIds.size).toBe(2);
  });
});

function createFinding(id: string, redactionRanges: TextRange[]): SensitiveFinding {
  return {
    id,
    category: 'Credential or secret',
    severity: 'High review priority',
    preview: '[masked]',
    source: 'cleaned',
    cleanedLine: 1,
    redactionRanges
  };
}

function rangeFor(text: string, value: string, fromIndex = 0): TextRange {
  const start = text.indexOf(value, fromIndex);

  if (start < 0) {
    throw new Error(`Missing test value: ${value}`);
  }

  return { start, end: start + value.length };
}

import { describe, expect, test } from 'vitest';
import { detectSensitive } from '../src/core/detectSensitive';
import {
  applySelectedRedactions,
  getDefaultSelectedFindingIds,
  reconcileSelectedFindingIds
} from '../src/core/redaction';
import type { SensitiveFinding, TextRange } from '../src/core/types';

describe('applySelectedRedactions', () => {
  test('replaces a single selected value with a redaction label', () => {
    const text = 'ip address 192.0.2.10';
    const finding = createFinding('ipv4', 'IPv4 address', [
      rangeFor(text, '192.0.2.10')
    ]);

    expect(applySelectedRedactions(text, [finding], new Set(['ipv4']))).toBe(
      'ip address <REDACTED:IP>'
    );
  });

  test('replaces selected values without changing unselected values', () => {
    const text = 'contact noc@example.com https://example.test/path';
    const email = createFinding('email', 'Email address', [
      rangeFor(text, 'noc@example.com')
    ]);
    const url = createFinding('url', 'URL', [
      rangeFor(text, 'https://example.test/path')
    ]);

    expect(applySelectedRedactions(text, [email, url], new Set(['email']))).toBe(
      'contact <REDACTED:EMAIL> https://example.test/path'
    );
  });

  test('merges overlapping ranges before replacement', () => {
    const text = 'prefix secret-value suffix';
    const finding = createFinding('credential', 'Credential or secret', [
      rangeFor(text, 'secret-value'),
      { start: text.indexOf('value'), end: text.indexOf('value') + 'value'.length }
    ]);

    expect(applySelectedRedactions(text, [finding], new Set(['credential']))).toBe(
      'prefix <REDACTED> suffix'
    );
  });

  test('keeps a specific label when overlapping replacements agree', () => {
    const text = 'prefix 192.0.2.10 suffix';
    const findings = [
      createFinding('ipv4-full', 'IPv4 address', [rangeFor(text, '192.0.2.10')]),
      createFinding('ipv4-partial', 'IPv4 address', [
        { start: text.indexOf('192.0.2'), end: text.indexOf('192.0.2') + '192.0.2'.length }
      ])
    ];

    expect(
      applySelectedRedactions(text, findings, new Set(['ipv4-full', 'ipv4-partial']))
    ).toBe('prefix <REDACTED:IP> suffix');
  });

  test('one deduplicated finding replaces repeated equivalent occurrences', () => {
    const text = 'primary 192.0.2.10\nsecondary 192.0.2.10';
    const finding = createFinding('ipv4', 'IPv4 address', [
      rangeFor(text, '192.0.2.10'),
      rangeFor(text, '192.0.2.10', text.indexOf('\n'))
    ]);

    expect(applySelectedRedactions(text, [finding], new Set(['ipv4']))).toBe(
      'primary <REDACTED:IP>\nsecondary <REDACTED:IP>'
    );
  });

  test('preserves surrounding config tokens when replacing a value', () => {
    const text = 'ip address 192.0.2.10 255.255.255.0';
    const finding = createFinding('ipv4', 'IPv4 address', [
      rangeFor(text, '192.0.2.10')
    ]);

    expect(applySelectedRedactions(text, [finding], new Set(['ipv4']))).toBe(
      'ip address <REDACTED:IP> 255.255.255.0'
    );
  });

  test('replaces Cisco password values without removing username syntax', () => {
    const text = 'username admin password 7 0822455D0A16';
    const findings = detectSensitive('', text);
    const selectedIds = getDefaultSelectedFindingIds(findings);
    const output = applySelectedRedactions(text, findings, selectedIds);

    expect(output).toBe('username admin password 7 <REDACTED:CREDENTIAL>');
    expect(output).not.toContain('0822455D0A16');
  });

  test('preserves suffix tokens after enable secret values', () => {
    const text = 'enable secret 5 myEnableSecret address 203.0.113.10';
    const findings = detectSensitive('', text);
    const selectedIds = new Set(findings.map((finding) => finding.id));
    const output = applySelectedRedactions(text, findings, selectedIds);

    expect(output).toBe(
      'enable secret 5 <REDACTED:SECRET> address <REDACTED:IP>'
    );
    expect(output).not.toContain('myEnableSecret');
    expect(output).not.toContain('203.0.113.10');
  });

  test('replaces only SNMP community values and keeps permission suffixes', () => {
    const text = 'snmp-server community private RO';
    const findings = detectSensitive('', text);
    const selectedIds = getDefaultSelectedFindingIds(findings);
    const output = applySelectedRedactions(text, findings, selectedIds);

    expect(output).toBe('snmp-server community <REDACTED:COMMUNITY> RO');
    expect(output).not.toContain('private');
  });

  test('replaces generic community values and keeps suffix tokens', () => {
    const text = 'set snmp community private authorization read-only';
    const findings = detectSensitive('', text);
    const selectedIds = getDefaultSelectedFindingIds(findings);
    const output = applySelectedRedactions(text, findings, selectedIds);

    expect(output).toBe(
      'set snmp community <REDACTED:COMMUNITY> authorization read-only'
    );
    expect(output).not.toContain('private');
  });

  test('replaces whitespace-separated API key values', () => {
    const text = 'api_key live_secret_value';
    const findings = detectSensitive('', text);
    const selectedIds = getDefaultSelectedFindingIds(findings);

    expect(applySelectedRedactions(text, findings, selectedIds)).toBe(
      'api_key <REDACTED:TOKEN>'
    );
  });

  test('replaces ISAKMP keys after an encryption type without removing other findings', () => {
    const text = 'crypto isakmp key 6 mySecretKey address 203.0.113.10';
    const findings = detectSensitive('', text);
    const selectedIds = new Set(findings.map((finding) => finding.id));
    const output = applySelectedRedactions(text, findings, selectedIds);

    expect(output).toBe(
      'crypto isakmp key 6 <REDACTED:SECRET> address <REDACTED:IP>'
    );
    expect(output).not.toContain('mySecretKey');
    expect(output).not.toContain('203.0.113.10');
  });

  test('degrades overlapping replacements with different labels to a generic label', () => {
    const text = 'password 0 203.0.113.10';
    const findings = detectSensitive('', text);
    const selectedIds = new Set(findings.map((finding) => finding.id));
    const credential = findings.find(
      (finding) => finding.category === 'Credential or secret'
    );
    const ipv4 = findings.find((finding) => finding.category === 'IPv4 address');

    expect(credential).toBeDefined();
    expect(ipv4).toBeDefined();
    expect(
      credential &&
        ipv4 &&
        credential.redactionRanges[0].start < ipv4.redactionRanges[0].end &&
        ipv4.redactionRanges[0].start < credential.redactionRanges[0].end
    ).toBe(true);
    expect(applySelectedRedactions(text, findings, selectedIds)).toBe(
      'password 0 <REDACTED>'
    );
  });

  test('keeps multiline config line count after replacing sensitive values', () => {
    const text = [
      'interface Vlan10',
      ' ip address 192.0.2.10 255.255.255.0',
      ' username admin secret 5 $1$abcdef',
      ' snmp-server community private RO'
    ].join('\n');
    const findings = detectSensitive('', text);
    const selectedIds = new Set(findings.map((finding) => finding.id));
    const output = applySelectedRedactions(text, findings, selectedIds);

    expect(output.split('\n')).toHaveLength(text.split('\n').length);
    expect(output).toContain(' username admin secret 5 <REDACTED:SECRET>');
    expect(output).toContain(' snmp-server community <REDACTED:COMMUNITY> RO');
    expect(output).not.toContain('$1$abcdef');
    expect(output).not.toContain('private');
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

  test('does not re-flag redaction labels as credentials after reruns', () => {
    const initialText = 'password 0 firstSecret';
    const initialFindings = detectSensitive('', initialText);
    const selectedIds = getDefaultSelectedFindingIds(initialFindings);
    const redactedText = applySelectedRedactions(initialText, initialFindings, selectedIds);
    const rerunFindings = detectSensitive('', redactedText);

    expect(redactedText).toBe('password 0 <REDACTED:CREDENTIAL>');
    expect(
      rerunFindings.filter((finding) => finding.category === 'Credential or secret')
    ).toHaveLength(0);
  });
});

function createFinding(
  id: string,
  category: SensitiveFinding['category'],
  redactionRanges: TextRange[]
): SensitiveFinding {
  return {
    id,
    category,
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

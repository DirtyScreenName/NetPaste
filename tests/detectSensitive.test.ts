import { describe, expect, test } from 'vitest';
import {
  detectSensitive,
  getRenderedFindings,
  summarizeFindings
} from '../src/core/detectSensitive';

describe('detectSensitive', () => {
  test('detects IPv4 addresses and ignores invalid IPv4 octets', () => {
    const findings = detectSensitive(
      'valid 192.0.2.10 invalid 999.1.1.1',
      'valid 192.0.2.10 invalid 999.1.1.1'
    );

    expect(findings.filter((finding) => finding.category === 'IPv4 address'))
      .toHaveLength(1);
    expect(findings[0]).toMatchObject({
      category: 'IPv4 address',
      source: 'both',
      originalLine: 1,
      cleanedLine: 1
    });
  });

  test('detects IPv6 addresses where reasonably identifiable', () => {
    const findings = detectSensitive('next-hop 2001:db8::1', '');

    expect(findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          category: 'IPv6 address',
          source: 'original',
          originalLine: 1
        })
      ])
    );
  });

  test('detects colon, dash, and Cisco dotted MAC address formats', () => {
    const findings = detectSensitive(
      'aabb.ccdd.eeff\n00:11:22:33:44:55\n00-11-22-33-44-66',
      ''
    );

    expect(findings.filter((finding) => finding.category === 'MAC address'))
      .toHaveLength(3);
  });

  test('detects email addresses and URLs with masked previews', () => {
    const findings = detectSensitive(
      'contact noc@example.com https://example.test/path?token=secret#frag',
      ''
    );

    expect(findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ category: 'Email address' }),
        expect.objectContaining({
          category: 'URL',
          preview: 'contact [masked-email] [masked-url]'
        })
      ])
    );
  });

  test('does not expose raw sensitive values in previews or finding ids', () => {
    const findings = detectSensitive(
      '',
      'Router01#show\nip address 192.0.2.10 255.255.255.0\nmac-address aabb.ccdd.eeff\ncontact noc@example.com https://example.test/path'
    );
    const renderedText = findings
      .map((finding) => `${finding.id} ${finding.preview}`)
      .join('\n');

    expect(renderedText).not.toContain('Router01');
    expect(renderedText).not.toContain('192.0.2.10');
    expect(renderedText).not.toContain('aabb.ccdd.eeff');
    expect(renderedText).not.toContain('noc@example.com');
    expect(renderedText).not.toContain('https://example.test/path');
  });

  test('detects hostname-like device prompts and avoids obvious false positives', () => {
    const findings = detectSensitive(
      'Router01(config-if)# description test\nset threshold > 90',
      ''
    );

    expect(findings.filter((finding) => finding.category === 'Hostname prompt'))
      .toHaveLength(1);
    expect(findings[0]).toMatchObject({
      category: 'Hostname prompt',
      originalLine: 1
    });
  });

  test('detects password and secret configuration lines with masked previews', () => {
    const findings = detectSensitive(
      'username admin secret 5 $1$abcdef\npassword 7 0822455D0A16',
      ''
    );

    const credentialFindings = findings.filter(
      (finding) => finding.category === 'Credential or secret'
    );

    expect(credentialFindings).toHaveLength(2);
    expect(credentialFindings.every((finding) => finding.severity === 'High review priority')).toBe(true);
    expect(credentialFindings.map((finding) => finding.preview).join('\n')).not.toContain('$1$abcdef');
    expect(credentialFindings.map((finding) => finding.preview).join('\n')).not.toContain('0822455D0A16');
    expect(credentialFindings[0].preview).toContain('[masked]');
  });

  test('detects SNMP community strings with masked previews', () => {
    const findings = detectSensitive('snmp-server community public RO', '');
    const credential = findings.find(
      (finding) => finding.category === 'Credential or secret'
    );

    expect(credential).toMatchObject({
      severity: 'High review priority',
      preview: 'snmp-server community [masked] RO'
    });
  });

  test('detects generic community strings with redactable value ranges', () => {
    const findings = detectSensitive(
      '',
      'set snmp community private authorization read-only'
    );
    const credential = findings.find(
      (finding) => finding.category === 'Credential or secret'
    );

    expect(credential).toMatchObject({
      severity: 'High review priority',
      preview: 'set snmp community [masked] authorization read-only'
    });
    expect(credential?.redactionRanges).toHaveLength(1);
  });

  test('detects whitespace-separated API keys without exposing values', () => {
    const findings = detectSensitive('', 'api_key live_secret_value');
    const credential = findings.find(
      (finding) => finding.category === 'Credential or secret'
    );

    expect(credential?.preview).toContain('api_key [masked]');
    expect(credential?.preview).not.toContain('live_secret_value');
    expect(credential?.redactionRanges).toHaveLength(1);
  });

  test('detects bearer tokens without exposing values', () => {
    const findings = detectSensitive('', 'Authorization: Bearer abc.def.ghi');
    const credential = findings.find(
      (finding) => finding.category === 'Credential or secret'
    );

    expect(credential).toMatchObject({
      severity: 'High review priority',
      preview: 'Authorization: Bearer [masked]'
    });
    expect(credential?.preview).not.toContain('abc.def.ghi');
    expect(credential?.redactionRanges).toHaveLength(1);
  });

  test('collects later generic credential values on lines with specific matches', () => {
    const findings = detectSensitive(
      '',
      'snmp-server community public password 0 laterSecret'
    );
    const credential = findings.find(
      (finding) => finding.category === 'Credential or secret'
    );

    expect(credential?.redactionRanges).toHaveLength(2);
    expect(credential?.preview).not.toContain('public');
    expect(credential?.preview).not.toContain('laterSecret');
  });

  test('does not create credential findings for redaction placeholders', () => {
    const findings = detectSensitive(
      '',
      'password 0 <REDACTED:CREDENTIAL>\nsecret 0 "<REDACTED:SECRET>"'
    );

    expect(
      findings.filter((finding) => finding.category === 'Credential or secret')
    ).toHaveLength(0);
  });

  test('avoids credential keyword false positives such as tokenization', () => {
    const findings = detectSensitive(
      'The parser uses tokenization before normalization.',
      ''
    );

    expect(findings).toHaveLength(0);
  });

  test('deduplicates equivalent original and cleaned findings and merges source', () => {
    const findings = detectSensitive(
      'Router01#\n ip address 192.0.2.5 255.255.255.0',
      'Router01#\nip address 192.0.2.5 255.255.255.0'
    );

    const ipv4 = findings.find((finding) => finding.category === 'IPv4 address');
    const prompt = findings.find(
      (finding) => finding.category === 'Hostname prompt'
    );

    expect(ipv4).toMatchObject({
      source: 'both',
      originalLine: 2,
      cleanedLine: 2
    });
    expect(prompt).toMatchObject({
      source: 'both',
      originalLine: 1,
      cleanedLine: 1
    });
  });

  test('preserves original versus cleaned line numbers after cleanup changes lines', () => {
    const findings = detectSensitive(
      '\n\nip address 198.51.100.10 255.255.255.0',
      'ip address 198.51.100.10 255.255.255.0'
    );
    const ipv4 = findings.find((finding) => finding.category === 'IPv4 address');

    expect(ipv4).toMatchObject({
      source: 'both',
      originalLine: 3,
      cleanedLine: 1
    });
  });

  test('sorts high-priority findings before review findings', () => {
    const findings = detectSensitive(
      'ip address 203.0.113.5 255.255.255.0\npassword 0 example',
      ''
    );

    expect(findings[0]).toMatchObject({
      category: 'Credential or secret',
      severity: 'High review priority'
    });
  });

  test('caps rendered findings while preserving full category counts', () => {
    const input = Array.from(
      { length: 205 },
      (_, index) => `host ${index} 192.0.2.${index % 200}`
    ).join('\n');
    const findings = detectSensitive(input, '');
    const rendered = getRenderedFindings(findings, 10);
    const summary = summarizeFindings(findings);

    expect(rendered).toHaveLength(10);
    expect(summary['IPv4 address']).toBeGreaterThan(10);
  });
});

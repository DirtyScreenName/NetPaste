import { describe, expect, test } from 'vitest';
import { maskSensitiveText } from '../src/core/maskSensitive';

describe('maskSensitiveText', () => {
  test('masks detected network identifiers and contact values', () => {
    const masked = maskSensitiveText(
      [
        'Router01#show ip interface brief',
        'Vlan10 192.0.2.10 2001:db8::1',
        'neighbor aabb.ccdd.eeff 00:11:22:33:44:55',
        'contact noc@example.com https://example.test/path?token=secret#frag'
      ].join('\n')
    );

    expect(masked).toContain('[masked-hostname]#show ip interface brief');
    expect(masked).toContain('[masked-ipv4]');
    expect(masked).toContain('[masked-ipv6]');
    expect(masked).toContain('[masked-mac]');
    expect(masked).toContain('[masked-email]');
    expect(masked).toContain('[masked-url]');
    expect(masked).not.toContain('Router01#');
    expect(masked).not.toContain('192.0.2.10');
    expect(masked).not.toContain('2001:db8::1');
    expect(masked).not.toContain('aabb.ccdd.eeff');
    expect(masked).not.toContain('00:11:22:33:44:55');
    expect(masked).not.toContain('noc@example.com');
    expect(masked).not.toContain('token=secret');
  });

  test('masks credential values without exposing secrets', () => {
    const masked = maskSensitiveText(
      [
        'username admin secret 5 $1$abcdef',
        'password 7 0822455D0A16',
        'snmp-server community public RO',
        'Authorization: Bearer abc.def.ghi',
        'api_key = live_secret_value'
      ].join('\n')
    );

    expect(masked).toContain('username [masked] secret [masked]');
    expect(masked).toContain('password [masked]');
    expect(masked).toContain('snmp-server community [masked]');
    expect(masked).toContain('Authorization: Bearer [masked]');
    expect(masked).toContain('api_key [masked]');
    expect(masked).not.toContain('$1$abcdef');
    expect(masked).not.toContain('0822455D0A16');
    expect(masked).not.toContain('public RO');
    expect(masked).not.toContain('abc.def.ghi');
    expect(masked).not.toContain('live_secret_value');
  });

  test('does not mask invalid IPv4 octets or credential keyword false positives', () => {
    const input =
      'invalid 999.1.1.1\nThe parser uses tokenization before normalization.';

    expect(maskSensitiveText(input)).toBe(input);
  });

  test('preserves existing line endings and indentation', () => {
    const input = '  host 198.51.100.10\r\n\tcontact noc@example.com\r\n';

    expect(maskSensitiveText(input)).toBe(
      '  host [masked-ipv4]\r\n\tcontact [masked-email]\r\n'
    );
  });
});

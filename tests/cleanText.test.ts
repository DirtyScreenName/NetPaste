import { describe, expect, test } from 'vitest';
import { cleanText } from '../src/core/cleanText';

describe('cleanText', () => {
  test('removes ANSI terminal sequences', () => {
    expect(cleanText('\x1b[31mERROR\x1b[0m')).toBe('ERROR');
  });

  test('removes common pagination markers', () => {
    const input = [
      'line one',
      '--More--',
      'line two',
      '---- More ----',
      'line three',
      '<--- More --->',
      'line four'
    ].join('\n');

    expect(cleanText(input)).toBe('line one\nline two\nline three\nline four');
  });

  test('handles backspace artifacts', () => {
    expect(cleanText('abc\b\bde')).toBe('ade');
  });

  test('normalizes CRLF and CR line endings', () => {
    expect(cleanText('one\r\ntwo\rthree')).toBe('one\ntwo\nthree');
  });

  test('preserves indentation while removing trailing whitespace', () => {
    const input = '  interface GigabitEthernet1/0/1  \n description uplink   ';

    expect(cleanText(input)).toBe(
      '  interface GigabitEthernet1/0/1\n description uplink'
    );
  });

  test('collapses runs of more than two blank lines and trims outer blanks', () => {
    expect(cleanText('\n\none\n\n\n\n\n two\n\n')).toBe('one\n\n two');
  });

  test('returns empty string for empty input', () => {
    expect(cleanText('')).toBe('');
  });

  test('handles large multiline terminal output', () => {
    const input = Array.from({ length: 1000 }, (_, index) => `line ${index}   `)
      .join('\r\n')
      .concat('\r\n--More--\r\nlast line');

    const output = cleanText(input);

    expect(output).toContain('line 999');
    expect(output).toContain('last line');
    expect(output).not.toContain('--More--');
    expect(output.split('\n')).toHaveLength(1001);
  });

  test('cleans a sanitized Cisco-style example conservatively', () => {
    const input = [
      'Router01#show run',
      '\x1b[32mBuilding configuration...\x1b[0m',
      '',
      'interface GigabitEthernet0/1   ',
      ' description Example uplink   ',
      '--More--',
      ' ip address 192.0.2.1 255.255.255.0'
    ].join('\r\n');

    expect(cleanText(input)).toBe(
      [
        'Router01#show run',
        'Building configuration...',
        '',
        'interface GigabitEthernet0/1',
        ' description Example uplink',
        ' ip address 192.0.2.1 255.255.255.0'
      ].join('\n')
    );
  });

  test('cleans a generic terminal-output example', () => {
    const input = 'user@host:~$ printf test\x00\r\nresult\t   \r\n';

    expect(cleanText(input)).toBe('user@host:~$ printf test\nresult');
  });
});

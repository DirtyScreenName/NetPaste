import { describe, expect, test } from 'vitest';
import { toMarkdownCodeBlock } from '../src/core/markdown';

describe('toMarkdownCodeBlock', () => {
  test('wraps text in a fenced code block with text as default language', () => {
    expect(toMarkdownCodeBlock('show version')).toBe(
      '```text\nshow version\n```'
    );
  });

  test('uses a safe fence length when content contains embedded backticks', () => {
    const output = toMarkdownCodeBlock('line with ``` embedded fence');

    expect(output.startsWith('````text\n')).toBe(true);
    expect(output.endsWith('\n````')).toBe(true);
    expect(output).toContain('line with ``` embedded fence');
  });

  test('preserves existing trailing newline before the closing fence', () => {
    expect(toMarkdownCodeBlock('line\n')).toBe('```text\nline\n```');
  });
});

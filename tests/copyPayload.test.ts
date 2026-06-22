import { describe, expect, test } from 'vitest';
import {
  getMarkdownCopyPayload,
  getPlainTextCopyPayload
} from '../src/ui/app';

describe('copy payloads', () => {
  test('plain text copy uses the current edited cleaned output', () => {
    const editedOutput =
      'username admin password 7 <REDACTED:CREDENTIAL>\n! operator note';

    expect(getPlainTextCopyPayload(editedOutput)).toBe(editedOutput);
  });

  test('Markdown copy uses the current edited cleaned output', () => {
    const editedOutput = 'snmp-server community <REDACTED:COMMUNITY> RO';

    expect(getMarkdownCopyPayload(editedOutput)).toBe(
      '```text\nsnmp-server community <REDACTED:COMMUNITY> RO\n```'
    );
  });
});

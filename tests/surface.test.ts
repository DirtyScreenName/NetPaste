import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, test } from 'vitest';
import { createSessionPolicy } from '../src/core/policy/builtins';
import { compilePolicy } from '../src/core/policy/compile';
import { policyHasBlockingRules } from '../src/ui/app';
import { resolveAppSurface } from '../src/ui/surface';

describe('app surfaces', () => {
  test('web and extension entries use the shared app bootstrap', () => {
    const webEntry = readFileSync(join(process.cwd(), 'src', 'main.ts'), 'utf8');
    const extensionEntry = readFileSync(
      join(process.cwd(), 'src', 'extension', 'sidepanel.ts'),
      'utf8'
    );

    expect(webEntry).toContain('initNetPasteApp');
    expect(webEntry).toContain("surface: 'web'");
    expect(extensionEntry).toContain('initNetPasteApp');
    expect(extensionEntry).toContain("surface: 'extension-side-panel'");
  });

  test('extension surface has a compact side-panel class and local status copy', () => {
    expect(resolveAppSurface({ surface: 'extension-side-panel' })).toEqual({
      surface: 'extension-side-panel',
      rootClassName: 'extension-surface',
      initialStatus: 'Paste text, clean it locally, review findings, then copy.'
    });
  });
});

describe('edited-output send guard', () => {
  test('suspends send actions only when the active session policy can block', () => {
    const blocking = compilePolicy(
      createSessionPolicy([
        {
          id: 'session-rule-block',
          category: 'Credential or secret',
          description: 'Block protected values.',
          matcher: {
            kind: 'dictionary',
            values: ['TEST-ONLY-SECRET'],
            caseSensitive: true
          },
          action: 'block',
          severity: 'High review priority',
          priority: 100
        }
      ])
    );
    const reviewing = compilePolicy(
      createSessionPolicy([
        {
          id: 'session-rule-review',
          category: 'Site or customer label',
          description: 'Review protected values.',
          matcher: {
            kind: 'dictionary',
            values: ['SITE-ALPHA'],
            caseSensitive: true
          },
          action: 'review',
          severity: 'Review',
          priority: 100
        }
      ])
    );

    expect(policyHasBlockingRules(blocking)).toBe(true);
    expect(policyHasBlockingRules(reviewing)).toBe(false);
    expect(policyHasBlockingRules()).toBe(false);
  });
});

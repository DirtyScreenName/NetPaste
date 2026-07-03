import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, test } from 'vitest';
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

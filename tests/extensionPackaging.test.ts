import {
  existsSync,
  readdirSync,
  readFileSync,
  statSync
} from 'node:fs';
import { join } from 'node:path';
import { describe, expect, test } from 'vitest';

const rootDir = process.cwd();
const manifestPath = join(rootDir, 'extension', 'public', 'manifest.json');
const manifest = JSON.parse(readFileSync(manifestPath, 'utf8')) as {
  manifest_version: number;
  name: string;
  version: string;
  minimum_chrome_version: string;
  permissions?: string[];
  host_permissions?: string[];
  optional_host_permissions?: string[];
  content_scripts?: unknown[];
  side_panel?: { default_path?: string };
  background?: { service_worker?: string; type?: string };
  content_security_policy?: { extension_pages?: string };
};
const packageJson = JSON.parse(
  readFileSync(join(rootDir, 'package.json'), 'utf8')
) as {
  version: string;
  scripts: Record<string, string>;
};

describe('Chromium extension packaging', () => {
  test('manifest is a minimal MV3 side-panel extension', () => {
    expect(manifest.manifest_version).toBe(3);
    expect(manifest.name).toBe('NetPaste');
    expect(manifest.version).toBe(packageJson.version);
    expect(manifest.minimum_chrome_version).toBe('114');
    expect(manifest.permissions).toEqual(['sidePanel']);
    expect(manifest.side_panel?.default_path).toBe('sidepanel.html');
    expect(manifest.background).toEqual({
      service_worker: 'service-worker.js',
      type: 'module'
    });
  });

  test('manifest does not request page access or persistence capabilities', () => {
    expect(manifest.host_permissions).toBeUndefined();
    expect(manifest.optional_host_permissions).toBeUndefined();
    expect(manifest.content_scripts).toBeUndefined();
    expect(manifest.permissions ?? []).not.toContain('storage');
    expect(manifest.permissions ?? []).not.toContain('tabs');
    expect(manifest.permissions ?? []).not.toContain('activeTab');
    expect(manifest.permissions ?? []).not.toContain('scripting');
  });

  test('extension CSP disallows external connections and remote code', () => {
    const csp = manifest.content_security_policy?.extension_pages ?? '';

    expect(csp).toContain("script-src 'self'");
    expect(csp).toContain("connect-src 'none'");
    expect(csp).not.toMatch(/https?:/);
    expect(csp).not.toContain("'unsafe-inline'");
    expect(csp).not.toContain("'unsafe-eval'");
  });

  test('extension build scripts are present', () => {
    expect(packageJson.scripts['build:extension']).toContain(
      'vite build --config vite.extension.config.ts'
    );
    expect(packageJson.scripts['package:extension']).toContain(
      'scripts/package-extension.mjs'
    );
  });

  test('extension build disables generated module preload fetching', () => {
    const extensionConfig = readFileSync(
      join(rootDir, 'vite.extension.config.ts'),
      'utf8'
    );

    expect(extensionConfig).toContain('modulePreload: false');
  });

  test('extension package script validates package contents and manifest shape', () => {
    const packageScript = readFileSync(
      join(rootDir, 'scripts', 'package-extension.mjs'),
      'utf8'
    );

    expect(packageScript).toContain('validatePackageFiles');
    expect(packageScript).toContain('unexpected files');
    expect(packageScript).toContain('validateManifest');
    expect(packageScript).toContain("permissions[0] !== 'sidePanel'");
  });

  test('extension implementation avoids prohibited network and storage APIs', () => {
    const sources = collectSourceFiles([
      join(rootDir, 'src'),
      join(rootDir, 'scripts'),
      join(rootDir, 'sidepanel.html'),
      manifestPath,
      join(rootDir, 'vite.extension.config.ts')
    ]);
    const combined = sources
      .map((filePath) => readFileSync(filePath, 'utf8'))
      .join('\n');

    expect(combined).not.toMatch(/\bfetch\s*\(/);
    expect(combined).not.toMatch(/\bXMLHttpRequest\b/);
    expect(combined).not.toMatch(/\bsendBeacon\b/);
    expect(combined).not.toMatch(/\blocalStorage\b/);
    expect(combined).not.toMatch(/\bsessionStorage\b/);
    expect(combined).not.toMatch(/\bdocument\.cookie\b/);
    expect(combined).not.toMatch(/\bindexedDB\b/);
    expect(combined).not.toMatch(/\bcaches\./);
    expect(combined).not.toMatch(/\bchrome\.storage\b/);
    expect(combined).not.toMatch(/\bbrowser\.storage\b/);
    expect(combined).not.toMatch(/\bWebSocket\b/);
    expect(combined).not.toMatch(/\bwss:\/\//);
    expect(combined).not.toMatch(/\bEventSource\b/);
    expect(combined).not.toMatch(/\bBroadcastChannel\b/);
    expect(combined).not.toMatch(/\binnerHTML\b/);
    expect(combined).not.toMatch(/\bouterHTML\b/);
    expect(combined).not.toMatch(/\binsertAdjacentHTML\b/);
    expect(combined).not.toMatch(/\beval\s*\(/);
    expect(combined).not.toMatch(/\bnew Function\b/);
    expect(combined).not.toMatch(/https?:\/\//);
  });
});

function collectSourceFiles(paths: string[]): string[] {
  return paths.flatMap((filePath) => {
    if (!existsSync(filePath)) {
      return [];
    }

    const stat = statSync(filePath);

    if (stat.isFile()) {
      return [filePath];
    }

    return readdirSync(filePath, { withFileTypes: true }).flatMap((entry) => {
      const childPath = join(filePath, entry.name);

      if (entry.isDirectory()) {
        return collectSourceFiles([childPath]);
      }

      return /\.(css|html|json|ts)$/.test(entry.name) ? [childPath] : [];
    });
  });
}

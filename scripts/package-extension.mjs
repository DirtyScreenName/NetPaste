import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  statSync,
  writeFileSync
} from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const rootDir = dirname(dirname(fileURLToPath(import.meta.url)));
const packageJson = JSON.parse(
  readFileSync(join(rootDir, 'package.json'), 'utf8')
);
const sourceDir = join(rootDir, 'dist-extension');
const releaseDir = join(rootDir, 'release');
const zipPath = join(
  releaseDir,
  `netpaste-chromium-${packageJson.version}.zip`
);
const requiredPackageFiles = [
  'manifest.json',
  'sidepanel.html',
  'service-worker.js',
  'icons/icon16.png',
  'icons/icon32.png',
  'icons/icon48.png',
  'icons/icon128.png'
];
const allowedPackageFilePatterns = [
  /^manifest\.json$/,
  /^sidepanel\.html$/,
  /^service-worker\.js$/,
  /^icons\/icon(?:16|32|48|128)\.png$/,
  /^assets\/[A-Za-z0-9._-]+\.(?:css|js)$/
];

if (!existsSync(sourceDir)) {
  throw new Error('dist-extension does not exist. Run npm run build:extension first.');
}

mkdirSync(releaseDir, { recursive: true });
const packageFiles = collectFiles(sourceDir);
validatePackageFiles(packageFiles.map((file) => file.zipPath));
validateManifest(join(sourceDir, 'manifest.json'));
writeFileSync(zipPath, createZip(packageFiles));
console.log(`Created ${zipPath}`);

function collectFiles(baseDir, currentDir = baseDir) {
  const entries = readdirSync(currentDir, { withFileTypes: true });
  const files = [];

  for (const entry of entries) {
    const fullPath = join(currentDir, entry.name);

    if (entry.isDirectory()) {
      files.push(...collectFiles(baseDir, fullPath));
      continue;
    }

    if (entry.isFile()) {
      files.push({
        fullPath,
        zipPath: relative(baseDir, fullPath).replaceAll('\\', '/')
      });
    }
  }

  return files.sort((a, b) => a.zipPath.localeCompare(b.zipPath));
}

function validatePackageFiles(packageFilePaths) {
  const missingFiles = requiredPackageFiles.filter(
    (requiredFile) => !packageFilePaths.includes(requiredFile)
  );
  const unexpectedFiles = packageFilePaths.filter(
    (packageFilePath) =>
      !allowedPackageFilePatterns.some((pattern) => pattern.test(packageFilePath))
  );

  if (missingFiles.length > 0) {
    throw new Error(`Extension package is missing: ${missingFiles.join(', ')}`);
  }

  if (unexpectedFiles.length > 0) {
    throw new Error(
      `Extension package contains unexpected files: ${unexpectedFiles.join(', ')}`
    );
  }
}

function validateManifest(manifestPath) {
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  const permissions = manifest.permissions ?? [];

  if (manifest.manifest_version !== 3) {
    throw new Error('Extension manifest must use Manifest V3.');
  }

  if (
    permissions.length !== 1 ||
    permissions[0] !== 'sidePanel' ||
    manifest.host_permissions ||
    manifest.optional_host_permissions ||
    manifest.content_scripts ||
    permissions.includes('storage') ||
    permissions.includes('tabs') ||
    permissions.includes('activeTab') ||
    permissions.includes('scripting')
  ) {
    throw new Error('Extension manifest requests unapproved permissions.');
  }

  if (manifest.side_panel?.default_path !== 'sidepanel.html') {
    throw new Error('Extension side panel path must be sidepanel.html.');
  }

  const csp = manifest.content_security_policy?.extension_pages ?? '';

  if (
    !csp.includes("script-src 'self'") ||
    !csp.includes("connect-src 'none'") ||
    /https?:/.test(csp) ||
    csp.includes("'unsafe-inline'") ||
    csp.includes("'unsafe-eval'")
  ) {
    throw new Error('Extension CSP must block remote code and network connections.');
  }
}

function createZip(files) {
  const localParts = [];
  const centralParts = [];
  let offset = 0;

  for (const file of files) {
    const data = readFileSync(file.fullPath);
    const name = Buffer.from(file.zipPath, 'utf8');
    const crc = crc32(data);
    const { dosDate, dosTime } = getDosTimestamp(file.fullPath);

    const localHeader = Buffer.alloc(30);
    localHeader.writeUInt32LE(0x04034b50, 0);
    localHeader.writeUInt16LE(20, 4);
    localHeader.writeUInt16LE(0x0800, 6);
    localHeader.writeUInt16LE(0, 8);
    localHeader.writeUInt16LE(dosTime, 10);
    localHeader.writeUInt16LE(dosDate, 12);
    localHeader.writeUInt32LE(crc, 14);
    localHeader.writeUInt32LE(data.length, 18);
    localHeader.writeUInt32LE(data.length, 22);
    localHeader.writeUInt16LE(name.length, 26);
    localHeader.writeUInt16LE(0, 28);

    localParts.push(localHeader, name, data);

    const centralHeader = Buffer.alloc(46);
    centralHeader.writeUInt32LE(0x02014b50, 0);
    centralHeader.writeUInt16LE(20, 4);
    centralHeader.writeUInt16LE(20, 6);
    centralHeader.writeUInt16LE(0x0800, 8);
    centralHeader.writeUInt16LE(0, 10);
    centralHeader.writeUInt16LE(dosTime, 12);
    centralHeader.writeUInt16LE(dosDate, 14);
    centralHeader.writeUInt32LE(crc, 16);
    centralHeader.writeUInt32LE(data.length, 20);
    centralHeader.writeUInt32LE(data.length, 24);
    centralHeader.writeUInt16LE(name.length, 28);
    centralHeader.writeUInt16LE(0, 30);
    centralHeader.writeUInt16LE(0, 32);
    centralHeader.writeUInt16LE(0, 34);
    centralHeader.writeUInt16LE(0, 36);
    centralHeader.writeUInt32LE(0, 38);
    centralHeader.writeUInt32LE(offset, 42);
    centralParts.push(centralHeader, name);

    offset += localHeader.length + name.length + data.length;
  }

  const centralDirectory = Buffer.concat(centralParts);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(0, 4);
  end.writeUInt16LE(0, 6);
  end.writeUInt16LE(files.length, 8);
  end.writeUInt16LE(files.length, 10);
  end.writeUInt32LE(centralDirectory.length, 12);
  end.writeUInt32LE(offset, 16);
  end.writeUInt16LE(0, 20);

  return Buffer.concat([...localParts, centralDirectory, end]);
}

function getDosTimestamp(filePath) {
  const date = statSync(filePath).mtime;
  const year = Math.max(1980, date.getFullYear());

  return {
    dosTime:
      (date.getHours() << 11) |
      (date.getMinutes() << 5) |
      Math.floor(date.getSeconds() / 2),
    dosDate:
      ((year - 1980) << 9) | ((date.getMonth() + 1) << 5) | date.getDate()
  };
}

function crc32(buffer) {
  let crc = 0xffffffff;

  for (const byte of buffer) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) {
      crc = crc & 1 ? (crc >>> 1) ^ 0xedb88320 : crc >>> 1;
    }
  }

  return (crc ^ 0xffffffff) >>> 0;
}

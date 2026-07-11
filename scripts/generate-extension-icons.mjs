import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const rootDir = dirname(dirname(fileURLToPath(import.meta.url)));
const outputDir = join(rootDir, 'extension', 'public', 'icons');
const pngSignature = Buffer.from([
  0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a
]);

for (const size of [16, 32, 48, 128]) {
  const iconPath = join(outputDir, `icon${size}.png`);
  const icon = readFileSync(iconPath);

  if (!icon.subarray(0, 8).equals(pngSignature)) {
    throw new Error(`${iconPath} is not a PNG file.`);
  }

  const width = icon.readUInt32BE(16);
  const height = icon.readUInt32BE(20);

  if (width !== size || height !== size) {
    throw new Error(
      `${iconPath} must be ${size}x${size}; received ${width}x${height}.`
    );
  }
}

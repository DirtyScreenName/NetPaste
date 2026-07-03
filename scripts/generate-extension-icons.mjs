import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { deflateSync } from 'node:zlib';

const rootDir = dirname(dirname(fileURLToPath(import.meta.url)));
const outputDir = join(rootDir, 'extension', 'public', 'icons');
const sizes = [16, 32, 48, 128];

mkdirSync(outputDir, { recursive: true });

for (const size of sizes) {
  writeFileSync(join(outputDir, `icon${size}.png`), createIcon(size));
}

function createIcon(size) {
  const pixels = Buffer.alloc((size * 4 + 1) * size);
  const margin = Math.max(1, Math.round(size * 0.08));
  const nodeRadius = Math.max(1.5, size * 0.085);
  const nodes = [
    [size * 0.28, size * 0.35],
    [size * 0.72, size * 0.28],
    [size * 0.66, size * 0.72],
    [size * 0.28, size * 0.68]
  ];

  for (let y = 0; y < size; y += 1) {
    const rowStart = y * (size * 4 + 1);
    pixels[rowStart] = 0;

    for (let x = 0; x < size; x += 1) {
      const offset = rowStart + 1 + x * 4;
      const inside =
        x >= margin && x < size - margin && y >= margin && y < size - margin;
      const gradient = y / Math.max(1, size - 1);
      let color = inside
        ? blend([16, 31, 45], [9, 18, 27], gradient)
        : [4, 9, 14];

      if (isNearSegment(x, y, nodes[0], nodes[1], size * 0.035)) {
        color = [79, 209, 197];
      }
      if (isNearSegment(x, y, nodes[1], nodes[2], size * 0.035)) {
        color = [96, 165, 250];
      }
      if (isNearSegment(x, y, nodes[2], nodes[3], size * 0.035)) {
        color = [251, 191, 36];
      }

      for (const node of nodes) {
        if (distance(x, y, node[0], node[1]) <= nodeRadius) {
          color = [243, 244, 246];
        }
      }

      if (inside && isBorder(x, y, size, margin)) {
        color = [79, 209, 197];
      }

      pixels[offset] = color[0];
      pixels[offset + 1] = color[1];
      pixels[offset + 2] = color[2];
      pixels[offset + 3] = 255;
    }
  }

  const pngSignature = Buffer.from([
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a
  ]);
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8;
  ihdr[9] = 6;
  ihdr[10] = 0;
  ihdr[11] = 0;
  ihdr[12] = 0;

  return Buffer.concat([
    pngSignature,
    createChunk('IHDR', ihdr),
    createChunk('IDAT', deflateSync(pixels)),
    createChunk('IEND', Buffer.alloc(0))
  ]);
}

function createChunk(type, data) {
  const typeBuffer = Buffer.from(type, 'ascii');
  const length = Buffer.alloc(4);
  length.writeUInt32BE(data.length, 0);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(Buffer.concat([typeBuffer, data])), 0);
  return Buffer.concat([length, typeBuffer, data, crc]);
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

function blend(a, b, amount) {
  return a.map((channel, index) =>
    Math.round(channel + (b[index] - channel) * amount)
  );
}

function isBorder(x, y, size, margin) {
  return (
    x === margin ||
    x === size - margin - 1 ||
    y === margin ||
    y === size - margin - 1
  );
}

function distance(x1, y1, x2, y2) {
  return Math.hypot(x1 - x2, y1 - y2);
}

function isNearSegment(px, py, start, end, tolerance) {
  const [x1, y1] = start;
  const [x2, y2] = end;
  const dx = x2 - x1;
  const dy = y2 - y1;
  const lengthSquared = dx * dx + dy * dy;

  if (lengthSquared === 0) {
    return distance(px, py, x1, y1) <= tolerance;
  }

  const t = Math.max(
    0,
    Math.min(1, ((px - x1) * dx + (py - y1) * dy) / lengthSquared)
  );

  return distance(px, py, x1 + t * dx, y1 + t * dy) <= tolerance;
}

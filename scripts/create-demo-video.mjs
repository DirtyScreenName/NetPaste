import { existsSync, mkdirSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { dirname, resolve } from 'node:path';

const ffmpeg = process.env.FFMPEG_PATH ?? 'ffmpeg';
const output = resolve('public/media/netpaste-demo-0.3.1.mp4');
const slides = [
  { path: 'release/chrome-store/netpaste-marquee-promo-1400x560.png', duration: 4, promo: true },
  { path: 'release/chrome-store/netpaste-screenshot-01-overview-1280x800.png', duration: 6 },
  { path: 'release/chrome-store/netpaste-screenshot-02-findings-1280x800.png', duration: 6 },
  { path: 'release/chrome-store/netpaste-screenshot-03-profiles-tokens-1280x800.png', duration: 6 },
  { path: 'release/chrome-store/netpaste-screenshot-04-prepare-ai-1280x800.png', duration: 6 },
  { path: 'release/chrome-store/netpaste-screenshot-05-compare-mode-1280x800.png', duration: 6 },
  { path: 'release/chrome-store/netpaste-marquee-promo-1400x560.png', duration: 4, promo: true },
];

for (const slide of slides) {
  if (!existsSync(slide.path)) throw new Error(`Missing demo asset: ${slide.path}`);
}

mkdirSync(dirname(output), { recursive: true });

const inputs = slides.flatMap((slide) => [
  '-loop', '1',
  '-framerate', '30',
  '-t', String(slide.duration),
  '-i', resolve(slide.path),
]);

const filters = slides.map((slide, index) => {
  const layout = slide.promo
    ? 'scale=1280:512:force_original_aspect_ratio=decrease,pad=1280:720:0:104:color=#05080d'
    : 'scale=1280:800:force_original_aspect_ratio=decrease,crop=1280:720:0:40';
  return `[${index}:v]${layout},trim=duration=${slide.duration},setpts=PTS-STARTPTS,` +
    `fade=t=in:st=0:d=0.45,fade=t=out:st=${slide.duration - 0.45}:d=0.45,` +
    `format=yuv420p,setsar=1[v${index}]`;
});

const concatInputs = slides.map((_, index) => `[v${index}]`).join('');
filters.push(`${concatInputs}concat=n=${slides.length}:v=1:a=0[outv]`);

const result = spawnSync(ffmpeg, [
  '-y',
  ...inputs,
  '-filter_complex', filters.join(';'),
  '-map', '[outv]',
  '-c:v', 'libx264',
  '-preset', 'medium',
  '-crf', '20',
  '-r', '30',
  '-movflags', '+faststart',
  '-an',
  output,
], { stdio: 'inherit' });

if (result.error) throw result.error;
if (result.status !== 0) process.exit(result.status ?? 1);

console.log(`Created ${output}`);

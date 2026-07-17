import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { dirname, resolve } from 'node:path';

const ffmpeg = process.env.FFMPEG_PATH ?? 'ffmpeg';
const outputs = {
  cisco: 'public/media/netpaste-cisco-redaction-walkthrough.mp4',
  cli: 'public/media/netpaste-cli-cleanup-walkthrough.mp4',
  ai: 'public/media/netpaste-prepare-ai-walkthrough.mp4',
};

const captureArgs = Object.fromEntries(
  process.argv.slice(2).map((argument) => {
    const separator = argument.indexOf('=');
    if (separator < 1) throw new Error(`Expected workflow=capture-directory, received: ${argument}`);
    return [argument.slice(0, separator), argument.slice(separator + 1)];
  }),
);

for (const [workflow, outputPath] of Object.entries(outputs)) {
  const captureDirectory = captureArgs[workflow];
  if (!captureDirectory) {
    throw new Error(`Missing ${workflow}=capture-directory argument.`);
  }

  const manifestPath = resolve(captureDirectory, 'frames.json');
  if (!existsSync(manifestPath)) throw new Error(`Missing capture manifest: ${manifestPath}`);

  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  if (!Array.isArray(manifest.frames) || manifest.frames.length < 2) {
    throw new Error(`Capture must contain at least two frames: ${manifestPath}`);
  }

  const lines = ['ffconcat version 1.0'];
  for (let index = 0; index < manifest.frames.length; index += 1) {
    const frame = manifest.frames[index];
    const nextFrame = manifest.frames[index + 1];
    const framePath = resolve(frame.file);
    if (!existsSync(framePath)) throw new Error(`Missing capture frame: ${framePath}`);

    const duration = nextFrame
      ? Math.max(0.04, nextFrame.timestamp - frame.timestamp)
      : Math.max(1.5, manifest.ended / 1000 - frame.timestamp);
    lines.push(`file '${framePath.replaceAll("'", "'\\''")}'`);
    lines.push(`duration ${duration.toFixed(6)}`);
  }

  // The concat demuxer requires the final frame twice to honor its duration.
  const finalFrame = resolve(manifest.frames.at(-1).file);
  lines.push(`file '${finalFrame.replaceAll("'", "'\\''")}'`);

  const concatPath = resolve(captureDirectory, `${workflow}.ffconcat`);
  writeFileSync(concatPath, `${lines.join('\n')}\n`, 'utf8');

  const output = resolve(outputPath);
  mkdirSync(dirname(output), { recursive: true });
  const result = spawnSync(ffmpeg, [
    '-y',
    '-f', 'concat',
    '-safe', '0',
    '-i', concatPath,
    '-vf', 'fps=30,format=yuv420p',
    '-c:v', 'libx264',
    '-preset', 'medium',
    '-crf', '20',
    '-movflags', '+faststart',
    '-an',
    output,
  ], { stdio: 'inherit' });

  rmSync(concatPath, { force: true });
  if (result.error) throw result.error;
  if (result.status !== 0) process.exit(result.status ?? 1);
  console.log(`Created ${output}`);
}

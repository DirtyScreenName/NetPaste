export function buildUnifiedDiff(
  beforeText: string,
  afterText: string,
  beforeLabel = 'before',
  afterLabel = 'after'
): string {
  const beforeLines = beforeText.split('\n');
  const afterLines = afterText.split('\n');
  const output = [`--- ${beforeLabel}`, `+++ ${afterLabel}`, '@@'];
  const maxLineCount = Math.max(beforeLines.length, afterLines.length);

  for (let index = 0; index < maxLineCount; index += 1) {
    const beforeLine = beforeLines[index];
    const afterLine = afterLines[index];

    if (beforeLine === afterLine) {
      output.push(` ${beforeLine ?? ''}`);
      continue;
    }

    if (beforeLine !== undefined) {
      output.push(`-${beforeLine}`);
    }

    if (afterLine !== undefined) {
      output.push(`+${afterLine}`);
    }
  }

  return output.join('\n');
}

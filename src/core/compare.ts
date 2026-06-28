export function buildUnifiedDiff(
  beforeText: string,
  afterText: string,
  beforeLabel = 'before',
  afterLabel = 'after'
): string {
  const beforeLines = beforeText.split('\n');
  const afterLines = afterText.split('\n');
  const rows = buildLcsRows(beforeLines, afterLines);
  const output = [`--- ${beforeLabel}`, `+++ ${afterLabel}`, '@@'];

  for (const row of rows) {
    if (row.type === 'same') {
      output.push(` ${row.value}`);
    } else if (row.type === 'remove') {
      output.push(`-${row.value}`);
    } else {
      output.push(`+${row.value}`);
    }
  }

  return output.join('\n');
}

type DiffRow =
  | { type: 'same'; value: string }
  | { type: 'remove'; value: string }
  | { type: 'add'; value: string };

function buildLcsRows(beforeLines: string[], afterLines: string[]): DiffRow[] {
  const table = Array.from({ length: beforeLines.length + 1 }, () =>
    Array<number>(afterLines.length + 1).fill(0)
  );

  for (let left = beforeLines.length - 1; left >= 0; left -= 1) {
    for (let right = afterLines.length - 1; right >= 0; right -= 1) {
      table[left][right] =
        beforeLines[left] === afterLines[right]
          ? table[left + 1][right + 1] + 1
          : Math.max(table[left + 1][right], table[left][right + 1]);
    }
  }

  const rows: DiffRow[] = [];
  let left = 0;
  let right = 0;

  while (left < beforeLines.length && right < afterLines.length) {
    if (beforeLines[left] === afterLines[right]) {
      rows.push({ type: 'same', value: beforeLines[left] });
      left += 1;
      right += 1;
    } else if (table[left + 1][right] >= table[left][right + 1]) {
      rows.push({ type: 'remove', value: beforeLines[left] });
      left += 1;
    } else {
      rows.push({ type: 'add', value: afterLines[right] });
      right += 1;
    }
  }

  while (left < beforeLines.length) {
    rows.push({ type: 'remove', value: beforeLines[left] });
    left += 1;
  }

  while (right < afterLines.length) {
    rows.push({ type: 'add', value: afterLines[right] });
    right += 1;
  }

  return rows;
}

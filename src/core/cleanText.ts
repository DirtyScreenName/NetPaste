const ANSI_ESCAPE_PATTERN =
  /(?:\x1B\][^\x07]*(?:\x07|\x1B\\))|(?:\x1B\[[0-?]*[ -/]*[@-~])|(?:\x1B[@-Z\\-_])/g;

const CONTROL_ARTIFACT_PATTERN = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g;

const PAGINATION_PATTERNS = [
  /<---\s*More\s*--->/gi,
  /-{3,}\s*More\s*-{3,}/gi,
  /--\s*More\s*--/gi
];

export function normalizeLineEndings(input: string): string {
  return input.replace(/\r\n?/g, '\n');
}

export function removeAnsiSequences(input: string): string {
  return input.replace(ANSI_ESCAPE_PATTERN, '');
}

export function applyBackspaces(input: string): string {
  const output: string[] = [];

  for (const char of input) {
    if (char === '\b') {
      const previous = output[output.length - 1];
      if (previous !== undefined && previous !== '\n') {
        output.pop();
      }
      continue;
    }

    output.push(char);
  }

  return output.join('');
}

function removePaginationMarkers(input: string): string {
  const lines = input.split('\n');
  const cleanedLines: string[] = [];

  for (const line of lines) {
    let cleanedLine = line;
    let hadPaginationMarker = false;

    for (const pattern of PAGINATION_PATTERNS) {
      pattern.lastIndex = 0;
      if (pattern.test(cleanedLine)) {
        hadPaginationMarker = true;
      }
      pattern.lastIndex = 0;
      cleanedLine = cleanedLine.replace(pattern, '');
    }

    if (hadPaginationMarker && cleanedLine.trim() === '') {
      continue;
    }

    cleanedLines.push(cleanedLine);
  }

  return cleanedLines.join('\n');
}

export function cleanText(input: string): string {
  if (input.length === 0) {
    return '';
  }

  let output = normalizeLineEndings(input);
  output = removeAnsiSequences(output);
  output = applyBackspaces(output);
  output = output.replace(CONTROL_ARTIFACT_PATTERN, '');
  output = removePaginationMarkers(output);
  output = output
    .split('\n')
    .map((line) => line.replace(/[ \t]+$/g, ''))
    .join('\n');
  output = output.replace(/\n{3,}/g, '\n\n');
  output = output.replace(/^\n+|\n+$/g, '');

  return output;
}

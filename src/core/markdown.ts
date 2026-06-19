export function toMarkdownCodeBlock(
  text: string,
  language = 'text'
): string {
  const longestBacktickRun = Math.max(
    0,
    ...Array.from(text.matchAll(/`+/g), (match) => match[0].length)
  );
  const fence = '`'.repeat(Math.max(3, longestBacktickRun + 1));
  const separator = text.endsWith('\n') ? '' : '\n';

  return `${fence}${language}\n${text}${separator}${fence}`;
}

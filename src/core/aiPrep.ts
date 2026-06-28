import type { AnalysisResult } from './types';
import { toMarkdownCodeBlock } from './markdown';

export function prepareForAi(text: string, analysis: AnalysisResult): string {
  const header = [
    'NetPaste prepared this text locally for AI review.',
    'Sensitive-looking values may be replaced with stable labels. Review before use.',
    `Share status: ${analysis.shareScore.status}.`
  ].join('\n');

  return `${header}\n\n${toMarkdownCodeBlock(text, 'text')}`;
}

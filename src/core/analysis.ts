import {
  detectSensitive,
  getRenderedFindings,
  summarizeFindings
} from './detectSensitive';
import type { AnalysisResult } from './types';

export function analyzeCurrentText(
  rawText: string,
  currentCleanedText: string,
  renderedLimit = 200
): AnalysisResult {
  const findings = detectSensitive(rawText, currentCleanedText);
  const renderedFindings = getRenderedFindings(findings, renderedLimit);

  return {
    findings,
    renderedFindings,
    categoryCounts: summarizeFindings(findings),
    hiddenFindingCount: Math.max(0, findings.length - renderedFindings.length)
  };
}

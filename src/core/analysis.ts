import {
  detectSensitive,
  getRenderedFindings,
  summarizeFindings
} from './detectSensitive';
import { getProfileActionForFinding, annotateFindingsForProfile, applyProfileDefaults } from './profiles';
import { scoreShareReadiness } from './shareScore';
import { suggestVendor } from './rulePacks';
import { applyTokenMapToFindings, buildTokenMap } from './tokenMap';
import type { AnalysisOptions, AnalysisResult } from './types';

export function analyzeCurrentText(
  rawText: string,
  currentCleanedText: string,
  renderedLimit = 200,
  options: AnalysisOptions = {}
): AnalysisResult {
  const profileId = options.profileId ?? 'custom-session';
  const documentMode = options.documentMode ?? 'cli-config';
  const vendorSuggestion = suggestVendor(`${rawText}\n${currentCleanedText}`);
  const activeVendor =
    options.vendorId && options.vendorId !== 'auto'
      ? options.vendorId
      : vendorSuggestion.vendor;
  const detectedFindings = detectSensitive(rawText, currentCleanedText, {
    ...options,
    vendorId: activeVendor
  });
  const profiledFindings = annotateFindingsForProfile(
    detectedFindings.map((finding) => ({
      ...finding,
      profileAction: getProfileActionForFinding(finding, profileId)
    })),
    profileId
  );
  const tokenMap = buildTokenMap(profiledFindings, {
    enabled: options.useTokenMapping
  });
  const findings = applyTokenMapToFindings(profiledFindings, tokenMap);
  const renderedFindings = getRenderedFindings(findings, renderedLimit);
  const selectedIds =
    options.selectedIds ?? applyProfileDefaults(findings, profileId);

  return {
    findings,
    renderedFindings,
    categoryCounts: summarizeFindings(findings),
    hiddenFindingCount: Math.max(0, findings.length - renderedFindings.length),
    profileId,
    documentMode,
    vendorSuggestion,
    activeVendor,
    shareScore: scoreShareReadiness(findings, selectedIds, profileId)
  };
}

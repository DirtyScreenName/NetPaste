import type { AnalysisResult, SensitiveFinding } from '../types';
import type { RedactionReceipt } from './types';

export interface ReceiptOptions {
  processedAt?: string;
}

export async function createRedactionReceipt(
  originalText: string,
  sanitizedText: string,
  analysis: AnalysisResult,
  selectedIds: ReadonlySet<string>,
  options: ReceiptOptions = {}
): Promise<RedactionReceipt> {
  const selectedFindings = analysis.findings.filter((finding) => selectedIds.has(finding.id));
  const classifications = summarizeSelectedClassifications(selectedFindings);
  const hasUnhandledBlock = analysis.findings.some(
    (finding) =>
      finding.policyAction === 'block' &&
      finding.redactionRanges.length > 0 &&
      !selectedIds.has(finding.id)
  );

  return {
    policyId: analysis.policyId,
    policyVersion: analysis.policyVersion,
    processedAt: options.processedAt ?? new Date().toISOString(),
    originalSha256: `sha256:${await sha256(originalText)}`,
    sanitizedSha256: `sha256:${await sha256(sanitizedText)}`,
    originalRetained: false,
    redactionCount: selectedFindings.length,
    classifications,
    reviewStatus: hasUnhandledBlock ? 'pending' : 'approved'
  };
}

export function serializeRedactionReceipt(receipt: RedactionReceipt): string {
  return `${JSON.stringify(receipt, null, 2)}\n`;
}

function summarizeSelectedClassifications(
  findings: SensitiveFinding[]
): Readonly<Record<string, number>> {
  const counts: Record<string, number> = {};
  for (const finding of findings) {
    const key = toReceiptCategory(finding.category);
    counts[key] = (counts[key] ?? 0) + 1;
  }
  return Object.fromEntries(Object.entries(counts).sort(([left], [right]) => left.localeCompare(right)));
}

function toReceiptCategory(category: string): string {
  return category
    .toLowerCase()
    .replace(/\bor\b/g, '')
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .replace(/_+/g, '_');
}

async function sha256(value: string): Promise<string> {
  const bytes = new TextEncoder().encode(value);
  const digest = await globalThis.crypto.subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

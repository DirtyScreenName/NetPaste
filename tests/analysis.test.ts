import { describe, expect, test } from 'vitest';
import { analyzeCurrentText } from '../src/core/analysis';

describe('analyzeCurrentText', () => {
  test('uses the current edited cleaned output for detection', () => {
    const analysis = analyzeCurrentText(
      'interface Gi0/1',
      'interface Gi0/1\npassword 0 editedSecret'
    );

    const credential = analysis.findings.find(
      (finding) => finding.category === 'Credential or secret'
    );

    expect(credential).toMatchObject({
      source: 'cleaned',
      cleanedLine: 2,
      severity: 'High review priority'
    });
    expect(credential?.preview).not.toContain('editedSecret');
  });

  test('returns rendered cap metadata separately from full findings', () => {
    const text = Array.from(
      { length: 20 },
      (_, index) => `host ${index} 10.0.0.${index}`
    ).join('\n');
    const analysis = analyzeCurrentText(text, '', 5);

    expect(analysis.renderedFindings).toHaveLength(5);
    expect(analysis.hiddenFindingCount).toBeGreaterThan(0);
    expect(analysis.categoryCounts['Private IP address']).toBeGreaterThan(5);
  });
});

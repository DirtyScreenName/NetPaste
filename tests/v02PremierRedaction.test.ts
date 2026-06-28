import { describe, expect, test } from 'vitest';
import { analyzeCurrentText } from '../src/core/analysis';
import { prepareForAi } from '../src/core/aiPrep';
import { buildUnifiedDiff } from '../src/core/compare';
import { detectSensitive } from '../src/core/detectSensitive';
import { applyProfileDefaults } from '../src/core/profiles';
import { suggestVendor } from '../src/core/rulePacks';
import { scoreShareReadiness } from '../src/core/shareScore';
import {
  applySelectedRedactions,
  reconcileSelectedFindingIds
} from '../src/core/redaction';
import type { DocumentModeId, VendorId } from '../src/core/types';

describe('v0.2 premier redaction workflows', () => {
  test('applies profile defaults and computes safe-share score', () => {
    const text = [
      'hostname Edge-Router-01',
      'ip address 10.10.20.5 255.255.255.0',
      'contact noc@example.com',
      'password 0 localSecret'
    ].join('\n');
    const analysis = analyzeCurrentText('', text, 200, {
      profileId: 'public',
      useTokenMapping: true
    });
    const selectedIds = applyProfileDefaults(analysis.findings, 'public');

    expect(
      analysis.findings.find((finding) => finding.category === 'Hostname')
        ?.profileAction
    ).toBe('redact');
    expect(
      analysis.findings.find((finding) => finding.category === 'Credential or secret')
        ?.profileAction
    ).toBe('redact');
    expect(scoreShareReadiness(analysis.findings, selectedIds, 'public').status).toBe(
      'Ready'
    );
    expect(scoreShareReadiness(analysis.findings, new Set(), 'public').status).toBe(
      'High risk'
    );
  });

  test('vendor rule packs identify common sanitized platform examples', () => {
    const samples: Array<[VendorId, string]> = [
      [
        'cisco',
        'show running-config\ninterface GigabitEthernet1/0/1\nsnmp-server community public RO'
      ],
      ['juniper', 'set system host-name edge01\nset interfaces ge-0/0/0 unit 0'],
      ['arista', 'management api http-commands\ninterface Ethernet1\nip routing'],
      ['palo-alto', 'set deviceconfig system hostname pa-fw\nsecurity-policy allow-web'],
      ['fortinet', 'config system interface\n edit "wan1"\n next\nend'],
      ['ciena', 'saos\nlogical-port create port 1\nflow-point fp-1'],
      ['linux', 'journalctl -u systemd-networkd\nip addr show eth0']
    ];

    for (const [vendor, sample] of samples) {
      expect(suggestVendor(sample).vendor).toBe(vendor);
    }
  });

  test('detects topology categories and assigns non-secret metadata', () => {
    const text = [
      'hostname Branch-01',
      'interface GigabitEthernet1/0/24',
      ' description customer ACME circuit CKT-778899',
      'vrf definition CUSTOMER-A',
      ' switchport access vlan 120',
      'router bgp 65001',
      ' serial number FTX1234ABCD',
      ' project-id pap-prod-001',
      '-----BEGIN PRIVATE KEY-----'
    ].join('\n');
    const findings = detectSensitive('', text, { vendorId: 'cisco' });
    const categories = findings.map((finding) => finding.category);

    expect(categories).toEqual(
      expect.arrayContaining([
        'Hostname',
        'Interface name',
        'Config comment metadata',
        'VRF name',
        'VLAN identifier',
        'BGP ASN',
        'Serial number',
        'Cloud identifier',
        'Certificate or key material'
      ])
    );
    expect(
      findings.every(
        (finding) =>
          finding.reason.length > 0 &&
          finding.ruleId.length > 0 &&
          finding.vendor === 'cisco'
      )
    ).toBe(true);
  });

  test('uses stable token mapping across repeated equivalent findings', () => {
    const text = [
      'hostname Edge01',
      'ip address 10.0.0.1 255.255.255.0',
      'neighbor 10.0.0.1 remote-as 64512',
      'hostname Edge01'
    ].join('\n');
    const analysis = analyzeCurrentText('', text, 200, {
      profileId: 'public',
      useTokenMapping: true
    });
    const selectedIds = applyProfileDefaults(analysis.findings, 'public');
    const output = applySelectedRedactions(text, analysis.findings, selectedIds);

    expect(output.match(/<IP-1>/g)).toHaveLength(2);
    expect(output.match(/<HOST-1>/g)).toHaveLength(2);
    expect(output).not.toContain('10.0.0.1');
    expect(output).not.toContain('Edge01');
  });

  test('keeps raw values out of previews, IDs, reasons, scores, and AI headers', () => {
    const text = [
      'hostname SecretRouter01',
      'ip address 10.12.14.16 255.255.255.0',
      'contact noc@example.com https://example.test/path?token=secret',
      'api_key live_secret_value'
    ].join('\n');
    const analysis = analyzeCurrentText('', text, 200, {
      profileId: 'ai-prompt',
      useTokenMapping: true
    });
    const selectedIds = applyProfileDefaults(analysis.findings, 'ai-prompt');
    const redacted = applySelectedRedactions(text, analysis.findings, selectedIds);
    const payload = prepareForAi(redacted, {
      ...analysis,
      shareScore: scoreShareReadiness(analysis.findings, selectedIds, 'ai-prompt')
    });
    const safeFields = analysis.findings
      .map((finding) => `${finding.id} ${finding.preview} ${finding.reason}`)
      .join('\n');

    for (const raw of [
      'SecretRouter01',
      '10.12.14.16',
      'noc@example.com',
      'https://example.test/path',
      'live_secret_value'
    ]) {
      expect(safeFields).not.toContain(raw);
      expect(payload.split('```text')[0]).not.toContain(raw);
    }

    expect(redacted).toContain('<HOST-1>');
    expect(redacted).toContain('<IP-1>');
    expect(redacted).toContain('<EMAIL-1>');
    expect(redacted).toContain('<URL-1>');
    expect(redacted).toContain('<SECRET-1>');
  });

  test('detects edited cleaned-output changes with profile defaults and token maps', () => {
    const initialFindings = analyzeCurrentText('', 'password 0 firstSecret', 200, {
      profileId: 'ai-prompt',
      useTokenMapping: true
    }).findings;
    const initialSelectedIds = applyProfileDefaults(initialFindings, 'ai-prompt');
    const editedFindings = analyzeCurrentText(
      '',
      'password 0 firstSecret\nhostname NewHost01',
      200,
      {
        profileId: 'ai-prompt',
        useTokenMapping: true
      }
    ).findings;
    const selectedIds = reconcileSelectedFindingIds(
      editedFindings,
      initialSelectedIds,
      new Set(initialFindings.map((finding) => finding.id)),
      'ai-prompt'
    );

    expect(selectedIds.size).toBe(2);
  });

  test('supports pasted document modes without persistence or network dependencies', () => {
    const modes: Array<[DocumentModeId, string]> = [
      ['json', '{"host":"edge01","ip":"10.0.0.1","token":"secret-value"}'],
      ['yaml', 'host: edge01\npassword: secret-value\nip: 10.0.0.2'],
      ['csv-log', 'time,host,ip\n12:00,edge01,10.0.0.3'],
      ['markdown', '## Change\nContact noc@example.com for 10.0.0.4'],
      ['ticket-email', 'Customer ACME reports device Edge01 at 10.0.0.5']
    ];

    for (const [documentMode, sample] of modes) {
      const analysis = analyzeCurrentText(sample, sample, 200, {
        documentMode,
        profileId: 'public'
      });

      expect(analysis.documentMode).toBe(documentMode);
      expect(analysis.findings.length).toBeGreaterThan(0);
    }
  });

  test('builds a redaction-ready before and after diff with shared tokens', () => {
    const beforeText = 'hostname Edge01\nip address 10.0.0.1';
    const afterText = 'hostname Edge01\nip address 10.0.0.2';
    const diff = buildUnifiedDiff(beforeText, afterText);
    const analysis = analyzeCurrentText(`${beforeText}\n${afterText}`, diff, 200, {
      profileId: 'public',
      useTokenMapping: true
    });
    const selectedIds = applyProfileDefaults(analysis.findings, 'public');
    const redactedDiff = applySelectedRedactions(diff, analysis.findings, selectedIds);

    expect(redactedDiff).toContain('--- before');
    expect(redactedDiff).toContain('+++ after');
    expect(redactedDiff).toContain('<HOST-1>');
    expect(redactedDiff).toContain('<IP-1>');
    expect(redactedDiff).toContain('<IP-2>');
    expect(redactedDiff).not.toContain('Edge01');
    expect(redactedDiff).not.toContain('10.0.0.1');
    expect(redactedDiff).not.toContain('10.0.0.2');
  });
});

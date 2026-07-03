import {
  type AnalysisOptions,
  type ConfidenceLevel,
  type FindingSeverity,
  type FindingsSummary,
  type FindingSource,
  type SensitiveCategory,
  type SensitiveFinding,
  type TextRange,
  type VendorId,
  sensitiveCategories
} from './types';
import { normalizeLineEndings, removeAnsiSequences } from './cleanText';
import { maskSensitiveText } from './maskSensitive';
import { suggestVendor } from './rulePacks';

interface RawFinding {
  category: SensitiveCategory;
  severity: FindingSeverity;
  preview: string;
  source: Exclude<FindingSource, 'both'>;
  line: number;
  canonical: string;
  redactionRanges: TextRange[];
  confidence: ConfidenceLevel;
  reason: string;
  ruleId: string;
  vendor: VendorId;
  previewRanges: PreviewRange[];
}

interface MergedFinding extends SensitiveFinding {
  canonical: string;
  order: number;
  previewRanges: PreviewRange[];
}

interface FindingInput {
  category: SensitiveCategory;
  severity?: FindingSeverity;
  line: string;
  source: Exclude<FindingSource, 'both'>;
  lineNumber: number;
  lineStartOffset: number;
  canonical: string;
  lineRanges: TextRange[];
  confidence?: ConfidenceLevel;
  reason: string;
  ruleId: string;
  vendor: VendorId;
}

interface PreviewRange extends TextRange {
  category: SensitiveCategory;
}

interface PreviewReplacement extends TextRange {
  label: string;
}

const MAX_PREVIEW_LENGTH = 160;

const IPV4_CANDIDATE_PATTERN =
  /(^|[^\d.])((?:\d{1,3}\.){3}\d{1,3})(?![\d.])/g;
const MAC_STANDARD_PATTERN =
  /(^|[^0-9A-Fa-f])((?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2})(?![0-9A-Fa-f])/g;
const MAC_CISCO_PATTERN =
  /(^|[^0-9A-Fa-f])([0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4})(?![0-9A-Fa-f])/g;
const EMAIL_PATTERN =
  /(^|[^A-Z0-9._%+-])([A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,})(?![A-Z0-9._%+-])/gi;
const URL_PATTERN = /\bhttps?:\/\/[^\s<>"']+/gi;
const HOSTNAME_PROMPT_PATTERN =
  /^\s*([A-Za-z][A-Za-z0-9._-]{1,63}(?:\([A-Za-z0-9_.:/-]+\))*[>#])(?:\s?.*)?$/;
const AUTHORIZATION_BEARER_VALUE_PATTERN =
  /\b(authorization\s*:\s*bearer)\s+("[^"]+"|'[^']+'|\S+)/gi;
const AUTHORIZATION_VALUE_PATTERN =
  /\b(authorization\s*:)\s*(?!bearer\b)("[^"]+"|'[^']+'|\S+)/gi;
const REDACTION_PLACEHOLDER_PATTERN = /^["']?<REDACTED(?::[^>]+)?>["']?$/i;
const TOKEN_PLACEHOLDER_PATTERN = /^<[-A-Z]+-\d+>$/i;

const CREDENTIAL_PATTERNS = [
  /\benable\s+secret\b/i,
  /\bsnmp-server\s+community\b/i,
  /\bprivate\s+key\b/i,
  /\bpre-shared\s+key\b/i,
  /\bpreshared\s+key\b/i,
  /\bkey-string\b/i,
  /\bcrypto\s+isakmp\s+key\b/i,
  /\bapi[-_ ]?key\b/i,
  /\bauthentication\s+key\b/i,
  /\bpassword\b/i,
  /\bpasswd\b/i,
  /\bsecret\b/i,
  /\busername\b/i,
  /\bcommunity\b/i,
  /\btoken\b/i,
  /\bbearer\b/i,
  /\bauthorization\b/i
];

export function detectSensitive(
  originalText: string,
  cleanedText: string,
  options: AnalysisOptions = {}
): SensitiveFinding[] {
  const suggestion = suggestVendor(`${originalText}\n${cleanedText}`);
  const activeVendor =
    options.vendorId && options.vendorId !== 'auto'
      ? options.vendorId
      : suggestion.vendor;
  const rawFindings = [
    ...detectInText(originalText, 'original', activeVendor),
    ...detectInText(cleanedText, 'cleaned', activeVendor)
  ];
  const merged = mergeEquivalentFindings(rawFindings);

  return merged.map(
    ({
      canonical: _canonical,
      order: _order,
      previewRanges: _previewRanges,
      ...finding
    }) => finding
  );
}

export function summarizeFindings(
  findings: SensitiveFinding[]
): FindingsSummary {
  const summary = Object.fromEntries(
    sensitiveCategories.map((category) => [category, 0])
  ) as FindingsSummary;

  for (const finding of findings) {
    summary[finding.category] += 1;
  }

  return summary;
}

export function getRenderedFindings(
  findings: SensitiveFinding[],
  limit = 200
): SensitiveFinding[] {
  return findings.slice(0, limit);
}

function detectInText(
  text: string,
  source: Exclude<FindingSource, 'both'>,
  vendor: VendorId
): RawFinding[] {
  const normalizedText = normalizeLineEndings(text);
  const lines = normalizedText.split('\n');
  const findings: RawFinding[] = [];
  let lineStartOffset = 0;

  lines.forEach((line, index) => {
    const lineNumber = index + 1;
    const lineFindings: RawFinding[] = [];

    if (line.length === 0) {
      lineStartOffset += 1;
      return;
    }

    collectCertificateKeyFindings(line, source, lineNumber, lineStartOffset, lineFindings, vendor);
    collectCloudIdentifierFindings(line, source, lineNumber, lineStartOffset, lineFindings, vendor);

    if (isCredentialLine(line)) {
      const redactionRanges = collectCredentialValueRanges(line);

      if (redactionRanges.length > 0) {
        lineFindings.push(
          buildRawFinding({
            category: 'Credential or secret',
            severity: 'High review priority',
            line,
            source,
            lineNumber,
            lineStartOffset,
            canonical: `credential:${canonicalizeLine(line)}`,
            lineRanges: redactionRanges,
            confidence: 'High',
            reason: 'Credential-oriented syntax matched a local rule.',
            ruleId: getCredentialRuleId(line),
            vendor
          })
        );
      }
    }

    collectIpv4Findings(line, source, lineNumber, lineStartOffset, lineFindings, vendor);
    collectIpv6Findings(line, source, lineNumber, lineStartOffset, lineFindings, vendor);
    collectMacFindings(line, source, lineNumber, lineStartOffset, lineFindings, vendor);
    collectEmailFindings(line, source, lineNumber, lineStartOffset, lineFindings, vendor);
    collectUrlFindings(line, source, lineNumber, lineStartOffset, lineFindings, vendor);
    collectHostnameFindings(line, source, lineNumber, lineStartOffset, lineFindings, vendor);
    collectHostnamePromptFinding(line, source, lineNumber, lineStartOffset, lineFindings, vendor);
    collectInterfaceFindings(line, source, lineNumber, lineStartOffset, lineFindings, vendor);
    collectVrfFindings(line, source, lineNumber, lineStartOffset, lineFindings, vendor);
    collectVlanFindings(line, source, lineNumber, lineStartOffset, lineFindings, vendor);
    collectAsnFindings(line, source, lineNumber, lineStartOffset, lineFindings, vendor);
    collectSerialFindings(line, source, lineNumber, lineStartOffset, lineFindings, vendor);
    collectCircuitFindings(line, source, lineNumber, lineStartOffset, lineFindings, vendor);
    collectSiteCustomerFindings(line, source, lineNumber, lineStartOffset, lineFindings, vendor);
    collectConfigCommentFindings(line, source, lineNumber, lineStartOffset, lineFindings, vendor);

    maskLineFindingPreviews(line, lineFindings);
    findings.push(...lineFindings);
    lineStartOffset += line.length + 1;
  });

  return findings;
}

function collectIpv4Findings(
  line: string,
  source: Exclude<FindingSource, 'both'>,
  lineNumber: number,
  lineStartOffset: number,
  findings: RawFinding[],
  vendor: VendorId
): void {
  IPV4_CANDIDATE_PATTERN.lastIndex = 0;

  for (const match of line.matchAll(IPV4_CANDIDATE_PATTERN)) {
    const candidate = match[2];
    const start = (match.index ?? 0) + match[1].length;

    if (!isValidIpv4(candidate)) {
      continue;
    }

    const category: SensitiveCategory = isPrivateIpv4(candidate)
      ? 'Private IP address'
      : 'Public IP address';

    findings.push(
      buildRawFinding({
        category,
        line,
        source,
        lineNumber,
        lineStartOffset,
        canonical: candidate,
        lineRanges: [{ start, end: start + candidate.length }],
        confidence: 'High',
        reason: 'Valid IPv4 address pattern matched.',
        ruleId: isPrivateIpv4(candidate) ? 'ip.private-ipv4' : 'ip.public-ipv4',
        vendor
      })
    );
  }
}

function collectIpv6Findings(
  line: string,
  source: Exclude<FindingSource, 'both'>,
  lineNumber: number,
  lineStartOffset: number,
  findings: RawFinding[],
  vendor: VendorId
): void {
  const pattern = /[A-Fa-f0-9:]{2,}(?:%[A-Za-z0-9_.-]+)?/g;

  for (const match of line.matchAll(pattern)) {
    const candidate = match[0];

    if (/^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/.test(candidate)) {
      continue;
    }

    if (!candidate.includes(':') || !isLikelyIpv6(candidate)) {
      continue;
    }

    const category: SensitiveCategory = isPrivateIpv6(candidate)
      ? 'Private IP address'
      : 'Public IP address';

    findings.push(
      buildRawFinding({
        category,
        line,
        source,
        lineNumber,
        lineStartOffset,
        canonical: candidate.toLowerCase(),
        lineRanges: [
          {
            start: match.index ?? 0,
            end: (match.index ?? 0) + candidate.length
          }
        ],
        confidence: 'Medium',
        reason: 'Likely IPv6 address pattern matched.',
        ruleId: isPrivateIpv6(candidate) ? 'ip.private-ipv6' : 'ip.public-ipv6',
        vendor
      })
    );
  }
}

function collectMacFindings(
  line: string,
  source: Exclude<FindingSource, 'both'>,
  lineNumber: number,
  lineStartOffset: number,
  findings: RawFinding[],
  vendor: VendorId
): void {
  collectPatternFindings(
    line,
    source,
    lineNumber,
    lineStartOffset,
    MAC_STANDARD_PATTERN,
    'MAC address',
    (value) => canonicalizeMac(value),
    findings,
    vendor,
    'mac.standard',
    'MAC address pattern matched.'
  );
  collectPatternFindings(
    line,
    source,
    lineNumber,
    lineStartOffset,
    MAC_CISCO_PATTERN,
    'MAC address',
    (value) => canonicalizeMac(value),
    findings,
    vendor,
    'mac.cisco-dotted',
    'Cisco dotted MAC address pattern matched.'
  );
}

function collectEmailFindings(
  line: string,
  source: Exclude<FindingSource, 'both'>,
  lineNumber: number,
  lineStartOffset: number,
  findings: RawFinding[],
  vendor: VendorId
): void {
  collectPatternFindings(
    line,
    source,
    lineNumber,
    lineStartOffset,
    EMAIL_PATTERN,
    'Email address',
    (value) => value.toLowerCase(),
    findings,
    vendor,
    'contact.email',
    'Email address pattern matched.'
  );
}

function collectPatternFindings(
  line: string,
  source: Exclude<FindingSource, 'both'>,
  lineNumber: number,
  lineStartOffset: number,
  pattern: RegExp,
  category: SensitiveCategory,
  canonicalize: (value: string) => string,
  findings: RawFinding[],
  vendor: VendorId,
  ruleId: string,
  reason: string,
  confidence: ConfidenceLevel = 'High'
): void {
  pattern.lastIndex = 0;

  for (const match of line.matchAll(pattern)) {
    const value = match[2] ?? match[1] ?? match[0];
    const start = (match.index ?? 0) + (match[1] && match[2] ? match[1].length : 0);

    findings.push(
      buildRawFinding({
        category,
        line,
        source,
        lineNumber,
        lineStartOffset,
        canonical: canonicalize(value),
        lineRanges: [{ start, end: start + value.length }],
        confidence,
        reason,
        ruleId,
        vendor
      })
    );
  }
}

function collectCapturedValueFindings(
  line: string,
  source: Exclude<FindingSource, 'both'>,
  lineNumber: number,
  lineStartOffset: number,
  pattern: RegExp,
  category: SensitiveCategory,
  findings: RawFinding[],
  vendor: VendorId,
  ruleId: string,
  reason: string,
  confidence: ConfidenceLevel = 'Medium',
  severity: FindingSeverity = 'Review'
): void {
  pattern.lastIndex = 0;

  for (const match of line.matchAll(pattern)) {
    const value = match[2];

    if (!value || isPlaceholder(value)) {
      continue;
    }

    const searchStart = (match.index ?? 0) + match[1].length;
    const start = line.indexOf(value, searchStart);

    if (start < 0) {
      continue;
    }

    findings.push(
      buildRawFinding({
        category,
        severity,
        line,
        source,
        lineNumber,
        lineStartOffset,
        canonical: `${category}:${value.toLowerCase()}`,
        lineRanges: [{ start, end: start + value.length }],
        confidence,
        reason,
        ruleId,
        vendor
      })
    );
  }
}

function collectUrlFindings(
  line: string,
  source: Exclude<FindingSource, 'both'>,
  lineNumber: number,
  lineStartOffset: number,
  findings: RawFinding[],
  vendor: VendorId
): void {
  URL_PATTERN.lastIndex = 0;

  for (const match of line.matchAll(URL_PATTERN)) {
    const value = match[0];

    findings.push(
      buildRawFinding({
        category: 'URL',
        line,
        source,
        lineNumber,
        lineStartOffset,
        canonical: stripUrlQueryAndFragment(value).toLowerCase(),
        lineRanges: [
          {
            start: match.index ?? 0,
            end: (match.index ?? 0) + value.length
          }
        ],
        confidence: 'High',
        reason: 'HTTP or HTTPS URL pattern matched.',
        ruleId: 'contact.url',
        vendor
      })
    );
  }
}

function collectHostnameFindings(
  line: string,
  source: Exclude<FindingSource, 'both'>,
  lineNumber: number,
  lineStartOffset: number,
  findings: RawFinding[],
  vendor: VendorId
): void {
  collectCapturedValueFindings(
    line,
    source,
    lineNumber,
    lineStartOffset,
    /\b(hostname)\s+([A-Za-z][A-Za-z0-9._-]{1,63})\b/gi,
    'Hostname',
    findings,
    vendor,
    'hostname.cisco',
    'Hostname declaration matched.'
  );
  collectCapturedValueFindings(
    line,
    source,
    lineNumber,
    lineStartOffset,
    /\b(set\s+system\s+host-name)\s+([A-Za-z][A-Za-z0-9._-]{1,63})\b/gi,
    'Hostname',
    findings,
    vendor,
    'hostname.juniper',
    'Juniper host-name declaration matched.'
  );
}

function collectHostnamePromptFinding(
  line: string,
  source: Exclude<FindingSource, 'both'>,
  lineNumber: number,
  lineStartOffset: number,
  findings: RawFinding[],
  vendor: VendorId
): void {
  const trimmed = line.trim();
  const match = trimmed.match(HOSTNAME_PROMPT_PATTERN);

  if (!match) {
    return;
  }

  const prompt = match[1];

  findings.push(
    buildRawFinding({
      category: 'Hostname prompt',
      line: trimmed,
      source,
      lineNumber,
      lineStartOffset,
      canonical: prompt.toLowerCase(),
      lineRanges: collectHostnamePromptRanges(line),
      confidence: 'High',
      reason: 'Network device prompt pattern matched.',
      ruleId: 'hostname.prompt',
      vendor
    })
  );
}

function collectInterfaceFindings(
  line: string,
  source: Exclude<FindingSource, 'both'>,
  lineNumber: number,
  lineStartOffset: number,
  findings: RawFinding[],
  vendor: VendorId
): void {
  const interfacePattern =
    /\b((?:GigabitEthernet|TenGigabitEthernet|FastEthernet|Ethernet|Port-channel|Loopback|Tunnel|Serial|HundredGigE|ge-|xe-|et-)[A-Za-z0-9/_.:-]*)\b/g;

  for (const match of line.matchAll(interfacePattern)) {
    const value = match[1];

    findings.push(
      buildRawFinding({
        category: 'Interface name',
        line,
        source,
        lineNumber,
        lineStartOffset,
        canonical: value.toLowerCase(),
        lineRanges: [
          {
            start: match.index ?? 0,
            end: (match.index ?? 0) + value.length
          }
        ],
        confidence: 'High',
        reason: 'Network interface identifier matched.',
        ruleId: 'topology.interface',
        vendor
      })
    );
  }
}

function collectVrfFindings(
  line: string,
  source: Exclude<FindingSource, 'both'>,
  lineNumber: number,
  lineStartOffset: number,
  findings: RawFinding[],
  vendor: VendorId
): void {
  collectCapturedValueFindings(
    line,
    source,
    lineNumber,
    lineStartOffset,
    /\b(vrf(?:\s+(?:definition|forwarding))?)\s+([A-Za-z0-9_.:-]{2,})\b/gi,
    'VRF name',
    findings,
    vendor,
    'topology.vrf',
    'VRF context matched.'
  );
  collectCapturedValueFindings(
    line,
    source,
    lineNumber,
    lineStartOffset,
    /\b(routing-instances)\s+([A-Za-z0-9_.:-]{2,})\b/gi,
    'VRF name',
    findings,
    vendor,
    'topology.routing-instance',
    'Routing instance context matched.'
  );
}

function collectVlanFindings(
  line: string,
  source: Exclude<FindingSource, 'both'>,
  lineNumber: number,
  lineStartOffset: number,
  findings: RawFinding[],
  vendor: VendorId
): void {
  collectCapturedValueFindings(
    line,
    source,
    lineNumber,
    lineStartOffset,
    /\b(vlan)\s+(\d{1,4})\b/gi,
    'VLAN identifier',
    findings,
    vendor,
    'topology.vlan-id',
    'VLAN identifier matched.'
  );

  const vlanInterfacePattern = /\b(Vlan\d{1,4})\b/g;

  for (const match of line.matchAll(vlanInterfacePattern)) {
    const value = match[1];

    findings.push(
      buildRawFinding({
        category: 'VLAN identifier',
        line,
        source,
        lineNumber,
        lineStartOffset,
        canonical: value.toLowerCase(),
        lineRanges: [
          {
            start: match.index ?? 0,
            end: (match.index ?? 0) + value.length
          }
        ],
        confidence: 'High',
        reason: 'VLAN interface identifier matched.',
        ruleId: 'topology.vlan-interface',
        vendor
      })
    );
  }
}

function collectAsnFindings(
  line: string,
  source: Exclude<FindingSource, 'both'>,
  lineNumber: number,
  lineStartOffset: number,
  findings: RawFinding[],
  vendor: VendorId
): void {
  collectCapturedValueFindings(
    line,
    source,
    lineNumber,
    lineStartOffset,
    /\b(router\s+bgp|local-as|remote-as|as-number)\s+(\d{1,10})\b/gi,
    'BGP ASN',
    findings,
    vendor,
    'topology.asn',
    'Autonomous system number context matched.'
  );
}

function collectSerialFindings(
  line: string,
  source: Exclude<FindingSource, 'both'>,
  lineNumber: number,
  lineStartOffset: number,
  findings: RawFinding[],
  vendor: VendorId
): void {
  collectCapturedValueFindings(
    line,
    source,
    lineNumber,
    lineStartOffset,
    /\b(serial(?:\s+number)?|sn)\s*[:= ]\s*([A-Z0-9-]{5,})\b/gi,
    'Serial number',
    findings,
    vendor,
    'asset.serial',
    'Serial-number context matched.'
  );
}

function collectCircuitFindings(
  line: string,
  source: Exclude<FindingSource, 'both'>,
  lineNumber: number,
  lineStartOffset: number,
  findings: RawFinding[],
  vendor: VendorId
): void {
  collectCapturedValueFindings(
    line,
    source,
    lineNumber,
    lineStartOffset,
    /\b(circuit|ckt|service[-\s]?id)\s*[:#= ]\s*([A-Z0-9._:-]{4,})\b/gi,
    'Circuit ID',
    findings,
    vendor,
    'customer.circuit-id',
    'Circuit or service identifier context matched.'
  );
}

function collectSiteCustomerFindings(
  line: string,
  source: Exclude<FindingSource, 'both'>,
  lineNumber: number,
  lineStartOffset: number,
  findings: RawFinding[],
  vendor: VendorId
): void {
  collectCapturedValueFindings(
    line,
    source,
    lineNumber,
    lineStartOffset,
    /\b(site|customer|cust|tenant)\s*[:= ]\s*([A-Za-z0-9._:-]{3,})\b/gi,
    'Site or customer label',
    findings,
    vendor,
    'customer.label',
    'Site or customer label context matched.'
  );
}

function collectCertificateKeyFindings(
  line: string,
  source: Exclude<FindingSource, 'both'>,
  lineNumber: number,
  lineStartOffset: number,
  findings: RawFinding[],
  vendor: VendorId
): void {
  const pattern =
    /-----BEGIN [A-Z ]*(?:PRIVATE KEY|CERTIFICATE)-----|-----END [A-Z ]*(?:PRIVATE KEY|CERTIFICATE)-----/g;

  for (const match of line.matchAll(pattern)) {
    const value = match[0];

    findings.push(
      buildRawFinding({
        category: 'Certificate or key material',
        severity: 'High review priority',
        line,
        source,
        lineNumber,
        lineStartOffset,
        canonical: `key-material:${value.toLowerCase()}`,
        lineRanges: [
          {
            start: match.index ?? 0,
            end: (match.index ?? 0) + value.length
          }
        ],
        confidence: 'High',
        reason: 'Certificate or private-key marker matched.',
        ruleId: 'secret.key-material',
        vendor
      })
    );
  }
}

function collectCloudIdentifierFindings(
  line: string,
  source: Exclude<FindingSource, 'both'>,
  lineNumber: number,
  lineStartOffset: number,
  findings: RawFinding[],
  vendor: VendorId
): void {
  const accessKeyPattern = /\b((?:AKIA|ASIA)[0-9A-Z]{16})\b/g;

  for (const match of line.matchAll(accessKeyPattern)) {
    const value = match[1];

    findings.push(
      buildRawFinding({
        category: 'Cloud identifier',
        severity: 'High review priority',
        line,
        source,
        lineNumber,
        lineStartOffset,
        canonical: `cloud-key:${value.toLowerCase()}`,
        lineRanges: [
          {
            start: match.index ?? 0,
            end: (match.index ?? 0) + value.length
          }
        ],
        confidence: 'High',
        reason: 'Cloud access-key style identifier matched.',
        ruleId: 'cloud.aws-access-key',
        vendor
      })
    );
  }

  collectCapturedValueFindings(
    line,
    source,
    lineNumber,
    lineStartOffset,
    /\b(project(?:-id)?|subscription(?:-id)?|tenant(?:-id)?)\s*[:= ]\s*([A-Za-z0-9._:-]{5,})\b/gi,
    'Cloud identifier',
    findings,
    vendor,
    'cloud.resource-id',
    'Cloud resource identifier context matched.',
    'Medium'
  );
}

function collectConfigCommentFindings(
  line: string,
  source: Exclude<FindingSource, 'both'>,
  lineNumber: number,
  lineStartOffset: number,
  findings: RawFinding[],
  vendor: VendorId
): void {
  const pattern =
    /^(\s*(?:description|remark|comment|#|!)\s+)(.*(?:customer|site|circuit|tenant|account|address|noc|contact).*)$/i;
  const match = line.match(pattern);

  if (!match) {
    return;
  }

  const value = match[2].trim();

  if (!value || isPlaceholder(value)) {
    return;
  }

  const start = line.indexOf(match[2]);

  findings.push(
    buildRawFinding({
      category: 'Config comment metadata',
      line,
      source,
      lineNumber,
      lineStartOffset,
      canonical: `comment:${canonicalizeLine(match[2])}`,
      lineRanges: [{ start, end: start + match[2].length }],
      confidence: 'Low',
      reason: 'Comment or description contains customer/site metadata terms.',
      ruleId: 'metadata.comment',
      vendor
    })
  );
}

function buildRawFinding(input: FindingInput): RawFinding {
  const previewRanges = input.lineRanges.map((range) => ({
    ...range,
    category: input.category
  }));

  return {
    category: input.category,
    severity: input.severity ?? 'Review',
    preview: buildPreview(input.line, previewRanges),
    source: input.source,
    line: input.lineNumber,
    canonical: input.canonical,
    redactionRanges: getCleanedRedactionRanges(
      input.source,
      input.lineStartOffset,
      input.lineRanges
    ),
    confidence: input.confidence ?? 'Medium',
    reason: input.reason,
    ruleId: input.ruleId,
    vendor: input.vendor,
    previewRanges
  };
}

function maskLineFindingPreviews(line: string, findings: RawFinding[]): void {
  const linePreviewRanges = findings.flatMap((finding) => finding.previewRanges);

  for (const finding of findings) {
    finding.preview = buildPreview(line, linePreviewRanges);
  }
}

function getCleanedRedactionRanges(
  source: Exclude<FindingSource, 'both'>,
  lineStartOffset: number,
  lineRanges: TextRange[]
): TextRange[] {
  if (source !== 'cleaned') {
    return [];
  }

  return lineRanges
    .filter((range) => range.end > range.start)
    .map((range) => ({
      start: lineStartOffset + range.start,
      end: lineStartOffset + range.end
    }));
}

function collectCredentialValueRanges(line: string): TextRange[] {
  const ranges: TextRange[] = [];

  addCapturedValueRanges(line, AUTHORIZATION_BEARER_VALUE_PATTERN, ranges);
  addCapturedValueRanges(line, AUTHORIZATION_VALUE_PATTERN, ranges);
  addCapturedValueRanges(line, /\b(bearer)\s+("[^"]+"|'[^']+'|\S+)/gi, ranges);
  addCapturedValueRanges(
    line,
    /\b(snmp-server\s+community)\s+("[^"]+"|'[^']+'|\S+)/gi,
    ranges
  );
  addCapturedValueRanges(line, /\b(community)\s+("[^"]+"|'[^']+'|\S+)/gi, ranges);
  addCapturedValueRanges(
    line,
    /\b(username\s+(?:"[^"]+"|'[^']+'|\S+)\s+(?:password|secret)(?:\s+(?:0|5|7|8|9))?)\s+("[^"]+"|'[^']+'|\S+)/gi,
    ranges
  );
  addCapturedValueRanges(
    line,
    /\b(enable\s+secret(?:\s+(?:0|5|7|8|9))?)\s+("[^"]+"|'[^']+'|\S+)/gi,
    ranges
  );
  addCapturedValueRanges(
    line,
    /\b(crypto\s+isakmp\s+key(?:\s+\d+)?)\s+("[^"]+"|'[^']+'|\S+)/gi,
    ranges
  );
  addCapturedValueRanges(
    line,
    /\b((?:api[-_ ]?key|token)\b(?:\s*[:=]\s*|\s+))("[^"]+"|'[^']+'|\S+)/gi,
    ranges
  );
  addCapturedValueRanges(
    line,
    /\b((?:password|passwd|secret|private\s+key|pre-shared\s+key|preshared\s+key|key-string|token|authentication\s+key)\b(?:\s*[:=])?(?:\s+(?:0|5|7|8|9))?)\s+("[^"]+"|'[^']+'|\S+)/gi,
    ranges
  );

  return mergeRanges(ranges);
}

function addCapturedValueRanges(
  line: string,
  pattern: RegExp,
  ranges: TextRange[]
): void {
  pattern.lastIndex = 0;

  for (const match of line.matchAll(pattern)) {
    const value = match[2];

    if (!value || isPlaceholder(value)) {
      continue;
    }

    const searchStart = (match.index ?? 0) + match[1].length;
    const start = line.indexOf(value, searchStart);

    if (start < 0) {
      continue;
    }

    if (isInsideUrlSpan(line, start)) {
      continue;
    }

    ranges.push({ start, end: start + value.length });
  }
}

function collectHostnamePromptRanges(line: string): TextRange[] {
  const match = line.match(
    /^(\s*)([A-Za-z][A-Za-z0-9._-]{1,63})((?:\([A-Za-z0-9_.:/-]+\))*)([>#])/
  );

  if (!match) {
    return [];
  }

  const start = match[1].length;
  return [{ start, end: start + match[2].length }];
}

function mergeEquivalentFindings(rawFindings: RawFinding[]): MergedFinding[] {
  const byKey = new Map<string, MergedFinding>();
  let order = 0;

  for (const rawFinding of rawFindings) {
    const key = `${rawFinding.category}:${rawFinding.canonical}`;
    const existing = byKey.get(key);

    if (!existing) {
      byKey.set(key, {
        id: buildFindingId(key),
        category: rawFinding.category,
        severity: rawFinding.severity,
        preview: rawFinding.preview,
        source: rawFinding.source,
        originalLine:
          rawFinding.source === 'original' ? rawFinding.line : undefined,
        cleanedLine: rawFinding.source === 'cleaned' ? rawFinding.line : undefined,
        redactionRanges: [...rawFinding.redactionRanges],
        confidence: rawFinding.confidence,
        reason: rawFinding.reason,
        ruleId: rawFinding.ruleId,
        vendor: rawFinding.vendor,
        profileAction: 'review',
        previewRanges: rawFinding.previewRanges,
        canonical: rawFinding.canonical,
        order
      });
      order += 1;
      continue;
    }

    if (existing.source !== rawFinding.source) {
      existing.source = 'both';
    }

    if (rawFinding.source === 'original' && existing.originalLine === undefined) {
      existing.originalLine = rawFinding.line;
    }

    if (rawFinding.source === 'cleaned' && existing.cleanedLine === undefined) {
      existing.cleanedLine = rawFinding.line;
    }

    existing.redactionRanges.push(...rawFinding.redactionRanges);

    if (confidenceRank(rawFinding.confidence) > confidenceRank(existing.confidence)) {
      existing.confidence = rawFinding.confidence;
    }

    if (
      existing.severity === 'Review' &&
      rawFinding.severity === 'High review priority'
    ) {
      existing.severity = rawFinding.severity;
      existing.preview = rawFinding.preview;
      existing.reason = rawFinding.reason;
      existing.ruleId = rawFinding.ruleId;
    }
  }

  return Array.from(byKey.values())
    .sort((left, right) => {
      const severityDelta =
        severityRank(right.severity) - severityRank(left.severity);

      if (severityDelta !== 0) {
        return severityDelta;
      }

      const lineDelta = firstLine(left) - firstLine(right);

      if (lineDelta !== 0) {
        return lineDelta;
      }

      return left.order - right.order;
    })
    .map((finding) => ({
      ...finding,
      redactionRanges: mergeRanges(finding.redactionRanges)
    }));
}

function mergeRanges(ranges: TextRange[]): TextRange[] {
  const sortedRanges = ranges
    .filter((range) => range.end > range.start)
    .sort((left, right) => left.start - right.start || left.end - right.end);
  const merged: TextRange[] = [];

  for (const range of sortedRanges) {
    const last = merged.at(-1);

    if (!last || range.start > last.end) {
      merged.push({ ...range });
      continue;
    }

    last.end = Math.max(last.end, range.end);
  }

  return merged;
}

function buildFindingId(key: string): string {
  return `finding-${hashString(key)}`;
}

function hashString(input: string): string {
  let hash = 0x811c9dc5;

  for (let index = 0; index < input.length; index += 1) {
    hash ^= input.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193);
  }

  return (hash >>> 0).toString(36);
}

function severityRank(severity: FindingSeverity): number {
  return severity === 'High review priority' ? 1 : 0;
}

function confidenceRank(confidence: ConfidenceLevel): number {
  switch (confidence) {
    case 'High':
      return 2;
    case 'Medium':
      return 1;
    case 'Low':
    default:
      return 0;
  }
}

function firstLine(finding: SensitiveFinding): number {
  return Math.min(
    finding.originalLine ?? Number.POSITIVE_INFINITY,
    finding.cleanedLine ?? Number.POSITIVE_INFINITY
  );
}

function isCredentialLine(line: string): boolean {
  return CREDENTIAL_PATTERNS.some((pattern) => pattern.test(line));
}

function getCredentialRuleId(line: string): string {
  if (/\bsnmp-server\s+community\b|\bcommunity\b/i.test(line)) {
    return 'credential.community';
  }

  if (/\b(?:authorization|bearer|token|api[-_ ]?key)\b/i.test(line)) {
    return 'credential.token';
  }

  if (/\b(?:private\s+key|pre-shared\s+key|preshared\s+key|key-string|crypto\s+isakmp\s+key)\b/i.test(line)) {
    return 'credential.key';
  }

  return 'credential.secret';
}

function isValidIpv4(candidate: string): boolean {
  return candidate.split('.').every((octet) => {
    if (!/^\d{1,3}$/.test(octet)) {
      return false;
    }

    const value = Number(octet);
    return value >= 0 && value <= 255;
  });
}

function isPrivateIpv4(candidate: string): boolean {
  const [first, second] = candidate.split('.').map(Number);

  return (
    first === 10 ||
    first === 127 ||
    (first === 169 && second === 254) ||
    (first === 172 && second >= 16 && second <= 31) ||
    (first === 192 && second === 168) ||
    (first === 100 && second >= 64 && second <= 127)
  );
}

function isLikelyIpv6(candidate: string): boolean {
  const zoneIndex = candidate.indexOf('%');
  const address = zoneIndex >= 0 ? candidate.slice(0, zoneIndex) : candidate;
  const parts = address.split(':');

  if (parts.length < 3 || parts.length > 8) {
    return false;
  }

  const compressedSections = address.match(/::/g)?.length ?? 0;

  if (compressedSections > 1) {
    return false;
  }

  return parts.every((part) => part === '' || /^[A-Fa-f0-9]{1,4}$/.test(part));
}

function isPrivateIpv6(candidate: string): boolean {
  const normalized = candidate.toLowerCase();

  return (
    normalized === '::1' ||
    normalized.startsWith('fc') ||
    normalized.startsWith('fd') ||
    normalized.startsWith('fe80')
  );
}

function canonicalizeMac(value: string): string {
  return value.replace(/[^0-9A-Fa-f]/g, '').toLowerCase();
}

function canonicalizeLine(line: string): string {
  return removeAnsiSequences(line)
    .replace(/[\x00-\x1F\x7F]/g, '')
    .replace(/\s+/g, ' ')
    .trim()
    .toLowerCase();
}

function buildPreview(
  line: string,
  previewRanges: PreviewRange[]
): string {
  let preview = removeAnsiSequences(line).replace(
    /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g,
    ''
  );

  preview = replaceRangesWithPreviewLabel(preview, previewRanges);
  preview = stripUrlPreviewSecrets(preview);
  preview = maskSensitiveText(preview).replace(/\s+/g, ' ').trim();

  if (preview.length > MAX_PREVIEW_LENGTH) {
    preview = `${preview.slice(0, MAX_PREVIEW_LENGTH - 3)}...`;
  }

  return escapePreview(preview);
}

function replaceRangesWithPreviewLabel(
  line: string,
  previewRanges: PreviewRange[]
): string {
  let preview = line;
  const replacements = mergePreviewRanges(previewRanges);

  for (const replacement of replacements.sort((left, right) => right.start - left.start)) {
    const start = Math.max(0, Math.min(replacement.start, preview.length));
    const end = Math.max(start, Math.min(replacement.end, preview.length));

    if (end > start) {
      preview = `${preview.slice(0, start)}${replacement.label}${preview.slice(end)}`;
    }
  }

  return preview;
}

function mergePreviewRanges(previewRanges: PreviewRange[]): PreviewReplacement[] {
  const sortedRanges = previewRanges
    .filter((range) => range.end > range.start)
    .sort((left, right) => left.start - right.start || left.end - right.end);
  const replacements: PreviewReplacement[] = [];

  for (const range of sortedRanges) {
    const nextReplacement = {
      start: range.start,
      end: range.end,
      label: getPreviewLabel(range.category)
    };
    const lastReplacement = replacements.at(-1);

    if (!lastReplacement || nextReplacement.start > lastReplacement.end) {
      replacements.push(nextReplacement);
      continue;
    }

    lastReplacement.end = Math.max(lastReplacement.end, nextReplacement.end);

    if (lastReplacement.label !== nextReplacement.label) {
      lastReplacement.label = '[masked-value]';
    }
  }

  return replacements;
}

function getPreviewLabel(category: SensitiveCategory): string {
  switch (category) {
    case 'Public IP address':
    case 'Private IP address':
    case 'IPv4 address':
    case 'IPv6 address':
      return '[masked-ip]';
    case 'MAC address':
      return '[masked-mac]';
    case 'Email address':
      return '[masked-email]';
    case 'URL':
      return '[masked-url]';
    case 'Credential or secret':
      return '[masked]';
    case 'Certificate or key material':
      return '[masked-key]';
    case 'Cloud identifier':
      return '[masked-cloud]';
    default:
      return '[masked-value]';
  }
}

function stripUrlPreviewSecrets(preview: string): string {
  return preview.replace(URL_PATTERN, (url) => stripUrlQueryAndFragment(url));
}

function stripUrlQueryAndFragment(url: string): string {
  const indexes = [url.indexOf('?'), url.indexOf('#')].filter(
    (index) => index >= 0
  );

  if (indexes.length === 0) {
    return url;
  }

  return url.slice(0, Math.min(...indexes));
}

function isPlaceholder(value: string): boolean {
  return (
    REDACTION_PLACEHOLDER_PATTERN.test(value) ||
    TOKEN_PLACEHOLDER_PATTERN.test(value)
  );
}

function isInsideUrlSpan(line: string, index: number): boolean {
  URL_PATTERN.lastIndex = 0;

  for (const match of line.matchAll(URL_PATTERN)) {
    const start = match.index ?? 0;
    const end = start + match[0].length;

    if (index >= start && index < end) {
      return true;
    }
  }

  return false;
}

function escapePreview(input: string): string {
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

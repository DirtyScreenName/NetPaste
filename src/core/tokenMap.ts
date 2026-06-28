import type { SensitiveCategory, SensitiveFinding } from './types';

export type TokenMap = ReadonlyMap<string, string>;

export interface TokenMapOptions {
  enabled?: boolean;
}

export function buildTokenMap(
  findings: SensitiveFinding[],
  options: TokenMapOptions = {}
): Map<string, string> {
  const tokenMap = new Map<string, string>();

  if (!options.enabled) {
    return tokenMap;
  }

  const counters = new Map<string, number>();

  for (const finding of findings) {
    if (finding.redactionRanges.length === 0) {
      continue;
    }

    const prefix = getTokenPrefix(finding.category);
    const nextIndex = (counters.get(prefix) ?? 0) + 1;
    counters.set(prefix, nextIndex);
    tokenMap.set(finding.id, `<${prefix}-${nextIndex}>`);
  }

  return tokenMap;
}

export function applyTokenMapToFindings(
  findings: SensitiveFinding[],
  tokenMap: TokenMap
): SensitiveFinding[] {
  return findings.map((finding) => {
    const replacementToken = tokenMap.get(finding.id);

    if (!replacementToken) {
      const { replacementToken: _unused, ...withoutToken } = finding;
      return withoutToken;
    }

    return {
      ...finding,
      replacementToken
    };
  });
}

function getTokenPrefix(category: SensitiveCategory): string {
  switch (category) {
    case 'IPv4 address':
    case 'IPv6 address':
    case 'Public IP address':
    case 'Private IP address':
      return 'IP';
    case 'Hostname prompt':
    case 'Hostname':
      return 'HOST';
    case 'Interface name':
      return 'IFACE';
    case 'VRF name':
      return 'VRF';
    case 'VLAN identifier':
      return 'VLAN';
    case 'BGP ASN':
      return 'ASN';
    case 'Serial number':
      return 'SERIAL';
    case 'Circuit ID':
      return 'CIRCUIT';
    case 'Site or customer label':
      return 'SITE';
    case 'Cloud identifier':
      return 'CLOUD';
    case 'Email address':
      return 'EMAIL';
    case 'URL':
      return 'URL';
    case 'MAC address':
      return 'MAC';
    case 'Certificate or key material':
      return 'KEY';
    case 'Credential or secret':
      return 'SECRET';
    case 'Config comment metadata':
      return 'NOTE';
    default:
      return 'VALUE';
  }
}

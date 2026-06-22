import { normalizeLineEndings } from './cleanText';

const IPV4_CANDIDATE_PATTERN =
  /(^|[^\d.])((?:\d{1,3}\.){3}\d{1,3})(?![\d.])/g;
const MAC_STANDARD_PATTERN =
  /(^|[^0-9A-Fa-f])((?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2})(?![0-9A-Fa-f])/g;
const MAC_CISCO_PATTERN =
  /(^|[^0-9A-Fa-f])([0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4})(?![0-9A-Fa-f])/g;
const EMAIL_PATTERN =
  /(^|[^A-Z0-9._%+-])([A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,})(?![A-Z0-9._%+-])/gi;
const URL_PATTERN = /\bhttps?:\/\/[^\s<>"']+/gi;
const IPV6_CANDIDATE_PATTERN = /[A-Fa-f0-9:]{2,}(?:%[A-Za-z0-9_.-]+)?/g;
const HOSTNAME_PROMPT_PATTERN =
  /^(\s*)([A-Za-z][A-Za-z0-9._-]{1,63})((?:\([A-Za-z0-9_.:/-]+\))*)([>#])(.*)?$/;

const LINE_ENDING_PATTERN = /(\r\n|\n|\r)/;

export function maskSensitiveText(input: string): string {
  return input
    .split(LINE_ENDING_PATTERN)
    .map((part) => (LINE_ENDING_PATTERN.test(part) ? part : maskSensitiveLine(part)))
    .join('');
}

export function maskCredentialValues(input: string): string {
  let masked = input;

  masked = masked.replace(
    /\b(authorization\s*:\s*bearer)\s+("[^"]+"|'[^']+'|\S+)/gi,
    '$1 [masked]'
  );
  masked = masked.replace(
    /\b(authorization\s*:)\s*(?!bearer\s+\[masked\]$)("[^"]+"|'[^']+'|\S+(?:\s+\S+)*)/gi,
    '$1 [masked]'
  );
  masked = masked.replace(/\b(bearer)\s+("[^"]+"|'[^']+'|\S+)/gi, '$1 [masked]');
  masked = masked.replace(
    /\b(snmp-server\s+community)\s+("[^"]+"|'[^']+'|\S+)/gi,
    '$1 [masked]'
  );
  masked = masked.replace(
    /\b(username\s+(?:"[^"]+"|'[^']+'|\S+)\s+(?:password|secret)(?:\s+(?:0|5|7|8|9))?)\s+("[^"]+"|'[^']+'|\S+)/gi,
    '$1 [masked]'
  );
  masked = masked.replace(
    /\b(enable\s+secret(?:\s+(?:0|5|7|8|9))?)\s+.+$/gi,
    '$1 [masked]'
  );
  masked = masked.replace(
    /\b(crypto\s+isakmp\s+key)\s+("[^"]+"|'[^']+'|\S+)/gi,
    '$1 [masked]'
  );
  masked = masked.replace(
    /\b(api[-_ ]?key|token)\b(\s*[:=]\s*)("[^"]+"|'[^']+'|[^\s]+)/gi,
    '$1$2[masked]'
  );
  masked = masked.replace(
    /\b(password|passwd|secret|private\s+key|pre-shared\s+key|preshared\s+key|key-string|token|authentication\s+key)\b(\s*[:=])?(\s+(?:0|5|7|8|9))?\s+.+$/gi,
    (
      _match,
      keyword: string,
      separator: string | undefined,
      secretType: string | undefined
    ) => `${keyword}${separator ?? ''}${secretType ?? ''} [masked]`
  );

  return masked;
}

function maskSensitiveLine(line: string): string {
  let masked = maskCredentialValues(line);

  masked = maskUrls(masked);
  masked = maskEmails(masked);
  masked = maskMacAddresses(masked);
  masked = maskIpv6Addresses(masked);
  masked = maskIpv4Addresses(masked);
  masked = maskHostnamePrompt(masked);

  return masked;
}

function maskUrls(input: string): string {
  URL_PATTERN.lastIndex = 0;
  return input.replace(URL_PATTERN, '[masked-url]');
}

function maskEmails(input: string): string {
  EMAIL_PATTERN.lastIndex = 0;
  return input.replace(EMAIL_PATTERN, (_match, prefix: string) => {
    return `${prefix}[masked-email]`;
  });
}

function maskMacAddresses(input: string): string {
  let masked = replaceBoundedPattern(
    input,
    MAC_STANDARD_PATTERN,
    '[masked-mac]'
  );
  masked = replaceBoundedPattern(masked, MAC_CISCO_PATTERN, '[masked-mac]');
  return masked;
}

function maskIpv4Addresses(input: string): string {
  IPV4_CANDIDATE_PATTERN.lastIndex = 0;
  return input.replace(IPV4_CANDIDATE_PATTERN, (match, prefix: string, value: string) => {
    if (!isValidIpv4(value)) {
      return match;
    }

    return `${prefix}[masked-ipv4]`;
  });
}

function maskIpv6Addresses(input: string): string {
  IPV6_CANDIDATE_PATTERN.lastIndex = 0;
  return input.replace(IPV6_CANDIDATE_PATTERN, (candidate: string) => {
    if (/^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/.test(candidate)) {
      return candidate;
    }

    if (!candidate.includes(':') || !isLikelyIpv6(candidate)) {
      return candidate;
    }

    return '[masked-ipv6]';
  });
}

function maskHostnamePrompt(input: string): string {
  const match = input.match(HOSTNAME_PROMPT_PATTERN);

  if (!match) {
    return input;
  }

  const [, leadingWhitespace, , modes, promptMarker, rest = ''] = match;
  return `${leadingWhitespace}[masked-hostname]${modes}${promptMarker}${rest}`;
}

function replaceBoundedPattern(
  input: string,
  pattern: RegExp,
  replacement: string
): string {
  pattern.lastIndex = 0;
  return input.replace(pattern, (_match, prefix: string) => {
    return `${prefix}${replacement}`;
  });
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

function isLikelyIpv6(candidate: string): boolean {
  const normalizedCandidate = normalizeLineEndings(candidate);
  const zoneIndex = normalizedCandidate.indexOf('%');
  const address =
    zoneIndex >= 0 ? normalizedCandidate.slice(0, zoneIndex) : normalizedCandidate;
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

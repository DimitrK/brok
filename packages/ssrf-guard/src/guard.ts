import {lookup as dnsLookup} from 'node:dns/promises';
import {BlockList, isIP} from 'node:net';
import {domainToASCII} from 'node:url';

import {
  DEFAULT_DNS_RESOLUTION_CONFIG,
  DnsResolutionConfigSchema,
  GuardExecuteRequestInputSchema,
  GuardExecuteRequestOutputSchema,
  GuardUpstreamResponseInputSchema,
  type DnsResolver,
  type GuardExecuteRequestOptions,
  type TemplateContract
} from './contracts';
import {err, ok, type SsrfGuardErrorCode, type SsrfGuardResult} from './errors';

const PRIVATE_CIDR_RANGES = [
  '10.0.0.0/8',
  '172.16.0.0/12',
  '192.168.0.0/16',
  '100.64.0.0/10',
  '198.18.0.0/15',
  'fc00::/7'
] as const;

const LOOPBACK_CIDR_RANGES = ['127.0.0.0/8', '::1/128'] as const;

const LINK_LOCAL_CIDR_RANGES = ['169.254.0.0/16', 'fe80::/10'] as const;

const METADATA_CIDR_RANGES = ['169.254.169.254/32', 'fd00:ec2::254/128'] as const;

type IpFamily = 'ipv4' | 'ipv6';

type CidrRange = `${string}/${number}`;

const getIpFamily = (value: string): IpFamily | null => {
  const ipVersion = isIP(value);
  if (ipVersion === 4) {
    return 'ipv4';
  }
  if (ipVersion === 6) {
    return 'ipv6';
  }
  return null;
};

const normalizeHostValue = (value: string): string | null => {
  const trimmed = value.trim().toLowerCase();
  if (trimmed.length === 0) {
    return null;
  }

  const withoutBrackets =
    trimmed.startsWith('[') && trimmed.endsWith(']') ? trimmed.slice(1, -1) : trimmed;
  const withoutTrailingDot = withoutBrackets.endsWith('.')
    ? withoutBrackets.slice(0, -1)
    : withoutBrackets;

  if (withoutTrailingDot.length === 0) {
    return null;
  }

  if (getIpFamily(withoutTrailingDot)) {
    return withoutTrailingDot;
  }

  const asciiDomain = domainToASCII(withoutTrailingDot);
  if (!asciiDomain) {
    return null;
  }

  return asciiDomain.toLowerCase();
};

const parseCidrRange = (value: CidrRange): {network: string; prefix: number; family: IpFamily} => {
  const [network, prefixText] = value.split('/', 2);
  const family = getIpFamily(network);
  const prefix = Number.parseInt(prefixText ?? '', 10);

  if (!family) {
    throw new Error(`Invalid CIDR range network: ${value}`);
  }

  if (!Number.isInteger(prefix)) {
    throw new Error(`Invalid CIDR range prefix: ${value}`);
  }

  const maxPrefix = family === 'ipv4' ? 32 : 128;
  if (prefix < 0 || prefix > maxPrefix) {
    throw new Error(`CIDR prefix out of bounds: ${value}`);
  }

  return {network, prefix, family};
};

const buildBlockList = (ranges: readonly CidrRange[]): BlockList => {
  const blockList = new BlockList();
  for (const range of ranges) {
    const parsedRange = parseCidrRange(range);
    blockList.addSubnet(parsedRange.network, parsedRange.prefix, parsedRange.family);
  }
  return blockList;
};

const PRIVATE_BLOCKLIST = buildBlockList(PRIVATE_CIDR_RANGES);
const LOOPBACK_BLOCKLIST = buildBlockList(LOOPBACK_CIDR_RANGES);
const LINK_LOCAL_BLOCKLIST = buildBlockList(LINK_LOCAL_CIDR_RANGES);
const METADATA_BLOCKLIST = buildBlockList(METADATA_CIDR_RANGES);

const isStatusRedirect = (statusCode: number) => statusCode >= 300 && statusCode <= 399;

const normalizeHostAllowlist = (
  allowedHosts: TemplateContract['allowed_hosts']
): SsrfGuardResult<Set<string>> => {
  const normalized = new Set<string>();
  for (const host of allowedHosts) {
    const normalizedHost = normalizeHostValue(host);
    if (!normalizedHost) {
      return err('template_host_invalid', `Template allowed host is invalid: ${host}`);
    }
    normalized.add(normalizedHost);
  }
  return ok(normalized);
};

const normalizeResolvedAddress = (value: string): string | null => normalizeHostValue(value);

const resolveWithTimeout = async ({
  hostname,
  resolver,
  timeoutMs
}: {
  hostname: string;
  resolver: DnsResolver;
  timeoutMs: number;
}): Promise<SsrfGuardResult<string[]>> => {
  let timeoutHandle: NodeJS.Timeout | null = null;

  try {
    const timeoutPromise = new Promise<string[]>((_, reject) => {
      timeoutHandle = setTimeout(() => {
        reject(new Error('dns_timeout'));
      }, timeoutMs);
    });

    const resolved = await Promise.race([Promise.resolve(resolver({hostname})), timeoutPromise]);
    return ok(resolved);
  } catch {
    return err('dns_resolution_failed', `DNS resolution failed for host ${hostname}`);
  } finally {
    if (timeoutHandle) {
      clearTimeout(timeoutHandle);
    }
  }
};

const defaultDnsResolver: DnsResolver = async ({hostname}) => {
  const records = await dnsLookup(hostname, {all: true, verbatim: true});
  return records.map(record => record.address);
};

const validateResolvedAddressFamily = (address: string): SsrfGuardResult<IpFamily> => {
  const family = getIpFamily(address);
  if (!family) {
    return err('resolved_ip_invalid', `Resolved address is not an IP literal: ${address}`);
  }
  return ok(family);
};

const matchDeniedRangeCode = ({
  address,
  family,
  template
}: {
  address: string;
  family: IpFamily;
  template: TemplateContract;
}): SsrfGuardErrorCode | null => {
  if (
    template.network_safety.deny_metadata_ranges &&
    METADATA_BLOCKLIST.check(address, family)
  ) {
    return 'resolved_ip_denied_metadata_range';
  }

  if (template.network_safety.deny_loopback && LOOPBACK_BLOCKLIST.check(address, family)) {
    return 'resolved_ip_denied_loopback';
  }

  if (template.network_safety.deny_link_local && LINK_LOCAL_BLOCKLIST.check(address, family)) {
    return 'resolved_ip_denied_link_local';
  }

  if (
    template.network_safety.deny_private_ip_ranges &&
    PRIVATE_BLOCKLIST.check(address, family)
  ) {
    return 'resolved_ip_denied_private_range';
  }

  return null;
};

const validateResolvedAddresses = ({
  addresses,
  template
}: {
  addresses: string[];
  template: TemplateContract;
}): SsrfGuardResult<string[]> => {
  const normalizedAddresses: string[] = [];
  const seen = new Set<string>();

  for (const rawAddress of addresses) {
    const normalizedAddress = normalizeResolvedAddress(rawAddress);
    if (!normalizedAddress) {
      return err('resolved_ip_invalid', `Resolved address is invalid: ${rawAddress}`);
    }

    const family = validateResolvedAddressFamily(normalizedAddress);
    if (!family.ok) {
      return family;
    }

    const deniedRange = matchDeniedRangeCode({
      address: normalizedAddress,
      family: family.value,
      template
    });
    if (deniedRange) {
      return err(
        deniedRange,
        `Resolved address ${normalizedAddress} is denied by network_safety`
      );
    }

    if (!seen.has(normalizedAddress)) {
      seen.add(normalizedAddress);
      normalizedAddresses.push(normalizedAddress);
    }
  }

  if (normalizedAddresses.length === 0) {
    return err('dns_resolution_empty', 'DNS resolution returned no IP addresses');
  }

  return ok(normalizedAddresses);
};

const validateRequestUrlAndAllowlist = ({
  rawUrl,
  template
}: {
  rawUrl: string;
  template: TemplateContract;
}): SsrfGuardResult<{
  parsedUrl: URL;
  normalizedHost: string;
  port: number;
  hostIsIpLiteral: boolean;
}> => {
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(rawUrl);
  } catch {
    return err('request_url_invalid', `Invalid request URL: ${rawUrl}`);
  }

  if (parsedUrl.username.length > 0 || parsedUrl.password.length > 0) {
    return err('request_url_userinfo_forbidden', 'Request URL userinfo is forbidden');
  }

  if (parsedUrl.hash.length > 0) {
    return err('request_url_fragment_forbidden', 'Request URL fragment is forbidden');
  }

  const scheme = parsedUrl.protocol.replace(/:$/u, '').toLowerCase();
  const allowedSchemes = new Set(template.allowed_schemes.map(item => item.toLowerCase()));
  if (!allowedSchemes.has(scheme)) {
    return err('request_scheme_not_allowed', `Request scheme is not allowed: ${scheme}`);
  }

  const normalizedHost = normalizeHostValue(parsedUrl.hostname);
  if (!normalizedHost) {
    return err('request_url_invalid', `Request host is invalid: ${parsedUrl.hostname}`);
  }

  const normalizedAllowlist = normalizeHostAllowlist(template.allowed_hosts);
  if (!normalizedAllowlist.ok) {
    return normalizedAllowlist;
  }

  const hostIsIpLiteral = getIpFamily(normalizedHost) !== null;
  if (hostIsIpLiteral && !normalizedAllowlist.value.has(normalizedHost)) {
    return err(
      'request_ip_literal_forbidden',
      `IP literal URL host requires explicit template allowlist entry: ${normalizedHost}`
    );
  }

  if (!normalizedAllowlist.value.has(normalizedHost)) {
    return err('request_host_not_allowed', `Request host is not allowed: ${normalizedHost}`);
  }

  const port = parsedUrl.port.length > 0 ? Number.parseInt(parsedUrl.port, 10) : 443;
  const allowedPorts = new Set(template.allowed_ports.map(Number));
  if (!allowedPorts.has(port)) {
    return err('request_port_not_allowed', `Request port is not allowed: ${port}`);
  }

  return ok({
    parsedUrl,
    normalizedHost,
    port,
    hostIsIpLiteral
  });
};

const resolveDestinationAddresses = async ({
  normalizedHost,
  hostIsIpLiteral,
  template,
  dnsResolver,
  timeoutMs
}: {
  normalizedHost: string;
  hostIsIpLiteral: boolean;
  template: TemplateContract;
  dnsResolver: DnsResolver;
  timeoutMs: number;
}): Promise<SsrfGuardResult<string[]>> => {
  if (hostIsIpLiteral) {
    return validateResolvedAddresses({
      addresses: [normalizedHost],
      template
    });
  }

  if (!template.network_safety.dns_resolution_required) {
    return err(
      'dns_resolution_required',
      'Template network_safety.dns_resolution_required must be true'
    );
  }

  const resolvedAddresses = await resolveWithTimeout({
    hostname: normalizedHost,
    resolver: dnsResolver,
    timeoutMs
  });
  if (!resolvedAddresses.ok) {
    return resolvedAddresses;
  }

  return validateResolvedAddresses({
    addresses: resolvedAddresses.value,
    template
  });
};

export const guardExecuteRequestDestination = async ({
  input,
  options
}: {
  input: unknown;
  options?: GuardExecuteRequestOptions;
}): Promise<SsrfGuardResult<{
  destination: {
    scheme: string;
    host: string;
    port: number;
    pathname: string;
  };
  resolved_ips: string[];
}>> => {
  const parsedInput = GuardExecuteRequestInputSchema.safeParse(input);
  if (!parsedInput.success) {
    return err('invalid_input', parsedInput.error.message);
  }

  const dnsConfig = DnsResolutionConfigSchema.parse({
    ...DEFAULT_DNS_RESOLUTION_CONFIG,
    ...(options?.dns_resolution ?? {})
  });

  const requestValidation = validateRequestUrlAndAllowlist({
    rawUrl: parsedInput.data.execute_request.request.url,
    template: parsedInput.data.template
  });
  if (!requestValidation.ok) {
    return requestValidation;
  }

  const resolvedAddresses = await resolveDestinationAddresses({
    normalizedHost: requestValidation.value.normalizedHost,
    hostIsIpLiteral: requestValidation.value.hostIsIpLiteral,
    template: parsedInput.data.template,
    dnsResolver: options?.dns_resolver ?? defaultDnsResolver,
    timeoutMs: dnsConfig.timeout_ms
  });
  if (!resolvedAddresses.ok) {
    return resolvedAddresses;
  }

  const outputCandidate = {
    destination: {
      scheme: requestValidation.value.parsedUrl.protocol.replace(/:$/u, '').toLowerCase(),
      host: requestValidation.value.normalizedHost,
      port: requestValidation.value.port,
      pathname: requestValidation.value.parsedUrl.pathname
    },
    resolved_ips: resolvedAddresses.value
  };

  const output = GuardExecuteRequestOutputSchema.safeParse(outputCandidate);
  /* c8 ignore next 3 -- defensive check: outputCandidate is built from validated data. */
  if (!output.success) {
    return err('invalid_input', output.error.message);
  }

  return ok(output.data);
};

export const enforceRedirectDenyPolicy = ({
  input
}: {
  input: unknown;
}): SsrfGuardResult<void> => {
  const parsedInput = GuardUpstreamResponseInputSchema.safeParse(input);
  if (!parsedInput.success) {
    return err('invalid_input', parsedInput.error.message);
  }

  if (isStatusRedirect(parsedInput.data.upstream_status_code)) {
    return err(
      'redirect_denied',
      `Upstream redirect status denied by template redirect policy: ${parsedInput.data.upstream_status_code}`
    );
  }

  return ok(undefined);
};

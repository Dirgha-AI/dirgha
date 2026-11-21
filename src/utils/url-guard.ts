/**
 * URL safety guard for SSRF prevention.
 *
 * Blocks HTTP requests to private / loopback / link-local / metadata
 * addresses unless the user explicitly opts out via
 * `DIRGHA_ALLOW_PRIVATE_FETCH=1`.
 *
 * `assertSafeFetchUrl` — sync literal-IP fast path.
 * `assertSafeFetchUrlAsync` — async variant that also resolves the
 * hostname via DNS and checks every resolved address against the same
 * private/loopback/link-local/RFC1918 blocks (DNS-rebind defence).
 */

import { lookup } from "node:dns/promises";

const LOCAL_HOSTNAMES = new Set([
  "localhost",
  "127.0.0.1",
  "::1",
  "0.0.0.0",
  "127.1",
  "[::1]",
]);

/**
 * Parse the hostname from a URL string. Returns null on parse failure.
 */
function parseHostname(url: string): string | null {
  try {
    return new URL(url).hostname;
  } catch {
    return null;
  }
}

/**
 * Return the first octet of an IPv4 address string, or -1.
 */
function firstOctet(ip: string): number {
  const dot = ip.indexOf(".");
  if (dot === -1) return -1;
  const octet = Number.parseInt(ip.slice(0, dot), 10);
  return Number.isFinite(octet) ? octet : -1;
}

/**
 * Parse an IPv4-mapped IPv6 suffix (e.g. `::ffff:127.0.0.1` or `::ffff:7f00:1`)
 * into a dotted IPv4 string, or return null if not IPv4-mapped.
 */
function extractMappedIpv4(ipv6: string): string | null {
  const lower = ipv6.toLowerCase();
  if (!lower.startsWith("::ffff:")) return null;
  const rest = lower.slice("::ffff:".length);
  if (/^\d+\.\d+\.\d+\.\d+$/.test(rest)) return rest;
  const hexMatch = /^([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(rest);
  if (!hexMatch) return null;
  const hi = Number.parseInt(hexMatch[1], 16);
  const lo = Number.parseInt(hexMatch[2], 16);
  return `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
}

/**
 * Returns one of: "loopback", "linklocal", "rfc1918", "zero", "ula", null.
 * Handles both bracketed (`[::1]`) and raw unbracketed IPv6 (`::1`, `fe80::1`,
 * `fc00::1`, `fd00::1`, `::ffff:127.0.0.1`, `::ffff:7f00:1`) returned by `dns.lookup`.
 */
function classifyIp(hostname: string): string | null {
  const raw = hostname.startsWith("[") && hostname.endsWith("]")
    ? hostname.slice(1, -1)
    : hostname;
  const lower = raw.toLowerCase();

  // IPv6 (bracketed or raw from DNS)
  if (lower.includes(":")) {
    const withoutZone = lower.split("%")[0];
    if (withoutZone === "::1" || withoutZone === "0:0:0:0:0:0:0:1") {
      return "loopback";
    }
    if (withoutZone === "::" || withoutZone === "0:0:0:0:0:0:0:0") {
      return "zero";
    }
    // IPv4-mapped IPv6 (::ffff:127.0.0.1, ::ffff:169.254.169.254, ::ffff:7f00:1)
    const mapped = extractMappedIpv4(withoutZone);
    if (mapped) {
      return classifyIp(mapped);
    }
    // Link-local fe80::/10 (fe80..febf)
    if (/^fe[89ab][0-9a-f]:/.test(withoutZone)) {
      return "linklocal";
    }
    // Unique Local Address fc00::/7 (fc00..fdff, includes AWS IMDSv2 fd00:ec2::254)
    if (/^f[cd][0-9a-f]{2}:/.test(withoutZone)) {
      return "ula";
    }
    return null;
  }

  // IPv4
  const first = firstOctet(lower);
  if (first < 0) return null;

  // 0.0.0.0/8 (0.x.x.x)
  if (first === 0) return "zero";

  // 10.0.0.0/8
  if (first === 10) return "rfc1918";

  // 127.0.0.0/8
  if (first === 127) return "loopback";

  // 169.254.0.0/16
  const parts = lower.split(".");
  if (first === 169 && parts.length >= 2) {
    const second = Number.parseInt(parts[1], 10);
    if (second === 254) return "linklocal";
  }

  // 172.16.0.0/12
  if (first === 172 && parts.length >= 2) {
    const second = Number.parseInt(parts[1], 10);
    if (second >= 16 && second <= 31) return "rfc1918";
  }

  // 192.168.0.0/16
  if (first === 192 && parts.length >= 2) {
    const second = Number.parseInt(parts[1], 10);
    if (second === 168) return "rfc1918";
  }

  // 100.64.0.0/10 (CGNAT / shared internal cloud networks)
  if (first === 100 && parts.length >= 2) {
    const second = Number.parseInt(parts[1], 10);
    if (second >= 64 && second <= 127) return "rfc1918";
  }

  return null;
}

/**
 * Throw if `url` resolves to a private / loopback / link-local / metadata
 * address. Checks the literal hostname only (no DNS). Opt out with
 * DIRGHA_ALLOW_PRIVATE_FETCH=1.
 *
 * @throws Error if the URL targets a blocked address.
 */
export function assertSafeFetchUrl(url: string): void {
  if (process.env.DIRGHA_ALLOW_PRIVATE_FETCH === "1") return;

  const hostname = parseHostname(url);
  if (hostname === null) {
    throw new Error(`SSRF guard: cannot parse URL "${url}"`);
  }

  // Check scheme — only http/https allowed for outbound fetch
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      throw new Error(
        `SSRF guard: blocked non-http(s) scheme "${parsed.protocol}" in URL "${url}"`,
      );
    }
  } catch (err) {
    if (err instanceof Error && err.message.startsWith("SSRF guard")) throw err;
    throw new Error(`SSRF guard: invalid URL "${url}"`);
  }

  // Check well-known hostnames & cloud metadata hostnames
  const lowerHost = hostname.toLowerCase();
  if (
    LOCAL_HOSTNAMES.has(lowerHost) ||
    lowerHost === "metadata.google.internal" ||
    lowerHost.endsWith(".localhost")
  ) {
    throw new Error(
      `SSRF guard: blocked fetch to loopback/metadata address "${hostname}" (set DIRGHA_ALLOW_PRIVATE_FETCH=1 to override)`,
    );
  }

  // Check IP ranges
  const classification = classifyIp(hostname);
  if (classification !== null) {
    const labels: Record<string, string> = {
      loopback: "loopback",
      linklocal: "link-local",
      rfc1918: "private (RFC1918)",
      zero: "zero-config (0.0.0.0/8)",
      ula: "private IPv6 ULA (fc00::/7)",
    };
    throw new Error(
      `SSRF guard: blocked fetch to ${labels[classification] ?? classification} address "${hostname}" (set DIRGHA_ALLOW_PRIVATE_FETCH=1 to override)`,
    );
  }
}

/**
 * True when the hostname looks like a raw IPv4 or IPv6 address.
 */
function isLiteralIp(hostname: string): boolean {
  if (hostname.startsWith("[")) return true;
  if (hostname.includes(":")) return true;
  return /^\d+\.\d+\.\d+\.\d+$/.test(hostname);
}

/**
 * Async variant that additionally resolves the hostname via DNS and
 * re-runs the private/loopback/link-local/RFC1918/IPv6 checks against
 * EVERY resolved address. Rejects if any resolved address is private
 * or if DNS resolution fails (fail-closed).
 *
 * Callers MUST also use `redirect: 'manual'` on their fetch call, OR
 * re-validate the final URL after redirects — otherwise a 301 to a
 * private address can bypass this guard.
 *
 * @throws Error if the URL or any resolved address targets a blocked address.
 */
export type DnsLookupFn = (
  hostname: string,
  options?: { all?: boolean; family?: number },
) => Promise<Array<{ address: string; family: number }>>;

export async function assertSafeFetchUrlAsync(
  url: string,
  lookupOrOpts: DnsLookupFn | { lookupFn?: DnsLookupFn } = lookup as unknown as DnsLookupFn,
): Promise<void> {
  if (process.env.DIRGHA_ALLOW_PRIVATE_FETCH === "1") return;

  // Sync fast-path first (catches literal IPs + known hostnames immediately).
  assertSafeFetchUrl(url);

  const hostname = parseHostname(url);
  if (!hostname || isLiteralIp(hostname)) return;

  const lookupFn: DnsLookupFn =
    typeof lookupOrOpts === "function"
      ? lookupOrOpts
      : (lookupOrOpts?.lookupFn ?? (lookup as unknown as DnsLookupFn));

  let addresses: { address: string; family: number }[];
  try {
    addresses = await lookupFn(hostname, { all: true, family: 0 });
  } catch (err) {
    // Fail-closed on DNS resolution failure so an attacker cannot bypass
    // checks via transient/split-horizon DNS errors.
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(
      `SSRF guard: DNS resolution failed for "${hostname}" (${msg}); refusing outbound fetch fail-closed`,
    );
  }

  for (const addr of addresses) {
    const classification = classifyIp(addr.address);
    if (classification !== null) {
      const labels: Record<string, string> = {
        loopback: "loopback",
        linklocal: "link-local",
        rfc1918: "private (RFC1918)",
        zero: "zero-config (0.0.0.0/8)",
        ula: "private IPv6 ULA (fc00::/7)",
      };
      throw new Error(
        `SSRF guard: DNS-resolved address ${addr.address} is ${labels[classification] ?? classification} for hostname "${hostname}" (set DIRGHA_ALLOW_PRIVATE_FETCH=1 to override)`,
      );
    }
  }
}

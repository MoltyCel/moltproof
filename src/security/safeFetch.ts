// SSRF-guarded fetch for DID/mandate resolution (cross-review F1–F3, 2026-07-08).
//
// Layers, defence in depth:
//   1. host allowlist  — only explicitly configured hosts may be fetched at all
//   2. scheme allowlist — https: only (blocks file:/ftp:/gopher:/data:)
//   3. DNS resolve + private/link-local/loopback/CGNAT/ULA block on every A/AAAA
//   4. no redirects     — 3xx is treated as failure (the #1 allowlist bypass)
//   5. size + time caps — bounded body, connect+total timeout
//
// RPC endpoints are NEVER derived from user input (F2): callers of this module
// pass only DID-document / status-list URLs, and only after host-allowlist check.

import { lookup } from "node:dns/promises";
import net from "node:net";

export class SsrfError extends Error {}

const PRIVATE_V4 = [
  [ip(10, 0, 0, 0), 8],
  [ip(172, 16, 0, 0), 12],
  [ip(192, 168, 0, 0), 16],
  [ip(127, 0, 0, 0), 8],
  [ip(169, 254, 0, 0), 16], // link-local (incl. cloud metadata 169.254.169.254)
  [ip(100, 64, 0, 0), 10], // CGNAT
  [ip(0, 0, 0, 0), 8],
] as const;

function ip(a: number, b: number, c: number, d: number): number {
  return ((a << 24) >>> 0) + (b << 16) + (c << 8) + d;
}
function v4ToInt(addr: string): number {
  const p = addr.split(".").map(Number);
  return ip(p[0]!, p[1]!, p[2]!, p[3]!);
}
function isPrivateV4(addr: string): boolean {
  const n = v4ToInt(addr);
  return PRIVATE_V4.some(([base, bits]) => (n >>> (32 - bits)) === (base >>> (32 - bits)));
}
function isPrivateV6(addr: string): boolean {
  const a = addr.toLowerCase();
  return (
    a === "::1" || // loopback
    a.startsWith("fe80") || // link-local
    a.startsWith("fc") || // ULA fc00::/7
    a.startsWith("fd") ||
    a.startsWith("::ffff:") // v4-mapped — re-check embedded v4
  );
}

export function isPrivateAddress(addr: string): boolean {
  if (net.isIPv4(addr)) return isPrivateV4(addr);
  if (net.isIPv6(addr)) {
    if (addr.toLowerCase().startsWith("::ffff:")) {
      const tail = addr.slice(addr.lastIndexOf(":") + 1);
      if (net.isIPv4(tail)) return isPrivateV4(tail);
    }
    return isPrivateV6(addr);
  }
  return true; // unparseable => treat as unsafe
}

export interface SafeFetchOpts {
  allowlist: string[]; // permitted hostnames (exact match)
  maxBytes?: number; // default 256 KB
  timeoutMs?: number; // default 5000
}

export async function safeFetchJson(url: string, opts: SafeFetchOpts): Promise<unknown> {
  const maxBytes = opts.maxBytes ?? 256 * 1024;
  const timeoutMs = opts.timeoutMs ?? 5000;

  let u: URL;
  try {
    u = new URL(url);
  } catch {
    throw new SsrfError("invalid url");
  }
  if (u.protocol !== "https:") throw new SsrfError(`scheme not allowed: ${u.protocol}`);
  if (!opts.allowlist.includes(u.hostname)) throw new SsrfError(`host not allowlisted: ${u.hostname}`);

  // Resolve and validate EVERY address for the host.
  const addrs = await lookup(u.hostname, { all: true });
  if (addrs.length === 0) throw new SsrfError("no dns records");
  for (const a of addrs) {
    if (isPrivateAddress(a.address)) throw new SsrfError(`resolves to private ip: ${a.address}`);
  }

  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(u, {
      redirect: "manual", // block redirect-based allowlist bypass
      signal: ctrl.signal,
      headers: { accept: "application/json,application/did+json,application/ld+json" },
    });
    if (res.status >= 300 && res.status < 400) throw new SsrfError(`redirect blocked (${res.status})`);
    if (!res.ok) throw new SsrfError(`upstream ${res.status}`);
    const len = Number(res.headers.get("content-length") ?? "0");
    if (len > maxBytes) throw new SsrfError("response too large");
    const text = await res.text();
    if (text.length > maxBytes) throw new SsrfError("response too large");
    return JSON.parse(text);
  } finally {
    clearTimeout(timer);
  }
}

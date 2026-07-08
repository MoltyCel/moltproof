import type { Mandate, MandateConstraints } from "../types.js";
import { safeFetchJson } from "../security/safeFetch.js";

// Mandate resolution. Trust boundary (cross-review F2/F3):
//  - A mandate reference is an OPAQUE id resolved via our own store or an
//    allowlisted issuer — never treated as a fetchable URL from the request.
//  - did:web is resolved ONLY against a configured host allowlist, via the
//    SSRF-guarded fetcher. We never auto-follow refreshService / credentialStatus
//    URLs (those would re-open the SSRF surface).

export class MandateError extends Error {}

/** Build a Mandate from a published AAE VC. Pure; used by the store, did:web
 *  resolution, and POST /verify alike. Rejects a VC missing required fields. */
export function parseMandateVc(vc: Record<string, unknown>): Mandate {
  const subject = (vc.credentialSubject ?? {}) as Record<string, unknown>;
  const c = (subject.constraints ?? {}) as Record<string, unknown>;

  const allowed = Array.isArray(c.allowed_venues) ? (c.allowed_venues as unknown[]).map(String) : [];
  const constraints: MandateConstraints = {
    allowed_venues: allowed,
    max_position_notional: String(c.max_position_notional ?? ""),
    valid_from: String(c.valid_from ?? ""),
    valid_until: String(c.valid_until ?? ""),
  };
  if (c.allowed_output_token) constraints.allowed_output_token = String(c.allowed_output_token);
  if (!constraints.max_position_notional || !constraints.valid_from || !constraints.valid_until) {
    throw new MandateError("mandate VC missing required constraints (max_position_notional/valid_from/valid_until)");
  }

  const agentDid = String(subject.id ?? subject.agent_did ?? "");
  if (!agentDid) throw new MandateError("mandate VC missing agent DID (credentialSubject.id)");

  const addrs = Array.isArray(subject.agent_addresses)
    ? (subject.agent_addresses as unknown[]).map(String)
    : [];

  const erc = subject.erc8004 as Record<string, unknown> | undefined;
  return {
    agent_did: agentDid,
    erc8004: erc
      ? { chainId: Number(erc.chainId), registry: String(erc.registry), agentId: String(erc.agentId) }
      : undefined,
    agent_addresses: addrs,
    constraints,
    source: { type: "inline", ref: agentDid },
    vc,
  };
}

/** Pluggable mandate store — the demonstrator/operator seeds this. */
export interface MandateStore {
  get(agentId: string): Promise<Mandate | null>;
}

/** In-memory store (also the shape a JSON-file store deserializes into). */
export class MemoryMandateStore implements MandateStore {
  private byKey = new Map<string, Mandate>();
  constructor(mandates: Mandate[] = []) {
    for (const m of mandates) this.index(m);
  }
  private index(m: Mandate): void {
    this.byKey.set(m.agent_did.toLowerCase(), m);
    for (const a of m.agent_addresses) this.byKey.set(a.toLowerCase(), m);
  }
  async get(agentId: string): Promise<Mandate | null> {
    return this.byKey.get(agentId.toLowerCase()) ?? null;
  }
  add(m: Mandate): void {
    this.index(m);
  }
  all(): Mandate[] {
    return [...new Set(this.byKey.values())];
  }
}

/** did:web -> https URL, enforced against the allowlist by safeFetchJson. */
export function didWebToUrl(did: string): string {
  // did:web:example.com:path:to -> https://example.com/path/to/did.json
  const rest = did.replace(/^did:web:/, "");
  const parts = rest.split(":").map(decodeURIComponent);
  const host = parts[0]!;
  const path = parts.slice(1).join("/");
  return path ? `https://${host}/${path}/did.json` : `https://${host}/.well-known/did.json`;
}

/**
 * Resolve a mandate for an agent id (address, did:web, or store key).
 * Order: local store first (authoritative, no network); then, for an allowlisted
 * did:web only, the SSRF-guarded did.json fetch.
 */
export async function resolveMandate(
  agentId: string,
  store: MandateStore,
  opts: { didAllowlist: string[] } = { didAllowlist: [] },
): Promise<Mandate | null> {
  const local = await store.get(agentId);
  if (local) return local;

  if (agentId.startsWith("did:web:")) {
    const url = didWebToUrl(agentId);
    const doc = (await safeFetchJson(url, { allowlist: opts.didAllowlist })) as Record<string, unknown>;
    // Look for an embedded MoltProof mandate VC in a service entry.
    const services = Array.isArray(doc.service) ? (doc.service as Record<string, unknown>[]) : [];
    const svc = services.find((s) => String(s.type ?? "").includes("MoltProofMandate"));
    const vc = svc?.mandate as Record<string, unknown> | undefined;
    if (vc) return parseMandateVc(vc);
  }
  return null;
}

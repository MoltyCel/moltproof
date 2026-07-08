import { createPrivateKey, createPublicKey } from "node:crypto";
import type { AppContext } from "./context.js";
import { computeVerdict } from "./engine/index.js";
import { recomputeVerdict, validateVerifyBody } from "./engine/recompute.js";
import { CHAINS, SUPPORTED_CHAINS, BETA_CHAINS } from "./config/chains.js";
import { KID } from "./engine/sign.js";

// Shared service layer: HTTP routes and MCP tools BOTH call these functions, so
// every guard and every piece of logic lives in one place (cross-review F10).
// Every function is pure input -> value; nothing is written to caller systems.

export function makeService(ctx: AppContext) {
  return {
    /** verdict-only (free tier). */
    async verdictFree(agent: string) {
      const r = await computeVerdict(agent, ctx);
      return {
        agent: r.agent,
        verdict: r.verdict,
        mandate_tightness: r.tightness?.score ?? null,
        recomputable: true as const,
        computedAt: nowIso(),
      };
    },

    /** full per-check breakdown (paid). */
    async verdict(agent: string) {
      const r = await computeVerdict(agent, ctx);
      return { ...r, computedAt: nowIso() };
    },

    /** verdict + decoded breaching txs (paid). */
    async evidence(agent: string) {
      const r = await computeVerdict(agent, ctx);
      return {
        agent: r.agent,
        verdict: r.verdict,
        mandate_tightness: r.tightness?.score ?? null,
        breaches: r.breaches.map((b) => ({
          txHash: b.action.txHash,
          chain: b.action.chain,
          blockNumber: b.action.blockNumber,
          timestamp: b.action.timestamp,
          venues: b.action.venues,
          notional: b.action.notional,
          failedChecks: {
            venue: b.venueCheck,
            notional: b.notionalCheck,
            validity: b.validityCheck,
          },
          reasons: b.reasons,
        })),
        needs_review: r.inconclusiveActions.map((a) => ({ txHash: a.action.txHash, reasons: a.reasons })),
        recomputable: true as const,
        computedAt: nowIso(),
      };
    },

    /** the committed mandate (free). */
    async mandate(agent: string) {
      const r = await computeVerdict(agent, ctx);
      if (!r.mandate) return { agent, mandate: null, verdict: "NO_MANDATE" as const };
      return { agent, mandate: r.mandate, mandate_tightness: r.tightness };
    },

    /** recompute + signature check (never gated, offline). */
    verify(rawBody: unknown) {
      const body = validateVerifyBody(rawBody);
      // MoltProof's own public key would be resolved from config/did:web here;
      // recompute is valid even when the key is not configured.
      return recomputeVerdict(body, ctx.signingKeyPem ? derivePublicPem(ctx.signingKeyPem) : undefined);
    },

    /** agents with committed mandates + current verdict (free). Consumption surface.
     *  Ranks NO_MANDATE / NEEDS_REVIEW lower. */
    async registry() {
      const agents = ctx.store.all();
      const rows = await Promise.all(
        agents.map(async (m) => {
          const r = await computeVerdict(m.agent_did, ctx);
          return {
            agent: m.agent_did,
            addresses: m.agent_addresses,
            verdict: r.verdict,
            mandate_tightness: r.tightness?.score ?? null,
            breaches: r.counts.breached,
          };
        }),
      );
      const rank: Record<string, number> = { ADHERENT: 0, NEEDS_REVIEW: 1, BREACHED: 2, NO_MANDATE: 3 };
      rows.sort((a, b) => (rank[a.verdict]! - rank[b.verdict]!) || (b.mandate_tightness ?? 0) - (a.mandate_tightness ?? 0));
      return { count: rows.length, agents: rows, computedAt: nowIso() };
    },

    info() {
      return {
        service: "moltproof",
        version: "0.1.0",
        description: "Read-only verifier: did an on-chain agent keep its committed AAE mandate?",
        signing_key: KID,
        aae_profile: "draft-kroehl-agentic-trust-aae-00",
        standards_alignment: ["owasp-agentic-top10"],
        chains: {
          supported: SUPPORTED_CHAINS.map((c) => c.id),
          beta: BETA_CHAINS.map((c) => c.id),
          all: CHAINS.map((c) => ({ id: c.id, status: c.status })),
        },
        constraints_v0: ["allowed_venues", "max_position_notional", "valid_from/valid_until"],
        read_only: true,
        custody: false,
      };
    },

    health() {
      return { status: "ok", read_only: true, mandates: ctx.store.all().length };
    },
  };
}

export type Service = ReturnType<typeof makeService>;

function nowIso(): string {
  return new Date().toISOString();
}

// Derive the SPKI public PEM from a private PEM (so /verify can check a signature
// against MoltProof's own key without a separate config entry).
function derivePublicPem(privatePem: string): string | undefined {
  try {
    const key = createPrivateKey(privatePem);
    return createPublicKey(key).export({ type: "spki", format: "pem" }).toString();
  } catch {
    return undefined;
  }
}

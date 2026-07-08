// MoltProof core types.
//
// Trust model: a verdict is RECOMPUTABLE from (public chain data + the public
// mandate). The Ed25519 signature is a portability convenience, never the anchor.

/** Top-level verdict for an agent against its committed mandate. */
export type Verdict =
  | "ADHERENT" // every decoded action passed every constraint; nothing undecodable
  | "BREACHED" // at least one action provably violates a constraint (cites tx)
  | "NO_MANDATE" // no committed AAE mandate resolvable for this agent
  | "NEEDS_REVIEW"; // no breach found, but some actions could not be decoded to
//                     (venue, notional, time) from a recomputable source. We never
//                     emit a silent ADHERENT over undecodable execution.

export type CheckResult = "pass" | "fail" | "inconclusive";

/** The three v0 constraints of an AAE mandate. */
export interface MandateConstraints {
  /** Checksummed contract addresses the agent is allowed to trade on. */
  allowed_venues: string[];
  /** Cap on position notional (in the mandate's quote asset / USD), as a string
   *  to preserve precision. */
  max_position_notional: string;
  /** ISO-8601 validity window. */
  valid_from: string;
  valid_until: string;
}

/** A committed mandate = a public AAE Verifiable Credential. */
export interface Mandate {
  /** The agent DID the mandate is bound to. */
  agent_did: string;
  /** ERC-8004 identity reference (chainId + registry + agentId), if present. */
  erc8004?: { chainId: number; registry: string; agentId: string };
  /** On-chain address(es) the DID resolves to (the trading account(s)). */
  agent_addresses: string[];
  constraints: MandateConstraints;
  /** Where this mandate was published (for recomputation). */
  source: { type: "did" | "erc8004" | "inline"; ref: string };
  /** Raw VC as published, for hashing / recompute. */
  vc: Record<string, unknown>;
}

/** One on-chain trading action, decoded (or not) from public data. */
export interface DecodedAction {
  chain: string;
  txHash: string;
  blockNumber: number;
  timestamp: number; // unix seconds
  /** Venue addresses this action touched: the called entrypoint plus every
   *  Swap-log emitter (pool). Empty if the action is not a recognisable trade. */
  venueAddressesTouched: string[];
  /** Resolved venue ids for the touched addresses (via the registry). */
  venues: { address: string; venueId: string | null; role: string | null }[];
  /** Position notional for this action in the quote asset, or null if not
   *  deterministically priceable from a pinned source. */
  notional: string | null;
  /** True when the action could NOT be fully decoded to (venue, notional, time)
   *  from a recomputable source — forces NEEDS_REVIEW rather than ADHERENT. */
  inconclusive: boolean;
  inconclusiveReason?: string;
}

/** Per-constraint outcome for a single action. */
export interface ActionEvaluation {
  action: DecodedAction;
  venueCheck: CheckResult;
  notionalCheck: CheckResult;
  validityCheck: CheckResult;
  /** action-level roll-up */
  status: "adherent" | "breached" | "inconclusive";
  reasons: string[];
}

/** Mandate-tightness: how constraining the mandate actually is (0 = trivially
 *  wide / gameable, 1 = tight). Always surfaced next to a verdict so an
 *  "ADHERENT" over a meaningless mandate can't be passed off as strong. */
export interface Tightness {
  score: number; // 0..1
  factors: {
    venueSpecificity: number; // narrower whitelist => higher
    notionalTightness: number; // finite, non-huge cap => higher
    windowTightness: number; // bounded, non-eternal window => higher
  };
  notes: string[];
}

export interface VerdictResult {
  agent: string;
  verdict: Verdict;
  mandate: Mandate | null;
  tightness: Tightness | null;
  /** Actions that breached, with the exact constraint each violated. */
  breaches: ActionEvaluation[];
  /** Actions that could not be decoded (drive NEEDS_REVIEW). */
  inconclusiveActions: ActionEvaluation[];
  counts: { evaluated: number; adherent: number; breached: number; inconclusive: number };
  window: { from: string; until: string } | null;
  recomputable: true;
  /** How to reproduce this verdict independently. */
  recompute: {
    method: "read public chain execution within validity window; decode venue from Swap-log emitter; check venue/notional/validity";
    chains: string[];
    mandateSource: Mandate["source"] | null;
  };
  computedAt: string;
  /** Detached Ed25519 JWS over the canonical result, if a signing key is set. */
  signature?: JwsSignature;
}

export interface JwsSignature {
  alg: "EdDSA";
  kid: "did:web:moltrust.ch#moltproof-key-1";
  /** base64url(JSON canonicalized payload) that was signed. */
  payloadDigestSha256: string;
  /** compact detached JWS: header..signature */
  jws: string;
}

/** Chain read-path maturity. Only "supported" chains may be claimed as such. */
export type ChainStatus = "supported" | "beta";
export interface ChainConfig {
  id: string;
  name: string;
  kind: "evm" | "solana" | "hyperliquid";
  chainId?: number;
  status: ChainStatus;
  rpcEnv?: string;
  note?: string;
}

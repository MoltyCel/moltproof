import type { ActionEvaluation, MandateConstraints, Tightness, Verdict } from "../types.js";

// The canonical payload that a MoltProof verdict signature is computed over.
//
// It contains ONLY fields a third party can reconstruct from public inputs (the
// agent id, the public mandate constraints, and the public on-chain actions):
// verdict, constraints, tightness, counts, and the per-tx check outcomes. It
// deliberately EXCLUDES service-local/context fields (the supported-chains list,
// wall-clock stamp, mandate source) so that POST /proof/verify, run offline by
// anyone, reproduces the exact same digest and the signature validates.

export interface SigningCoreInput {
  agent: string;
  verdict: Verdict;
  constraints: MandateConstraints | null;
  tightness: Tightness | null;
  counts: { evaluated: number; adherent: number; breached: number; inconclusive: number };
  breaches: ActionEvaluation[];
  inconclusiveActions: ActionEvaluation[];
  window: { from: string; until: string } | null;
}

export function buildSigningCore(x: SigningCoreInput): Record<string, unknown> {
  const evalToCore = (e: ActionEvaluation) => ({
    txHash: e.action.txHash,
    chain: e.action.chain,
    checks: {
      venue: e.venueCheck,
      outputToken: e.outputTokenCheck,
      notional: e.notionalCheck,
      validity: e.validityCheck,
    },
    reasons: e.reasons,
  });
  return {
    agent: x.agent,
    verdict: x.verdict,
    constraints: x.constraints,
    tightness: x.tightness,
    counts: x.counts,
    breaches: x.breaches.map(evalToCore),
    inconclusive: x.inconclusiveActions.map(evalToCore),
    window: x.window,
  };
}

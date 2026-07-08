import type { Mandate, VerdictResult } from "../types.js";
import type { ExecutionReader } from "./replay.js";
import type { MandateStore } from "./mandate.js";
import { resolveMandate } from "./mandate.js";
import { evaluateAction, rollUp } from "./evaluate.js";
import { computeTightness } from "./tightness.js";
import { signPayload } from "./sign.js";
import { buildSigningCore } from "./verdictCore.js";

export interface EngineDeps {
  store: MandateStore;
  reader: ExecutionReader;
  didAllowlist: string[];
  signingKeyPem?: string; // optional; recomputability is the anchor
  chainsUsed: string[];
}

/** Full verdict for an agent. Side-effect-free: input -> verdict + evidence. */
export async function computeVerdict(agent: string, deps: EngineDeps): Promise<VerdictResult> {
  const mandate = await resolveMandate(agent, deps.store, { didAllowlist: deps.didAllowlist });

  if (!mandate) {
    return finalize(agent, {
      verdict: "NO_MANDATE",
      mandate: null,
      tightness: null,
      breaches: [],
      inconclusiveActions: [],
      counts: { evaluated: 0, adherent: 0, breached: 0, inconclusive: 0 },
      window: null,
      chainsUsed: deps.chainsUsed,
    }, deps.signingKeyPem);
  }

  const window = { from: mandate.constraints.valid_from, until: mandate.constraints.valid_until };
  const actions = await deps.reader.read(mandate.agent_addresses.length ? mandate.agent_addresses : [agent], window);
  const evaluations = actions.map((a) => evaluateAction(a, mandate));
  const rolled = rollUp(evaluations, true);
  const tightness = computeTightness(mandate);

  return finalize(agent, {
    verdict: rolled.verdict,
    mandate,
    tightness,
    breaches: rolled.breaches,
    inconclusiveActions: rolled.inconclusiveActions,
    counts: rolled.counts,
    window,
    chainsUsed: deps.chainsUsed,
  }, deps.signingKeyPem);
}

function finalize(
  agent: string,
  r: {
    verdict: VerdictResult["verdict"];
    mandate: Mandate | null;
    tightness: VerdictResult["tightness"];
    breaches: VerdictResult["breaches"];
    inconclusiveActions: VerdictResult["inconclusiveActions"];
    counts: VerdictResult["counts"];
    window: VerdictResult["window"];
    chainsUsed: string[];
  },
  signingKeyPem?: string,
): VerdictResult {
  const result: VerdictResult = {
    agent,
    verdict: r.verdict,
    mandate: r.mandate,
    tightness: r.tightness,
    breaches: r.breaches,
    inconclusiveActions: r.inconclusiveActions,
    counts: r.counts,
    window: r.window,
    recomputable: true,
    recompute: {
      method:
        "read public chain execution within validity window; decode venue from Swap-log emitter; check venue/notional/validity",
      chains: r.chainsUsed,
      mandateSource: r.mandate?.source ?? null,
    },
    computedAt: new Date(0).toISOString(), // caller stamps real time; deterministic default for tests
  };
  if (signingKeyPem) {
    // Sign the public, reconstructable core (see verdictCore) so POST /proof/verify
    // can reproduce the exact digest offline and validate the signature.
    result.signature = signPayload(
      buildSigningCore({
        agent,
        verdict: r.verdict,
        constraints: r.mandate?.constraints ?? null,
        tightness: r.tightness,
        counts: r.counts,
        breaches: r.breaches,
        inconclusiveActions: r.inconclusiveActions,
        window: r.window,
      }),
      signingKeyPem,
    );
  }
  return result;
}

/** Payload used for signing/recompute: the result without its own signature and
 *  without the wall-clock stamp (which is not part of the recomputable claim). */
export function strip(result: VerdictResult): Omit<VerdictResult, "signature" | "computedAt"> {
  const { signature, computedAt, ...rest } = result;
  void [signature, computedAt];
  return rest;
}

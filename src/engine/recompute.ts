import type { DecodedAction, VerdictResult } from "../types.js";
import { parseMandateVc } from "./mandate.js";
import { evaluateAction, rollUp } from "./evaluate.js";
import { computeTightness } from "./tightness.js";
import { verifyPayload, type JwsSignature } from "./sign.js";
import { buildSigningCore } from "./verdictCore.js";

// POST /verify — recompute a verdict from PUBLIC inputs and, if a signature is
// supplied, check it against MoltProof's OWN published key (never a key from the
// body). Fully offline: no DID/mandate/context fetching happens here (F4). The
// body is a closed schema; unknown fields are rejected.

const ALLOWED_TOP_KEYS = new Set(["agent", "mandate", "actions", "signature"]);

export class VerifyInputError extends Error {}

export interface VerifyBody {
  agent: string;
  mandate: Record<string, unknown>; // a public AAE VC
  actions: DecodedAction[]; // public, already-decoded on-chain actions
  signature?: JwsSignature; // optional prior MoltProof signature to check
}

/** Strict, closed-schema validation. Rejects unknown top-level keys and any
 *  attempt to smuggle a URL-bearing/secret field into the offline path. */
export function validateVerifyBody(raw: unknown): VerifyBody {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new VerifyInputError("body must be an object");
  const obj = raw as Record<string, unknown>;
  for (const k of Object.keys(obj)) {
    if (!ALLOWED_TOP_KEYS.has(k)) throw new VerifyInputError(`unknown field: ${k}`);
  }
  if (typeof obj.agent !== "string") throw new VerifyInputError("agent must be a string");
  if (!obj.mandate || typeof obj.mandate !== "object") throw new VerifyInputError("mandate must be an object");
  if (!Array.isArray(obj.actions)) throw new VerifyInputError("actions must be an array");
  if (obj.actions.length > 5000) throw new VerifyInputError("too many actions");
  return {
    agent: obj.agent,
    mandate: obj.mandate as Record<string, unknown>,
    actions: obj.actions as DecodedAction[],
    signature: obj.signature as JwsSignature | undefined,
  };
}

export interface RecomputeResult {
  agent: string;
  recomputedVerdict: VerdictResult["verdict"];
  tightness: VerdictResult["tightness"];
  counts: VerdictResult["counts"];
  breaches: VerdictResult["breaches"];
  signature: { present: boolean; valid: boolean | null; note: string };
  recomputable: true;
}

/**
 * Recompute a verdict offline. `moltproofPublicKeyPem` is MoltProof's OWN key,
 * resolved from config/did:web by the caller — the body can never choose the key.
 */
export function recomputeVerdict(body: VerifyBody, moltproofPublicKeyPem?: string): RecomputeResult {
  const mandate = parseMandateVc(body.mandate); // throws on invalid VC
  const evaluations = body.actions.map((a) => evaluateAction(a, mandate));
  const rolled = rollUp(evaluations, true);
  const tightness = computeTightness(mandate);

  let sig: RecomputeResult["signature"] = { present: false, valid: null, note: "no signature supplied" };
  if (body.signature) {
    if (!moltproofPublicKeyPem) {
      sig = { present: true, valid: null, note: "MoltProof public key not configured; cannot verify (recompute still valid)" };
    } else {
      // Reconstruct the SAME public core the service signed (verdictCore) and verify.
      const core = buildSigningCore({
        agent: body.agent,
        verdict: rolled.verdict,
        constraints: mandate.constraints,
        tightness,
        counts: rolled.counts,
        breaches: rolled.breaches,
        inconclusiveActions: rolled.inconclusiveActions,
        window: { from: mandate.constraints.valid_from, until: mandate.constraints.valid_until },
      });
      const ok = verifyPayload(core, body.signature, moltproofPublicKeyPem);
      sig = { present: true, valid: ok, note: ok ? "signature valid for recomputed payload" : "signature does not match recomputed payload" };
    }
  }

  return {
    agent: body.agent,
    recomputedVerdict: rolled.verdict,
    tightness,
    counts: rolled.counts,
    breaches: rolled.breaches,
    signature: sig,
    recomputable: true,
  };
}

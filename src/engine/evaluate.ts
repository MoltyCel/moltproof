import type { ActionEvaluation, CheckResult, DecodedAction, Mandate, Verdict } from "../types.js";
import { resolveVenue, venueIdsOf } from "../config/venues.js";

/** Compare two non-negative decimal strings. Returns -1|0|1 (a vs b). */
export function compareDecimal(a: string, b: string): number {
  const [ai, af = ""] = a.trim().split(".");
  const [bi, bf = ""] = b.trim().split(".");
  const ain = BigInt(ai || "0");
  const bin = BigInt(bi || "0");
  if (ain !== bin) return ain < bin ? -1 : 1;
  const len = Math.max(af.length, bf.length);
  const afn = BigInt((af + "0".repeat(len)).slice(0, len) || "0");
  const bfn = BigInt((bf + "0".repeat(len)).slice(0, len) || "0");
  if (afn === bfn) return 0;
  return afn < bfn ? -1 : 1;
}

function withinWindow(ts: number, from: string, until: string): boolean {
  const f = Date.parse(from) / 1000;
  const u = Date.parse(until) / 1000;
  return ts >= f && ts <= u;
}

/** Venue check: every venue-address the action touched (entrypoint + Swap-log
 *  emitters) must be allowed — directly, or via its venueId (group match).
 *  An unrecognised trading address => inconclusive (never a guessed pass). */
function checkVenue(action: DecodedAction, mandate: Mandate): { result: CheckResult; reason?: string } {
  // Venue is enforced only if a whitelist is given. An empty/absent list means
  // the mandate does not constrain venue (e.g. an output-token-only mandate).
  if (!mandate.constraints.allowed_venues || mandate.constraints.allowed_venues.length === 0) {
    return { result: "pass", reason: "venue not constrained" };
  }
  const touched = action.venueAddressesTouched;
  if (touched.length === 0) {
    return action.inconclusive
      ? { result: "inconclusive", reason: action.inconclusiveReason ?? "action not decodable to a venue" }
      : { result: "pass", reason: "no venue interaction" };
  }
  const allowedAddrs = new Set(mandate.constraints.allowed_venues.map((a) => a.toLowerCase()));
  const allowedVenueIds = venueIdsOf(mandate.constraints.allowed_venues);

  for (const addr of touched) {
    const low = addr.toLowerCase();
    if (allowedAddrs.has(low)) continue; // directly whitelisted
    const v = resolveVenue(addr);
    if (v && allowedVenueIds.has(v.venueId)) continue; // same venue, different router
    if (!v) return { result: "inconclusive", reason: `unrecognised venue address ${addr}` };
    return { result: "fail", reason: `traded on non-whitelisted venue ${v.venueId} (${addr})` };
  }
  return { result: "pass" };
}

function checkNotional(action: DecodedAction, mandate: Mandate): { result: CheckResult; reason?: string } {
  if (action.notional == null) {
    return { result: "inconclusive", reason: "notional not deterministically priceable" };
  }
  const cap = mandate.constraints.max_position_notional;
  if (compareDecimal(action.notional, cap) > 0) {
    return { result: "fail", reason: `position notional ${action.notional} exceeds cap ${cap}` };
  }
  return { result: "pass" };
}

function checkValidity(action: DecodedAction, mandate: Mandate): { result: CheckResult; reason?: string } {
  const { valid_from, valid_until } = mandate.constraints;
  if (!withinWindow(action.timestamp, valid_from, valid_until)) {
    return { result: "fail", reason: `acted outside mandate validity window (${valid_from}..${valid_until})` };
  }
  return { result: "pass" };
}

/** Output-token check: the acquired (swap-output) token must equal the single
 *  allowed token. Read from the swap event, so it is independent of venue/router
 *  recognition (holds under 7702 self-execution). Enforced only if the mandate
 *  pins an allowed_output_token; an undecoded out-token is inconclusive. */
function checkOutputToken(action: DecodedAction, mandate: Mandate): { result: CheckResult; reason?: string } {
  const allowed = mandate.constraints.allowed_output_token;
  if (!allowed) return { result: "pass" }; // not constrained
  if (action.outputToken == null) {
    return { result: "inconclusive", reason: "output token not decodable from the swap" };
  }
  if (action.outputToken.toLowerCase() === allowed.toLowerCase()) return { result: "pass" };
  return { result: "fail", reason: `acquired ${action.outputToken}; mandate allows only ${allowed}` };
}

export function evaluateAction(action: DecodedAction, mandate: Mandate): ActionEvaluation {
  const venue = checkVenue(action, mandate);
  const outputToken = checkOutputToken(action, mandate);
  const notional = checkNotional(action, mandate);
  const validity = checkValidity(action, mandate);
  const results = [venue.result, outputToken.result, notional.result, validity.result];
  const reasons = [venue.reason, outputToken.reason, notional.reason, validity.reason].filter(Boolean) as string[];

  let status: ActionEvaluation["status"];
  if (results.includes("fail")) status = "breached";
  else if (results.includes("inconclusive") || action.inconclusive) status = "inconclusive";
  else status = "adherent";

  return {
    action,
    venueCheck: venue.result,
    outputTokenCheck: outputToken.result,
    notionalCheck: notional.result,
    validityCheck: validity.result,
    status,
    reasons,
  };
}

export interface EvaluationRollup {
  verdict: Verdict;
  evaluations: ActionEvaluation[];
  breaches: ActionEvaluation[];
  inconclusiveActions: ActionEvaluation[];
  counts: { evaluated: number; adherent: number; breached: number; inconclusive: number };
}

/** Roll individual action evaluations up into a top-level verdict.
 *  BREACHED dominates; otherwise any undecodable action forces NEEDS_REVIEW so we
 *  never emit a silent ADHERENT over execution we could not decode. */
export function rollUp(evaluations: ActionEvaluation[], hasMandate: boolean): EvaluationRollup {
  if (!hasMandate) {
    return {
      verdict: "NO_MANDATE",
      evaluations,
      breaches: [],
      inconclusiveActions: [],
      counts: { evaluated: 0, adherent: 0, breached: 0, inconclusive: 0 },
    };
  }
  const breaches = evaluations.filter((e) => e.status === "breached");
  const inconclusiveActions = evaluations.filter((e) => e.status === "inconclusive");
  const adherent = evaluations.filter((e) => e.status === "adherent");
  let verdict: Verdict;
  if (breaches.length > 0) verdict = "BREACHED";
  else if (inconclusiveActions.length > 0) verdict = "NEEDS_REVIEW";
  else verdict = "ADHERENT";
  return {
    verdict,
    evaluations,
    breaches,
    inconclusiveActions,
    counts: {
      evaluated: evaluations.length,
      adherent: adherent.length,
      breached: breaches.length,
      inconclusive: inconclusiveActions.length,
    },
  };
}

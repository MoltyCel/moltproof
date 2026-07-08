import { describe, it, expect } from "vitest";
import { evaluateAction, rollUp } from "../src/engine/evaluate.js";
import { computeTightness } from "../src/engine/tightness.js";
import type { DecodedAction, Mandate } from "../src/types.js";

const WETH = "0x4200000000000000000000000000000000000006";
const USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";

// Output-token-only mandate: no venue list (venue not enforced), pin WETH.
function mandate(over: Partial<Mandate["constraints"]> = {}): Mandate {
  return {
    agent_did: "did:moltrust:agentA",
    agent_addresses: ["0xagent"],
    constraints: {
      allowed_venues: [],
      allowed_output_token: WETH,
      max_position_notional: "20",
      valid_from: "2026-07-08T00:00:00Z",
      valid_until: "2026-07-15T00:00:00Z",
      ...over,
    },
    source: { type: "inline", ref: "did:moltrust:agentA" },
    vc: {},
  };
}

// A 7702-self-routed action: venueAddressesTouched is the EOA / an unknown pool,
// which the venue check would normally flag — here venue is NOT enforced.
function action(outputToken: string | null, over: Partial<DecodedAction> = {}): DecodedAction {
  return {
    chain: "base",
    txHash: "0x" + "1".repeat(64),
    blockNumber: 48377373,
    timestamp: Date.parse("2026-07-08T20:54:53Z") / 1000,
    venueAddressesTouched: ["0xd35ae5c22c117cf1b9ef870697ab0034314a59e2"], // EOA (7702)
    venues: [{ address: "0xd35a…", venueId: null, role: null }],
    notional: "5",
    outputToken,
    inconclusive: false,
    ...over,
  };
}

describe("output-token constraint", () => {
  it("ADHERENT: bought the allowed token (WETH) — venue irrelevant / 7702-routed", () => {
    const e = evaluateAction(action(WETH), mandate());
    expect(e.venueCheck).toBe("pass"); // venue not enforced (empty whitelist)
    expect(e.outputTokenCheck).toBe("pass");
    expect(e.status).toBe("adherent");
  });

  it("BREACHED: bought a non-allowed token (USDC)", () => {
    const e = evaluateAction(action(USDC, { notional: "14.97" }), mandate());
    expect(e.outputTokenCheck).toBe("fail");
    expect(e.status).toBe("breached");
    expect(e.reasons.join(" ")).toContain("allows only");
  });

  it("case-insensitive token match", () => {
    const e = evaluateAction(action(WETH.toLowerCase()), mandate());
    expect(e.status).toBe("adherent");
  });

  it("INCONCLUSIVE: out-token not decodable", () => {
    const e = evaluateAction(action(null), mandate());
    expect(e.outputTokenCheck).toBe("inconclusive");
    expect(e.status).toBe("inconclusive");
  });

  it("not enforced when allowed_output_token absent", () => {
    const m = mandate({ allowed_output_token: undefined });
    const e = evaluateAction(action(USDC), m);
    expect(e.outputTokenCheck).toBe("pass");
    expect(e.status).toBe("adherent");
  });

  it("venue check is a no-op when allowed_venues is empty (7702 EOA touched)", () => {
    // recognised non-whitelisted venue would normally fail; empty list => pass
    const e = evaluateAction(action(WETH), mandate({ allowed_venues: [] }));
    expect(e.venueCheck).toBe("pass");
  });

  it("roll-up: 3 WETH adherent + 1 USDC breach => BREACHED with cited tx", () => {
    const evals = [
      evaluateAction(action(WETH, { txHash: "0xa" }), mandate()),
      evaluateAction(action(WETH, { txHash: "0xb" }), mandate()),
      evaluateAction(action(WETH, { txHash: "0xc" }), mandate()),
      evaluateAction(action(USDC, { txHash: "0xbreach", notional: "14.97" }), mandate()),
    ];
    const r = rollUp(evals, true);
    expect(r.verdict).toBe("BREACHED");
    expect(r.counts.adherent).toBe(3);
    expect(r.counts.breached).toBe(1);
    expect(r.breaches[0]!.action.txHash).toBe("0xbreach");
  });
});

describe("tightness reflects the output-token constraint", () => {
  it("output-token-only mandate is not scored as zero-specificity", () => {
    const t = computeTightness(mandate());
    expect(t.factors.venueSpecificity).toBeGreaterThan(0);
    expect(t.notes.join(" ")).toContain("allowed_output_token");
  });
  it("no venue and no output-token => zero specificity + note", () => {
    const t = computeTightness(mandate({ allowed_venues: [], allowed_output_token: undefined }));
    expect(t.factors.venueSpecificity).toBe(0);
    expect(t.notes.join(" ")).toContain("any trade allowed");
  });
});

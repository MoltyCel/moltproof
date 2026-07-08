import { describe, it, expect } from "vitest";
import { evaluateAction, rollUp, compareDecimal } from "../src/engine/evaluate.js";
import type { DecodedAction, Mandate } from "../src/types.js";

const UNI_ROUTER = "0x6fF5693b99212Da76ad316178A184AB56D299b43"; // uniswap (registry)
const AERO_ROUTER = "0xcF77a3Ba9A5CA399B7c97c74d54e5b1Beb874E43"; // aerodrome (registry)
const UNKNOWN = "0x9999999999999999999999999999999999999999";

function mandate(over: Partial<Mandate["constraints"]> = {}): Mandate {
  return {
    agent_did: "did:moltrust:agentA",
    agent_addresses: ["0xagent"],
    constraints: {
      allowed_venues: [UNI_ROUTER],
      max_position_notional: "10000",
      valid_from: "2026-01-01T00:00:00Z",
      valid_until: "2026-02-01T00:00:00Z",
      ...over,
    },
    source: { type: "inline", ref: "did:moltrust:agentA" },
    vc: {},
  };
}

function action(over: Partial<DecodedAction> = {}): DecodedAction {
  return {
    chain: "base",
    txHash: "0x" + "1".repeat(64),
    blockNumber: 100,
    timestamp: Date.parse("2026-01-15T00:00:00Z") / 1000,
    venueAddressesTouched: [UNI_ROUTER],
    venues: [{ address: UNI_ROUTER, venueId: "uniswap", role: "router" }],
    notional: "500",
    inconclusive: false,
    ...over,
  };
}

describe("compareDecimal", () => {
  it("compares integers and fractionals", () => {
    expect(compareDecimal("500", "10000")).toBe(-1);
    expect(compareDecimal("10000", "10000")).toBe(0);
    expect(compareDecimal("10000.5", "10000.4")).toBe(1);
    expect(compareDecimal("2", "10")).toBe(-1);
  });
});

describe("evaluateAction", () => {
  it("ADHERENT: within venue, under cap, in window", () => {
    const e = evaluateAction(action(), mandate());
    expect(e.status).toBe("adherent");
  });

  it("BREACHED (venue): traded on a recognised but non-whitelisted venue", () => {
    const e = evaluateAction(
      action({ venueAddressesTouched: [AERO_ROUTER], venues: [{ address: AERO_ROUTER, venueId: "aerodrome", role: "router" }] }),
      mandate(),
    );
    expect(e.status).toBe("breached");
    expect(e.venueCheck).toBe("fail");
  });

  it("group match: a different Uniswap router is still adherent", () => {
    const otherUniRouter = "0x2626664c2603336E57B271c5C0b26F421741e481"; // SwapRouter02, same venueId
    const e = evaluateAction(
      action({ venueAddressesTouched: [otherUniRouter], venues: [{ address: otherUniRouter, venueId: "uniswap", role: "router" }] }),
      mandate(),
    );
    expect(e.status).toBe("adherent");
  });

  it("BREACHED (notional): over the position cap", () => {
    const e = evaluateAction(action({ notional: "50000" }), mandate());
    expect(e.status).toBe("breached");
    expect(e.notionalCheck).toBe("fail");
  });

  it("BREACHED (validity): acted outside the window", () => {
    const e = evaluateAction(action({ timestamp: Date.parse("2026-03-01T00:00:00Z") / 1000 }), mandate());
    expect(e.status).toBe("breached");
    expect(e.validityCheck).toBe("fail");
  });

  it("INCONCLUSIVE: unrecognised venue -> not a guessed pass", () => {
    const e = evaluateAction(
      action({ venueAddressesTouched: [UNKNOWN], venues: [{ address: UNKNOWN, venueId: null, role: null }] }),
      mandate(),
    );
    expect(e.status).toBe("inconclusive");
    expect(e.venueCheck).toBe("inconclusive");
  });

  it("INCONCLUSIVE: notional not priceable", () => {
    const e = evaluateAction(action({ notional: null }), mandate());
    expect(e.status).toBe("inconclusive");
    expect(e.notionalCheck).toBe("inconclusive");
  });
});

describe("rollUp", () => {
  it("NO_MANDATE when no mandate", () => {
    expect(rollUp([], false).verdict).toBe("NO_MANDATE");
  });
  it("ADHERENT when all pass", () => {
    const e = [evaluateAction(action(), mandate())];
    expect(rollUp(e, true).verdict).toBe("ADHERENT");
  });
  it("BREACHED dominates NEEDS_REVIEW", () => {
    const e = [
      evaluateAction(action({ notional: "50000" }), mandate()), // breach
      evaluateAction(action({ notional: null }), mandate()), // inconclusive
    ];
    expect(rollUp(e, true).verdict).toBe("BREACHED");
  });
  it("NEEDS_REVIEW when no breach but something undecodable", () => {
    const e = [evaluateAction(action(), mandate()), evaluateAction(action({ notional: null }), mandate())];
    expect(rollUp(e, true).verdict).toBe("NEEDS_REVIEW");
  });
});

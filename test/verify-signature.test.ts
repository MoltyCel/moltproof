import { describe, it, expect } from "vitest";
import crypto from "node:crypto";
import { computeVerdict } from "../src/engine/index.js";
import { recomputeVerdict } from "../src/engine/recompute.js";
import { MemoryMandateStore } from "../src/engine/mandate.js";
import { StaticReader } from "../src/engine/replay.js";
import type { DecodedAction, Mandate } from "../src/types.js";

const WETH = "0x4200000000000000000000000000000000000006";
const USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const AGENT = "0xd35ae5c22c117cf1b9ef870697ab0034314a59e2";

function keys() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  return {
    priv: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    pub: publicKey.export({ type: "spki", format: "pem" }).toString(),
  };
}

const constraints = {
  allowed_venues: [] as string[],
  allowed_output_token: WETH,
  max_position_notional: "20",
  valid_from: "2026-07-08T00:00:00Z",
  valid_until: "2026-07-15T00:00:00Z",
};
const vc = { credentialSubject: { id: `did:moltrust:${AGENT}`, agent_addresses: [AGENT], constraints } };
const mandate: Mandate = {
  agent_did: `did:moltrust:${AGENT}`,
  agent_addresses: [AGENT],
  constraints,
  source: { type: "inline", ref: `did:moltrust:${AGENT}` },
  vc,
};
function act(out: string, over: Partial<DecodedAction> = {}): DecodedAction {
  return {
    chain: "base", txHash: "0x" + "1".repeat(64), blockNumber: 1,
    timestamp: Date.parse("2026-07-08T20:54:53Z") / 1000,
    venueAddressesTouched: [], venues: [], notional: "5", outputToken: out, inconclusive: false, ...over,
  };
}

describe("verdict signature validates through /verify (public core)", () => {
  it("recompute reproduces the signed core → signature valid", async () => {
    const { priv, pub } = keys();
    const actions = [act(WETH, { txHash: "0xa" }), act(USDC, { txHash: "0xbreach", notional: "14.97" })];
    const result = await computeVerdict(AGENT, {
      store: new MemoryMandateStore([mandate]),
      reader: new StaticReader(actions),
      didAllowlist: [],
      signingKeyPem: priv,
      chainsUsed: ["base", "ethereum"], // service-local; must NOT affect the signature
    });
    expect(result.verdict).toBe("BREACHED");
    expect(result.signature).toBeDefined();

    const rec = recomputeVerdict({ agent: AGENT, mandate: vc, actions, signature: result.signature }, pub);
    expect(rec.recomputedVerdict).toBe("BREACHED");
    expect(rec.signature.valid).toBe(true);
  });

  it("a tampered actions set → signature no longer valid", async () => {
    const { priv, pub } = keys();
    const actions = [act(WETH, { txHash: "0xa" })];
    const result = await computeVerdict(AGENT, {
      store: new MemoryMandateStore([mandate]),
      reader: new StaticReader(actions),
      didAllowlist: [], signingKeyPem: priv, chainsUsed: ["base"],
    });
    // recompute over a DIFFERENT action set (adds a breach) must not validate the old signature
    const tampered = [...actions, act(USDC, { txHash: "0xb", notional: "1" })];
    const rec = recomputeVerdict({ agent: AGENT, mandate: vc, actions: tampered, signature: result.signature }, pub);
    expect(rec.signature.valid).toBe(false);
  });
});

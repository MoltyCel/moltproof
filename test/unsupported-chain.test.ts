import { describe, it, expect } from "vitest";
import crypto from "node:crypto";
import { computeVerdict } from "../src/engine/index.js";
import { recomputeVerdict, validateVerifyBody, VerifyInputError } from "../src/engine/recompute.js";
import { MemoryMandateStore } from "../src/engine/mandate.js";
import { StaticReader, EvmSwapReader } from "../src/engine/replay.js";
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

function deps(reader: any, priv: string) {
  return {
    store: new MemoryMandateStore([mandate]),
    reader,
    didAllowlist: [] as string[],
    signingKeyPem: priv,
    chainsUsed: ["base"],
  };
}

// (1) A chain declared in the registry but without a decoder in this build must
//     not roll up to ADHERENT. Nothing was observed, so nothing is attested.
describe("unsupported chain does not yield a silent ADHERENT", () => {
  for (const chainId of ["solana", "hyperliquid"]) {
    it(`${chainId}: reader reports unsupported`, async () => {
      // The guard runs before any network access, so no RPC is contacted here.
      const r = await new EvmSwapReader(chainId, "http://127.0.0.1:1").read([AGENT], {
        from: constraints.valid_from,
        until: constraints.valid_until,
      });
      expect(r.unsupported).toBe(true);
      expect(r.actions).toEqual([]);
    });

    it(`${chainId}: computeVerdict returns NEEDS_REVIEW, not ADHERENT`, async () => {
      const { priv } = keys();
      const result = await computeVerdict(AGENT, deps(new EvmSwapReader(chainId, "http://127.0.0.1:1"), priv));
      expect(result.verdict).toBe("NEEDS_REVIEW");
      expect(result.verdict).not.toBe("ADHERENT");
      expect(result.counts.evaluated).toBe(0);
    });
  }
});

// (2) The observed-but-empty case is deliberately unchanged. An agent on a
//     supported chain that genuinely did nothing still rolls up as before.
//     Changing this is a spec question (-02), not part of this fix.
describe("observed-but-empty window is unchanged", () => {
  it("supported chain, agent idle -> still ADHERENT", async () => {
    const { priv } = keys();
    const result = await computeVerdict(AGENT, deps(new StaticReader([]), priv));
    expect(result.verdict).toBe("ADHERENT");
    expect(result.counts.evaluated).toBe(0);
  });
});

// (3) The offline /verify path never sees the reader, so it needs its own guard:
//     a caller must not be able to mint a signed clean verdict by sending nothing.
describe("offline /verify rejects an empty action list", () => {
  const body = { agent: AGENT, mandate: vc, actions: [] as DecodedAction[] };

  it("validateVerifyBody throws on actions: []", () => {
    expect(() => validateVerifyBody(body)).toThrow(VerifyInputError);
    expect(() => validateVerifyBody(body)).toThrow(/must not be empty/);
  });

  it("a non-empty list still validates", () => {
    const ok = validateVerifyBody({ ...body, actions: [act(WETH)] });
    expect(ok.actions).toHaveLength(1);
  });

  it("the >5000 guard still applies", () => {
    const many = Array.from({ length: 5001 }, () => act(WETH));
    expect(() => validateVerifyBody({ ...body, actions: many })).toThrow(/too many actions/);
  });
});

// (4) A failing chain read must stay loud. withTimeout rejects; the read must
//     not degrade into an empty result that looks like an idle agent.
describe("a failing chain read throws rather than reading empty", () => {
  it("supported chain, unreachable RPC -> rejects", async () => {
    const reader = new EvmSwapReader("base", "http://127.0.0.1:1", 10n, 50);
    await expect(
      reader.read([AGENT], { from: constraints.valid_from, until: constraints.valid_until }),
    ).rejects.toBeTruthy();
  });
});

// (5) The verdicts that already worked must keep working through the new
//     reader shape.
describe("existing verdicts unchanged through the new reader shape", () => {
  it("breach still BREACHED and still recomputes", async () => {
    const { priv, pub } = keys();
    const actions = [act(WETH, { txHash: "0xa" }), act(USDC, { txHash: "0xbreach", notional: "14.97" })];
    const result = await computeVerdict(AGENT, deps(new StaticReader(actions), priv));
    expect(result.verdict).toBe("BREACHED");

    const rec = recomputeVerdict({ agent: AGENT, mandate: vc, actions, signature: result.signature }, pub);
    expect(rec.recomputedVerdict).toBe("BREACHED");
    expect(rec.signature.valid).toBe(true);
  });

  it("clean actions still ADHERENT", async () => {
    const { priv } = keys();
    const result = await computeVerdict(AGENT, deps(new StaticReader([act(WETH, { txHash: "0xa" })]), priv));
    expect(result.verdict).toBe("ADHERENT");
    expect(result.counts.evaluated).toBe(1);
  });

  it("unknown agent still NO_MANDATE", async () => {
    const { priv } = keys();
    const result = await computeVerdict("0x" + "9".repeat(40), {
      store: new MemoryMandateStore([mandate]),
      reader: new StaticReader([]),
      didAllowlist: [],
      signingKeyPem: priv,
      chainsUsed: ["base"],
    });
    expect(result.verdict).toBe("NO_MANDATE");
  });
});

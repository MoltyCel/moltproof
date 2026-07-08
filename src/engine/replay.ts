import type { DecodedAction } from "../types.js";
import { resolveVenue } from "../config/venues.js";
import { getChain } from "../config/chains.js";

// Execution replay = read PUBLIC on-chain execution for the agent within the
// validity window. Bounded by construction (cross-review F7): fixed lookback,
// no caller-controlled ranges, per-call timeout. The reader is an interface so
// the engine is testable offline and so live chain access is a swappable edge.

export interface ExecutionWindow {
  from: string; // ISO
  until: string; // ISO
}

export interface ExecutionReader {
  /** Read decoded trading actions for the given addresses within the window. */
  read(addresses: string[], window: ExecutionWindow): Promise<DecodedAction[]>;
}

/** Deterministic reader for tests and for the seeded demonstrator record.
 *  Actions are pre-associated with the agent; out-of-window actions are kept so
 *  the validity check can flag them. */
export class StaticReader implements ExecutionReader {
  constructor(private actions: DecodedAction[]) {}
  async read(_addresses: string[], _window: ExecutionWindow): Promise<DecodedAction[]> {
    return [...this.actions];
  }
}

// Uniswap V2/V3 Swap event signatures (pool-emitted; robust to routers).
export const SWAP_EVENT_V3 =
  "event Swap(address indexed sender, address indexed recipient, int256 amount0, int256 amount1, uint160 sqrtPriceX96, uint128 liquidity, int24 tick)";
export const SWAP_EVENT_V2 =
  "event Swap(address indexed sender, uint256 amount0In, uint256 amount1In, uint256 amount0Out, uint256 amount1Out, address indexed to)";

/**
 * Live EVM reader: decode venue from the Swap-log EMITTER (the pool), never the
 * top-level `to`, so router/aggregator/proxy calls still resolve to the true
 * venue (cross-review A). Notional is left null unless a pinned price source is
 * configured — an un-priceable action becomes an inconclusive notional check,
 * never a silent ADHERENT. This path requires a configured read-only RPC and is
 * exercised by the demonstrator, not by offline unit tests.
 */
export class EvmSwapReader implements ExecutionReader {
  constructor(
    private chainId: string,
    private rpcUrl: string,
    private lookbackBlocks = 50_000n,
    private timeoutMs = 8_000,
  ) {}

  async read(addresses: string[], _window: ExecutionWindow): Promise<DecodedAction[]> {
    const chain = getChain(this.chainId);
    if (!chain || chain.kind !== "evm") return [];
    // Lazy import so offline tests never touch viem's network stack.
    const viem = await import("viem");
    const client = viem.createPublicClient({ transport: viem.http(this.rpcUrl) });

    const latest = await withTimeout(client.getBlockNumber(), this.timeoutMs);
    const fromBlock = latest > this.lookbackBlocks ? latest - this.lookbackBlocks : 0n;
    const wanted = new Set(addresses.map((a) => a.toLowerCase()));

    const logs = await withTimeout(
      client.getLogs({
        event: viem.parseAbiItem(SWAP_EVENT_V3) as never,
        fromBlock,
        toBlock: latest,
      }),
      this.timeoutMs,
    );

    const out: DecodedAction[] = [];
    for (const log of logs as { address: string; topics: string[]; transactionHash: string; blockNumber: bigint; args?: Record<string, unknown> }[]) {
      const sender = String((log.args?.sender ?? "")).toLowerCase();
      const recipient = String((log.args?.recipient ?? "")).toLowerCase();
      if (!wanted.has(sender) && !wanted.has(recipient)) continue;
      const emitter = log.address;
      const block = await withTimeout(client.getBlock({ blockNumber: log.blockNumber }), this.timeoutMs);
      out.push({
        chain: this.chainId,
        txHash: log.transactionHash,
        blockNumber: Number(log.blockNumber),
        timestamp: Number(block.timestamp),
        venueAddressesTouched: [emitter],
        venues: [{ address: emitter, ...venueMeta(emitter) }],
        notional: null, // pinned-price source not configured in v0 => inconclusive
        inconclusive: false,
        inconclusiveReason: undefined,
      });
    }
    return out;
  }
}

function venueMeta(address: string): { venueId: string | null; role: string | null } {
  const v = resolveVenue(address);
  return { venueId: v?.venueId ?? null, role: v?.role ?? null };
}

async function withTimeout<T>(p: Promise<T>, ms: number): Promise<T> {
  let t: ReturnType<typeof setTimeout>;
  const timeout = new Promise<never>((_, rej) => {
    t = setTimeout(() => rej(new Error("chain read timeout")), ms);
  });
  try {
    return await Promise.race([p, timeout]);
  } finally {
    clearTimeout(t!);
  }
}

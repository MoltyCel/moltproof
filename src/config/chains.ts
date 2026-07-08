import type { ChainConfig } from "../types.js";

// Read-path maturity per cross-review (2026-07-08):
//  - EVM: SUPPORTED — decode venue from the pool Swap-log emitter (not tx.to),
//    so routers/aggregators/proxies still resolve to the true venue.
//  - Hyperliquid: SUPPORTED — native userFillsByTime; notional = px*sz (no oracle).
//  - Solana: BETA — per-program IDL maintenance + aggregator-route disambiguation
//    is not reliably recomputable in v0.
export const CHAINS: ChainConfig[] = [
  { id: "base", name: "Base", kind: "evm", chainId: 8453, status: "supported", rpcEnv: "RPC_BASE", note: "canonical" },
  { id: "ethereum", name: "Ethereum", kind: "evm", chainId: 1, status: "supported", rpcEnv: "RPC_ETHEREUM" },
  { id: "arbitrum", name: "Arbitrum", kind: "evm", chainId: 42161, status: "supported", rpcEnv: "RPC_ARBITRUM" },
  { id: "optimism", name: "Optimism", kind: "evm", chainId: 10, status: "supported", rpcEnv: "RPC_OPTIMISM" },
  { id: "polygon", name: "Polygon", kind: "evm", chainId: 137, status: "supported", rpcEnv: "RPC_POLYGON" },
  { id: "hyperliquid", name: "Hyperliquid", kind: "hyperliquid", status: "supported", rpcEnv: "HYPERLIQUID_INFO_URL" },
  { id: "solana", name: "Solana", kind: "solana", status: "beta", note: "decode path in progress; verdicts labelled beta" },
];

export const SUPPORTED_CHAINS = CHAINS.filter((c) => c.status === "supported");
export const BETA_CHAINS = CHAINS.filter((c) => c.status === "beta");

export function getChain(id: string): ChainConfig | undefined {
  return CHAINS.find((c) => c.id === id.toLowerCase());
}

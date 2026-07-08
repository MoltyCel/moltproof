// Venue registry: checksummed contract address -> canonical venue.
//
// Per cross-review (2026-07-08): one venue exposes MANY entrypoints (routers +
// pool manager), and the address an agent's tx TOUCHES may be the router (tx.to)
// OR a pool that emits the Swap log. We therefore match BOTH the entrypoint and
// the Swap-log emitters, and resolve them to a venueId here. An address that is
// not in this registry AND not in the mandate's allowed_venues is "unrecognised"
// — never guessed. Addresses below are explorer/official-doc verified on Base.
//
// Sources (accessed 2026-07-08):
//   Uniswap Base v3 deployments — developers.uniswap.org/contracts/v3/reference/deployments/base-deployments
//   Uniswap v4 deployments      — developers.uniswap.org/contracts/v4/deployments
//   universal-router deploy JSON — github.com/Uniswap/universal-router/tree/main/deploy-addresses
//   Aerodrome contracts + Basescan verified "Aerodrome: Router"

export interface VenueEntry {
  venueId: string; // canonical venue name
  role: "router" | "poolmanager" | "pool" | "factory";
  chain: string;
  source: string;
}

// key = lowercased address (we compare lowercased to avoid checksum mismatches)
export const VENUE_REGISTRY: Record<string, VenueEntry> = {
  "0x6ff5693b99212da76ad316178a184ab56d299b43": {
    venueId: "uniswap",
    role: "router",
    chain: "base",
    source: "uniswap-docs:base-v3/v4 UniversalRouter",
  },
  "0xfdf682f51fe81aa4898f0ae2163d8a55c127fbc7": {
    venueId: "uniswap",
    role: "router",
    chain: "base",
    source: "uniswap:universal-router/deploy-addresses/base.json v2.1.1",
  },
  "0x2626664c2603336e57b271c5c0b26f421741e481": {
    venueId: "uniswap",
    role: "router",
    chain: "base",
    source: "uniswap-docs:base SwapRouter02 (legacy v3)",
  },
  "0x498581ff718922c3f8e6a244956af099b2652b2b": {
    venueId: "uniswap",
    role: "poolmanager",
    chain: "base",
    source: "uniswap-docs:base v4 PoolManager (singleton)",
  },
  "0xcf77a3ba9a5ca399b7c97c74d54e5b1beb874e43": {
    venueId: "aerodrome",
    role: "router",
    chain: "base",
    source: "aerodrome-finance/contracts + basescan verified 'Aerodrome: Router'",
  },
};

export function resolveVenue(address: string): VenueEntry | null {
  return VENUE_REGISTRY[address.toLowerCase()] ?? null;
}

/** venueIds represented by a set of allowed_venues addresses (group match). */
export function venueIdsOf(addresses: string[]): Set<string> {
  const ids = new Set<string>();
  for (const a of addresses) {
    const v = resolveVenue(a);
    if (v) ids.add(v.venueId);
  }
  return ids;
}

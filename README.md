# MoltProof

**Read-only verifier: did an on-chain trading agent keep its publicly committed mandate?**

MoltProof resolves an agent's on-chain address(es) from its DID / ERC-8004
identity, reads its public execution within the mandate's validity window, and
checks each action against a signed public **AAE mandate** (allowed venues,
position cap, validity). It emits `ADHERENT` / `BREACHED` / `NO_MANDATE` /
`NEEDS_REVIEW`, cites the exact breaching transactions, and scores how tight the
mandate is so an "adherent" over a trivially-wide mandate can't be passed off as
strong.

Every verdict is **recomputable** from public chain data + the public mandate.
Verdicts are signed (Ed25519 JWS, `did:web:moltrust.ch#moltproof-key-1`) for
portability — the signature is a convenience; **recomputability is the trust
anchor**.

## What it does NOT do (hard gates)

- Accepts **only public inputs** (agent address / DID / mandate ref). It does not
  accept, request, store, or log any private key, API key, seed, or wallet
  connection — enforced by a scanner and an **automated build-gating test**
  (`test/no-secret-route.test.ts`).
- **No execution, no signing on behalf of users, no custody.** Read-only RPC /
  indexer calls only.
- **Side-effect-free**: input → verdict + evidence. Nothing is written to caller
  systems.

## Constraints (v0)

1. `allowed_venues` — contract addresses the agent may trade on
2. `max_position_notional` — position cap in the mandate's quote asset
3. `valid_from` / `valid_until` — validity window

## Chains

| Chain | Read path | v0 status |
|---|---|---|
| Base (canonical), Ethereum, Arbitrum, Optimism, Polygon | EVM Swap-log emitter decode | **supported** |
| Hyperliquid | native `userFillsByTime` (px·sz notional) | **supported** |
| Solana | program-ID / inner-instruction decode | **beta** |

Venue is decoded from the **pool `Swap` log emitter**, not `tx.to`, so router /
aggregator / proxy calls still resolve to the true venue. An action that can't be
decoded to (venue, notional, time) from a recomputable source becomes
**`NEEDS_REVIEW`**, never a silent `ADHERENT`.

## API (base `/proof`)

| Method | Path | Tier |
|---|---|---|
| GET | `/proof/verdict-free/:agent` | free (1 / 10 min) — verdict only |
| GET | `/proof/verdict/:agent` | $0.05 — full per-check breakdown |
| GET | `/proof/evidence/:agent` | $0.05 — verdict + decoded breaching txs |
| GET | `/proof/mandate/:agent` | free — the committed AAE mandate |
| POST | `/proof/verify` | free (never gated) — recompute + check signature |
| GET | `/proof/registry` | free — agents + current verdict (consumption surface) |
| GET | `/proof/info`, `/proof/health` | free |

Pricing uses x402 on Base (same pattern as MoltGuard); core verdict is free
(free-first — the goal is adoption). MCP tools (`moltproof_verdict`, `_mandate`,
`_evidence`, `_verify`, `_registry`) are exposed at `/mcp`.

## Develop

```bash
npm install
npm run typecheck   # tsc --noEmit
npm test            # vitest (incl. the no-secret-route hard gate)
npm run build       # tsc -> dist/
npm start           # node dist/index.js  (PORT, default 3006)
```

## Security review

The read-only claim was cross-reviewed pre-ship and holds **only** with the
implemented SSRF/allowlist/offline-verify/bounded-read/log-redaction mitigations.
See [`CROSS-REVIEW.md`](./CROSS-REVIEW.md) for the full log (F1–F11) and the build
changes each finding drove.

---

## Verification status

Each load-bearing factual claim, with source and date. Nothing ships unverified.

- ✅ **Venue is decodable from the pool `Swap` log emitter (EVM)** — cross-review
  (a), 2026-07-08. Robust to routers/aggregators/proxies.
- ✅ **Hyperliquid fills readable via `userFillsByTime`, notional = px·sz** —
  Hyperliquid API docs, 2026-07-08.
- ⚠️ **Solana venue+notional decode** — labelled **beta**; not reliably
  recomputable in v0 (aggregator routing + per-program IDL drift). Not claimed as
  supported.
- ✅ **Verified Base venue addresses** — Uniswap Universal Router
  `0x6fF5…9b43`, `0xFdf6…fbC7`; SwapRouter02 `0x2626…e481`; v4 PoolManager
  `0x4985…2b2b`; Aerodrome Router `0xcF77…4E43` — Uniswap deploy docs / Aerodrome
  repo / Basescan verified, 2026-07-08. See `src/config/venues.ts`.
- ✅ **Signature algorithm = Ed25519 (EdDSA JWS), `alg:none` rejected** — code +
  `test/sign.test.ts`, 2026-07-08.
- ✅ **AAE profile pin = `draft-kroehl-agentic-trust-aae-00`** — `/proof/info`.
- ✅ **Standards alignment = `owasp-agentic-top10`** (not owasp-llm-top10) —
  `/proof/info`.
- ✅ **Read-only / no-custody / no-secret-accepting route** — enforced +
  `test/no-secret-route.test.ts` (build-gating), 2026-07-08.
- ⚠️ **Live service, live `/proof` + `/mcp` endpoints, and the on-chain
  demonstrator** — **not yet deployed**. This repo is the service + engine +
  tests; deploy (nginx route, systemd unit) and the fresh-wallet demonstrator are
  operator steps (see the deploy handoff).

MoltProof verifies **adherence to a committed mandate, not profitability**. No
trading, no advice. Supports Article 12 logging.

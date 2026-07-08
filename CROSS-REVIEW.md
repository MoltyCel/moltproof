# MoltProof — cross-review log

Three load-bearing points were put through an independent peer review (Claude
frontier-model reviewers, web-research enabled) on **2026-07-08**, before ship.
Each outcome and the concrete build change it drove is recorded here.

> Reviewer note: the "peer frontier-model" reviewers here are independent Claude
> agents with web access, not a different vendor's model. Stated plainly so the
> provenance isn't overclaimed.

## (a) Adherence-evaluation correctness (raw tx → venue/position/validity)

**Outcome:** EVM and Hyperliquid are sound for v0; Solana is not.

- **EVM → SUPPORTED**, on one hard rule: decode the **venue from the pool `Swap`
  log emitter, not the top-level `to`**. Because the pool emits the event
  regardless of caller, routers, 1inch/0x/CoW solvers, multi-hop and proxies all
  still resolve to the true venue. Failure modes: notional needs a **pinned price
  source** (or scope the cap to the mandate's quote asset); CoW batch settlements
  can lack a per-order `Swap` → treat as **inconclusive**, never adherent.
- **Hyperliquid → SUPPORTED** (strongest): native `userFillsByTime`, notional =
  `px·sz` (no oracle). Guard: resolve the **master/sub-account**, not the agent
  (API) wallet, or fills come back empty and misread as NO_MANDATE.
- **Solana → BETA**: no typed logs; actions live in program IDs + base58
  instruction data + inner CPIs, and near-all real flow is Jupiter-routed
  multi-venue — a single (venue, notional) is not reliably recomputable in v0
  without per-program IDL maintenance.
- **Cross-cutting:** any action that can't be decoded to (venue, notional, time)
  from a recomputable source must emit **inconclusive / NEEDS_REVIEW**, never a
  silent ADHERENT.

**Build changes:** `config/chains.ts` marks EVM+Hyperliquid `supported`, Solana
`beta`. `engine/replay.ts` (`EvmSwapReader`) decodes venue from the Swap-log
emitter. `types.ts`/`engine/evaluate.ts` add a `NEEDS_REVIEW` verdict and an
inconclusive action state; undecodable notional → inconclusive, never adherent.

## (b) Read-only security claim (exploit / exfil surface)

**Outcome:** the "structurally read-only, cannot cause loss / cannot exfil" claim
does **NOT** hold on design alone — DID/mandate **resolution is a live SSRF/exfil
channel** — and holds only after the mitigations below. Ship-gated on F1–F4, F10.

- **F1 SSRF via did:web/mandate resolution** (CRITICAL) → `security/safeFetch.ts`:
  host allowlist, `https:`-only, DNS-resolve + block private/link-local/loopback/
  CGNAT/ULA on every A/AAAA, **redirects blocked**, size+time caps.
- **F2 RPC from input** → RPCs are **server config only**, never derived from a
  request (`.env`, `config/chains.ts`).
- **F3 mandate ref as URL** → `engine/mandate.ts` treats a mandate ref as an
  **opaque id** resolved via the store / allowlisted did:web; never follows
  `refreshService`/`credentialStatus`.
- **F4 /verify smuggled URL / body-supplied key** → `engine/recompute.ts` uses a
  **closed schema** (unknown fields rejected), is fully **offline**, and checks
  the signature against **MoltProof's own key** — never a key from the body.
- **F6 alg confusion** → `engine/sign.ts` hard-pins `EdDSA`, rejects `none`.
- **F7 DoS via unbounded reads** → bounded lookback + timeouts (`replay.ts`),
  rate limits (`middleware/guards.ts`).
- **F8 secret logging / log-injection** → `security/logger.ts` allowlist-only
  fields + CR/LF strip; `security/noSecrets.ts` rejects secret-shaped input (422)
  so a secret can't enter the process. Automated test: `test/no-secret-route`.
- **F9 x402** → recipient/amount/asset/network are server config, fail-closed
  (`middleware/x402.ts`, wired at deploy).
- **F10 MCP duplicate surface** → all guards live in the **shared service layer**
  (`service.ts`); `mcp/server.ts` adds an Origin allowlist and marks tool output
  as untrusted data.

**Build changes:** all of the above are implemented; the no-secret-route test is
the automated build gate the spec required.

## (c) Venue-address → venue-name map accuracy

**Outcome:** feasible with a curated, explorer-verified map; the top risk is
**router-vs-pool / one-venue-many-routers**.

- Source-of-truth: the project's own deploy artifact (Uniswap `universal-router/
  deploy-addresses`, docs deployment tables; Aerodrome contracts repo), confirmed
  against a Basescan verified contract. Never a name tag alone; never a
  third-party list as canonical.
- A single venue exposes several live routers (Uniswap Universal Router +
  SwapRouter02, and v4 is the singleton **PoolManager**), so keying on one router
  silently rejects legitimate swaps.

**Build changes:** `config/venues.ts` holds explorer-verified Base addresses
(Uniswap Universal Router ×2, SwapRouter02, v4 PoolManager; Aerodrome Router)
with sources, keyed by lowercased address, tagged with a `venueId` for **group
matching** (a different Uniswap router still counts as Uniswap). Any address not
in the registry and not in the mandate whitelist → **inconclusive**
("unrecognised venue"), never a guessed name (`engine/evaluate.ts`).

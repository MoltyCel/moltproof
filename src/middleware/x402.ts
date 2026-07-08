import type { Context, Next } from "hono";

// x402 paywall SEAM (Base). Mirrors MoltGuard's pattern but is intentionally a
// pluggable interface so this repo builds/tests without the payment stack wired.
// At deploy, replace `settle` with @x402/hono's facilitator-backed verification.
//
// Cross-review F9: recipient (payTo), amount, asset and network are SERVER config
// — never chosen by the request; verification is server-side and fails closed.

export interface X402Config {
  enabled: boolean;
  payTo: string; // server-configured recipient; never from the request
  network: "base";
  chainId: 8453;
}

export interface PaymentSettler {
  /** Return true only if a valid, non-replayed payment for `priceUsd` is present. */
  settle(c: Context, priceUsd: string): Promise<boolean>;
}

/** Default settler: paywall disabled => endpoint behaves as free (v0 free-first).
 *  A real deploy injects a facilitator-backed settler. */
export const openSettler: PaymentSettler = {
  async settle() {
    return true;
  },
};

export function paywall(price: string, cfg: X402Config, settler: PaymentSettler = openSettler) {
  return async function (c: Context, next: Next): Promise<Response | void> {
    if (!cfg.enabled || price === "0") return next();
    const ok = await settler.settle(c, price);
    if (!ok) {
      return c.json(
        { error: "payment_required", price, asset: "USDC", network: cfg.network, payTo: cfg.payTo },
        402,
      );
    }
    await next();
  };
}

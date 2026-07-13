import { Hono } from "hono";
import { serve } from "@hono/node-server";
import "dotenv/config";
import { buildContext } from "./context.js";
import { makeService } from "./service.js";
import { noSecretsMiddleware, rateLimit, type AppEnv } from "./middleware/guards.js";
import { paywall, type X402Config } from "./middleware/x402.js";
import { mountMcp } from "./mcp/server.js";
import { log } from "./security/logger.js";
import { VerifyInputError } from "./engine/recompute.js";
import { MandateError } from "./engine/mandate.js";
import { SsrfError } from "./security/safeFetch.js";

const ctx = buildContext();
const service = makeService(ctx);

const x402: X402Config = {
  enabled: process.env.X402_ENABLED === "true",
  payTo: process.env.X402_PAY_TO_ADDRESS ?? "",
  network: "base",
  chainId: 8453,
};

export const app = new Hono<AppEnv>();

// Shared guard layer — applies to every /proof route (and MCP calls the same
// service functions, so it inherits the input logic).
app.use("/proof/*", noSecretsMiddleware);
app.use("/mcp", noSecretsMiddleware);

const PATHS = {
  verdictFree: "/proof/verdict-free/:agent",
  verdict: "/proof/verdict/:agent",
  evidence: "/proof/evidence/:agent",
  mandate: "/proof/mandate/:agent",
  verify: "/proof/verify",
  registry: "/proof/registry",
  info: "/proof/info",
  health: "/proof/health",
};

// verdict-free: free, tight rate limit (spec: 1 / 10 min).
app.get(PATHS.verdictFree, rateLimit({ windowMs: 10 * 60_000, max: 1 }), async (c) => {
  const agent = c.req.param("agent") ?? "";
  const out = await service.verdictFree(agent);
  log("info", { route: "verdict-free", agent, verdict: out.verdict });
  return c.json(out);
});

// verdict / evidence: paid ($0.05) via x402 seam (free while paywall disabled).
app.get(PATHS.verdict, paywall("0.05", x402), async (c) => {
  const out = await service.verdict(c.req.param("agent") ?? "");
  return c.json(out);
});
app.get(PATHS.evidence, paywall("0.05", x402), async (c) => {
  const out = await service.evidence(c.req.param("agent") ?? "");
  return c.json(out);
});

app.get(PATHS.mandate, async (c) => c.json(await service.mandate(c.req.param("agent") ?? "")));

// verify: NEVER gated (spec). Uses body parsed by the guard, or parses here.
app.post(PATHS.verify, async (c) => {
  const body = c.get("parsedBody") ?? (await c.req.json().catch(() => null));
  try {
    return c.json(service.verify(body));
  } catch (e) {
    if (e instanceof VerifyInputError || e instanceof MandateError) return c.json({ error: "invalid_input", detail: e.message }, 400);
    throw e;
  }
});

app.get(PATHS.registry, rateLimit({ windowMs: 60_000, max: 30 }), async (c) => c.json(await service.registry()));
app.get(PATHS.info, (c) => c.json(service.info()));
app.get(PATHS.health, (c) => c.json(service.health()));

// MCP: same tools over the same service (shared layer).
mountMcp(app, service);

app.onError((err, c) => {
  if (err instanceof SsrfError) return c.json({ error: "resolution_blocked", detail: err.message }, 422);
  log("error", { route: "onError", msg: err.message });
  return c.json({ error: "internal_error" }, 500);
});

// Only listen when run directly (tests import `app` without binding a port).
if (process.env.NODE_ENV !== "test" && process.argv[1]?.endsWith("index.js")) {
  const port = Number(process.env.PORT ?? 3006);
  serve({ fetch: app.fetch, port, hostname: "127.0.0.1" });
  log("info", { route: "boot", msg: `moltproof listening on ${port} (read-only)` });
}

import type { Context, Next } from "hono";
import { scanRequestParts } from "../security/noSecrets.js";

// Shared guard layer (cross-review F10): HTTP routes AND the MCP tool layer call
// these, so no surface bypasses them.

/** Hono environment: the parsed request body is stashed once by the guard so
 *  handlers don't re-read the (already consumed) stream. */
export type AppEnv = { Variables: { parsedBody: unknown } };

/** Reject any request carrying a secret-shaped field/value. Never echoes it. */
export async function noSecretsMiddleware(c: Context<AppEnv>, next: Next): Promise<Response | void> {
  const headers: Record<string, unknown> = {};
  for (const h of ["authorization", "x-api-key", "x-seed", "cookie"]) {
    const v = c.req.header(h);
    if (v != null) headers[h] = v;
  }
  let body: unknown;
  if (c.req.method === "POST" || c.req.method === "PUT") {
    try {
      body = await c.req.json();
      // stash parsed body so handlers don't re-read the stream
      c.set("parsedBody", body);
    } catch {
      body = undefined;
    }
  }
  const hit = scanRequestParts({
    params: c.req.param() as Record<string, unknown>,
    query: c.req.query() as Record<string, unknown>,
    headers,
    body,
  });
  if (hit.hit) {
    // Generic message; the offending value is NEVER included or logged.
    return c.json(
      {
        error: "secret_shaped_input_rejected",
        detail: "MoltProof accepts only public inputs (agent address / DID / mandate ref). A secret-shaped field was rejected.",
        field: hit.field,
        reason: hit.reason,
      },
      422,
    );
  }
  await next();
}

/** Minimal in-memory fixed-window rate limiter (cross-review F7). */
export function rateLimit(opts: { windowMs: number; max: number }) {
  const hits = new Map<string, { count: number; reset: number }>();
  return async function (c: Context, next: Next): Promise<Response | void> {
    const now = Date.now();
    const ip = c.req.header("x-forwarded-for")?.split(",")[0]?.trim() || c.req.header("x-real-ip") || "unknown";
    const key = `${ip}:${new URL(c.req.url).pathname.split("/").slice(0, 3).join("/")}`;
    const e = hits.get(key);
    if (!e || e.reset < now) {
      hits.set(key, { count: 1, reset: now + opts.windowMs });
    } else {
      e.count++;
      if (e.count > opts.max) {
        return c.json({ error: "rate_limited", retryAfterMs: e.reset - now }, 429);
      }
    }
    await next();
  };
}

import type { Hono } from "hono";
import type { Service } from "../service.js";
import type { AppEnv } from "../middleware/guards.js";

// MCP over streamable-http at /mcp. The tools are thin wrappers over the SAME
// shared service the HTTP routes use (cross-review F10 — no bypass surface).
// Guards: Origin allowlist (DNS-rebinding on SSE/streamable-http), and outputs
// are marked as untrusted data for the calling LLM (prompt-injection hygiene).
//
// This is a compliant JSON-RPC 2.0 tools surface (initialize / tools/list /
// tools/call). A full @modelcontextprotocol/sdk transport is wired at deploy;
// the tool contracts and handlers here are the source of truth.

const TOOLS = [
  { name: "moltproof_verdict", description: "Verdict + per-check breakdown for an agent vs its committed mandate.", input: "agent" },
  { name: "moltproof_mandate", description: "The committed AAE mandate for an agent.", input: "agent" },
  { name: "moltproof_evidence", description: "Verdict plus decoded breaching transactions.", input: "agent" },
  { name: "moltproof_verify", description: "Recompute a verdict from public inputs and check its signature.", input: "body" },
  { name: "moltproof_registry", description: "Agents with committed mandates and their current verdict.", input: "none" },
] as const;

function originAllowed(origin: string | undefined, allowlist: string[]): boolean {
  if (!origin) return true; // non-browser MCP clients often omit Origin
  try {
    return allowlist.includes(new URL(origin).host);
  } catch {
    return false;
  }
}

export function mountMcp(app: Hono<AppEnv>, service: Service): void {
  const allowlist = (process.env.MCP_ORIGIN_ALLOWLIST ?? "moltrust.ch,api.moltrust.ch,localhost")
    .split(",")
    .map((s) => s.trim());

  app.post("/mcp", async (c) => {
    if (!originAllowed(c.req.header("origin"), allowlist)) {
      return c.json({ jsonrpc: "2.0", id: null, error: { code: -32600, message: "origin not allowed" } }, 403);
    }
    const req = (c.get("parsedBody") ?? (await c.req.json().catch(() => null))) as
      | { jsonrpc?: string; id?: unknown; method?: string; params?: Record<string, unknown> }
      | null;
    if (!req || req.jsonrpc !== "2.0" || typeof req.method !== "string") {
      return c.json({ jsonrpc: "2.0", id: req?.id ?? null, error: { code: -32600, message: "invalid request" } }, 400);
    }
    const id = req.id ?? null;

    if (req.method === "initialize") {
      return c.json({ jsonrpc: "2.0", id, result: { protocolVersion: "2025-06-18", serverInfo: { name: "moltproof", version: "0.1.0" }, capabilities: { tools: {} } } });
    }
    if (req.method === "tools/list") {
      return c.json({
        jsonrpc: "2.0",
        id,
        result: {
          tools: TOOLS.map((t) => ({
            name: t.name,
            description: t.description,
            inputSchema:
              t.input === "none"
                ? { type: "object", properties: {}, additionalProperties: false }
                : t.input === "agent"
                  ? { type: "object", properties: { agent: { type: "string" } }, required: ["agent"], additionalProperties: false }
                  : { type: "object", properties: { agent: { type: "string" }, mandate: { type: "object" }, actions: { type: "array" }, signature: { type: "object" } }, required: ["agent", "mandate", "actions"], additionalProperties: false },
          })),
        },
      });
    }
    if (req.method === "tools/call") {
      const name = String(req.params?.name ?? "");
      const args = (req.params?.arguments ?? {}) as Record<string, unknown>;
      try {
        const data = await dispatch(service, name, args);
        return c.json({
          jsonrpc: "2.0",
          id,
          result: {
            // Mark as untrusted data for the calling LLM (F10 prompt-injection hygiene).
            content: [{ type: "text", text: JSON.stringify({ untrusted_data: true, source: "moltproof", data }) }],
          },
        });
      } catch (e) {
        return c.json({ jsonrpc: "2.0", id, error: { code: -32000, message: (e as Error).message } });
      }
    }
    return c.json({ jsonrpc: "2.0", id, error: { code: -32601, message: "method not found" } }, 404);
  });
}

async function dispatch(service: Service, name: string, args: Record<string, unknown>): Promise<unknown> {
  switch (name) {
    case "moltproof_verdict":
      return service.verdict(String(args.agent ?? ""));
    case "moltproof_mandate":
      return service.mandate(String(args.agent ?? ""));
    case "moltproof_evidence":
      return service.evidence(String(args.agent ?? ""));
    case "moltproof_verify":
      return service.verify(args);
    case "moltproof_registry":
      return service.registry();
    default:
      throw new Error(`unknown tool: ${name}`);
  }
}

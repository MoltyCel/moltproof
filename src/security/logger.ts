// Structural log safety (cross-review F8): allowlist-only fields, CR/LF stripped,
// never the request body/headers/params and never the signing key. There is no
// "redact the secret" step because a secret must never enter the process (see
// noSecrets) — this logger simply cannot be handed one.

type Level = "info" | "warn" | "error";

const ALLOWED_FIELDS = new Set(["route", "agent", "verdict", "status", "latencyMs", "requestId", "chain", "msg"]);

function clean(v: unknown): unknown {
  if (typeof v === "string") return v.replace(/[\r\n]+/g, " ").slice(0, 256);
  if (typeof v === "number" || typeof v === "boolean") return v;
  return String(v).replace(/[\r\n]+/g, " ").slice(0, 256);
}

export function log(level: Level, fields: Record<string, unknown>): void {
  const safe: Record<string, unknown> = { level, t: new Date().toISOString() };
  for (const [k, v] of Object.entries(fields)) {
    if (ALLOWED_FIELDS.has(k)) safe[k] = clean(v);
  }
  const line = JSON.stringify(safe);
  if (level === "error") console.error(line);
  else if (level === "warn") console.warn(line);
  else console.log(line);
}

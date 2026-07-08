import fs from "node:fs";
import path from "node:path";
import type { DecodedAction, Mandate } from "./types.js";
import { MemoryMandateStore } from "./engine/mandate.js";
import { StaticReader, type ExecutionReader } from "./engine/replay.js";
import type { EngineDeps } from "./engine/index.js";
import { SUPPORTED_CHAINS } from "./config/chains.js";

// Build the engine dependencies from environment + optional seed data.
// v0 is honest about having no live data until the demonstrator seeds it:
//  - mandates come from data/mandates.json (the demonstrator/operator writes it)
//  - execution comes from data/actions.json (seed) or, once wired, live readers
// With no seed, unknown agents correctly return NO_MANDATE and /registry is empty.

export interface AppContext extends EngineDeps {
  store: MemoryMandateStore;
}

function readJson<T>(file: string, fallback: T): T {
  try {
    const p = path.resolve(process.cwd(), file);
    if (!fs.existsSync(p)) return fallback;
    return JSON.parse(fs.readFileSync(p, "utf8")) as T;
  } catch {
    return fallback;
  }
}

export function buildContext(env: NodeJS.ProcessEnv = process.env): AppContext {
  const mandates = readJson<Mandate[]>("data/mandates.json", []);
  const seedActions = readJson<DecodedAction[]>("data/actions.json", []);
  const store = new MemoryMandateStore(mandates);
  const reader: ExecutionReader = new StaticReader(seedActions);
  const didAllowlist = (env.DID_RESOLVE_ALLOWLIST ?? "moltrust.ch,api.moltrust.ch")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);

  return {
    store,
    reader,
    didAllowlist,
    signingKeyPem: env.MOLTPROOF_SIGNING_KEY_PEM || undefined,
    chainsUsed: SUPPORTED_CHAINS.map((c) => c.id),
  };
}

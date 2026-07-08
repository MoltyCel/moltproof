import { describe, it, expect } from "vitest";
import { app } from "../src/index.js";

// HARD SECURITY GATE (spec): assert that NO route accepts a secret-shaped field.
// If any route lets a secret-shaped input through, this test fails => build fails.

const AGENT = "0x1111111111111111111111111111111111111111";

const routes = [
  { name: "verdict-free", method: "GET", path: `/proof/verdict-free/${AGENT}` },
  { name: "verdict", method: "GET", path: `/proof/verdict/${AGENT}` },
  { name: "evidence", method: "GET", path: `/proof/evidence/${AGENT}` },
  { name: "mandate", method: "GET", path: `/proof/mandate/${AGENT}` },
  { name: "registry", method: "GET", path: `/proof/registry` },
  { name: "info", method: "GET", path: `/proof/info` },
  { name: "health", method: "GET", path: `/proof/health` },
];

// Each of these is a secret-shaped input that must be rejected everywhere.
const secretQueries = ["privateKey=0x" + "a".repeat(64), "seed=" + "a".repeat(40), "apiKey=sk_live_deadbeefcafe1234"];

describe("HARD GATE: no route accepts a secret-shaped field", () => {
  for (const r of routes) {
    for (const q of secretQueries) {
      it(`${r.name} rejects ?${q.split("=")[0]}`, async () => {
        const res = await app.fetch(new Request(`http://x${r.path}?${q}`, { method: r.method }));
        expect(res.status).toBe(422);
        const body = await res.json();
        expect(body.error).toBe("secret_shaped_input_rejected");
        // The offending VALUE must never be echoed back.
        const text = JSON.stringify(body);
        expect(text).not.toContain("a".repeat(64));
        expect(text).not.toContain("sk_live_deadbeefcafe1234");
      });
    }
  }

  it("POST /proof/verify rejects a mnemonic in the body", async () => {
    const seed = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const res = await app.fetch(
      new Request("http://x/proof/verify", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ agent: AGENT, mandate: {}, actions: [], note: seed }),
      }),
    );
    expect(res.status).toBe(422);
    const body = await res.json();
    expect(JSON.stringify(body)).not.toContain("abandon abandon");
  });

  it("POST /proof/verify rejects a private-key-named field", async () => {
    const res = await app.fetch(
      new Request("http://x/proof/verify", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ agent: AGENT, mandate: {}, actions: [], private_key: "0x" + "b".repeat(64) }),
      }),
    );
    expect(res.status).toBe(422);
  });

  it("PEM private key in any body field is rejected", async () => {
    const res = await app.fetch(
      new Request("http://x/proof/verify", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ agent: AGENT, mandate: {}, actions: [], x: "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----" }),
      }),
    );
    expect(res.status).toBe(422);
  });

  it("Authorization header carrying a key-shaped token is rejected", async () => {
    const res = await app.fetch(
      new Request(`http://x/proof/verdict-free/${AGENT}`, {
        method: "GET",
        headers: { authorization: "Bearer sk_live_abcdefgh12345678" },
      }),
    );
    expect(res.status).toBe(422);
  });
});

describe("clean public inputs are NOT rejected", () => {
  it("verdict-free for a plain address returns 200 NO_MANDATE (no mandate seeded)", async () => {
    const res = await app.fetch(new Request(`http://x/proof/verdict-free/${AGENT}`, { method: "GET" }));
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.verdict).toBe("NO_MANDATE");
  });

  it("info and health are public and open", async () => {
    expect((await app.fetch(new Request("http://x/proof/info"))).status).toBe(200);
    expect((await app.fetch(new Request("http://x/proof/health"))).status).toBe(200);
  });

  it("a tx-hash-shaped (0x+64hex) value in a normal field is allowed (not a secret)", async () => {
    // A tx hash is public data; it must NOT be blanket-rejected.
    const res = await app.fetch(
      new Request("http://x/proof/verify", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          agent: AGENT,
          mandate: {
            credentialSubject: {
              id: "did:moltrust:agent1",
              constraints: { allowed_venues: [], max_position_notional: "1000", valid_from: "2026-01-01T00:00:00Z", valid_until: "2026-02-01T00:00:00Z" },
            },
          },
          actions: [{ chain: "base", txHash: "0x" + "c".repeat(64), blockNumber: 1, timestamp: 1735732800, venueAddressesTouched: [], venues: [], notional: null, inconclusive: false }],
        }),
      }),
    );
    // Not 422 (tx hash is fine); recompute runs.
    expect(res.status).toBe(200);
  });
});

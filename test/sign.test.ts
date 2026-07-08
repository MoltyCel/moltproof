import { describe, it, expect } from "vitest";
import crypto from "node:crypto";
import { signPayload, verifyPayload, canonicalize } from "../src/engine/sign.js";

function ed25519Pems() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  return {
    priv: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    pub: publicKey.export({ type: "spki", format: "pem" }).toString(),
  };
}

describe("Ed25519 JWS verdict signing", () => {
  it("canonicalize is key-order independent", () => {
    expect(canonicalize({ b: 1, a: 2 })).toBe(canonicalize({ a: 2, b: 1 }));
  });

  it("signs and verifies a payload", () => {
    const { priv, pub } = ed25519Pems();
    const payload = { agent: "0xabc", verdict: "ADHERENT" };
    const sig = signPayload(payload, priv);
    expect(sig.alg).toBe("EdDSA");
    expect(sig.kid).toBe("did:web:moltrust.ch#moltproof-key-1");
    expect(verifyPayload(payload, sig, pub)).toBe(true);
  });

  it("rejects a tampered payload", () => {
    const { priv, pub } = ed25519Pems();
    const sig = signPayload({ verdict: "ADHERENT" }, priv);
    expect(verifyPayload({ verdict: "BREACHED" }, sig, pub)).toBe(false);
  });

  it("rejects a wrong key", () => {
    const a = ed25519Pems();
    const b = ed25519Pems();
    const sig = signPayload({ x: 1 }, a.priv);
    expect(verifyPayload({ x: 1 }, sig, b.pub)).toBe(false);
  });

  it("rejects alg confusion (non-EdDSA)", () => {
    const { priv, pub } = ed25519Pems();
    const sig = signPayload({ x: 1 }, priv);
    const forged = { ...sig, alg: "none" as unknown as "EdDSA" };
    expect(verifyPayload({ x: 1 }, forged, pub)).toBe(false);
  });
});

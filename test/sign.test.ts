import { describe, it, expect } from "vitest";
import crypto from "node:crypto";
import { signPayload, verifyPayload, canonicalize, publicKeyFromVerificationMethod } from "../src/engine/sign.js";

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

describe("did.json JsonWebKey2020 entry is parseable by the resolver", () => {
  // Proves the published did.json convention (JsonWebKey2020 / OKP-Ed25519 JWK)
  // verifies a MoltProof JWS directly — closing the loop between the .env signing
  // key and the #moltproof-key-1 entry the site serves.
  function keypairWithDidEntry() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
    const jwk = publicKey.export({ format: "jwk" }); // { kty:"OKP", crv:"Ed25519", x:"..." }
    return {
      priv: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
      didEntry: {
        id: "did:web:moltrust.ch#moltproof-key-1",
        type: "JsonWebKey2020",
        controller: "did:web:moltrust.ch",
        publicKeyJwk: { ...jwk, alg: "EdDSA", use: "sig", kid: "did:web:moltrust.ch#moltproof-key-1" },
      },
    };
  }

  it("verifies a signature using the publicKeyJwk straight from did.json", () => {
    const { priv, didEntry } = keypairWithDidEntry();
    const payload = { agent: "did:moltrust:x", verdict: "ADHERENT" };
    const sig = signPayload(payload, priv);
    // pass the JWK object exactly as it appears in did.json
    expect(verifyPayload(payload, sig, didEntry.publicKeyJwk)).toBe(true);
  });

  it("publicKeyFromVerificationMethod resolves the entry to an ed25519 key", () => {
    const { priv, didEntry } = keypairWithDidEntry();
    const sig = signPayload({ v: 1 }, priv);
    const key = publicKeyFromVerificationMethod(didEntry);
    expect(key.asymmetricKeyType).toBe("ed25519");
    expect(key.export({ format: "jwk" }).x).toBe(didEntry.publicKeyJwk.x);
    expect(verifyPayload({ v: 1 }, sig, didEntry.publicKeyJwk)).toBe(true);
  });

  it("kid on the entry equals the JWS kid constant", () => {
    const { didEntry } = keypairWithDidEntry();
    const sig = signPayload({ a: 1 }, keypairWithDidEntry().priv);
    expect(didEntry.id).toBe(sig.kid); // did:web:moltrust.ch#moltproof-key-1
  });
});

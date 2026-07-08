// Ed25519 JWS over a verdict (spec: sign for portability; recomputability is the
// real anchor). Cross-review F6/F11: alg is hard-pinned to EdDSA (reject "none"),
// the signing key is loaded once and never serialized, and verification uses a
// key resolved from our allowlisted did:web — never a key supplied in a request.

import crypto from "node:crypto";

export const KID = "did:web:moltrust.ch#moltproof-key-1" as const;

function b64url(buf: Buffer | string): string {
  return Buffer.from(buf).toString("base64url");
}

/** Deterministic canonical JSON (sorted keys) so the digest is reproducible. */
export function canonicalize(value: unknown): string {
  return JSON.stringify(sortDeep(value));
}
function sortDeep(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(sortDeep);
  if (v && typeof v === "object") {
    return Object.fromEntries(
      Object.entries(v as Record<string, unknown>)
        .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
        .map(([k, val]) => [k, sortDeep(val)]),
    );
  }
  return v;
}

export function sha256Hex(s: string): string {
  return crypto.createHash("sha256").update(s).digest("hex");
}

export interface JwsSignature {
  alg: "EdDSA";
  kid: typeof KID;
  payloadDigestSha256: string;
  jws: string; // detached compact JWS: base64url(header)..base64url(sig)
}

/** Sign a canonical payload with an Ed25519 PKCS#8 PEM private key. */
export function signPayload(payload: unknown, privateKeyPem: string): JwsSignature {
  const canonical = canonicalize(payload);
  const header = { alg: "EdDSA", kid: KID, typ: "JWS" };
  const signingInput = `${b64url(JSON.stringify(header))}.${b64url(canonical)}`;
  const key = crypto.createPrivateKey(privateKeyPem);
  if (key.asymmetricKeyType !== "ed25519") throw new Error("signing key is not ed25519");
  const sig = crypto.sign(null, Buffer.from(signingInput), key);
  const [h] = signingInput.split(".");
  return {
    alg: "EdDSA",
    kid: KID,
    payloadDigestSha256: sha256Hex(canonical),
    jws: `${h}..${b64url(sig)}`, // detached (payload segment omitted)
  };
}

/** An OKP/Ed25519 public JWK, as published in a did.json `publicKeyJwk`. */
export interface PublicJwk {
  kty?: string;
  crv?: string;
  x?: string;
  alg?: string;
  use?: string;
  kid?: string;
  [k: string]: unknown;
}

/** A JsonWebKey2020 verificationMethod entry, as published in did.json. */
export interface Ed25519VerificationMethod {
  id: string;
  type: string;
  controller?: string;
  publicKeyJwk?: PublicJwk;
}

/** Build an Ed25519 public KeyObject from what a did.json entry actually carries.
 *  Accepts a JsonWebKey2020 `publicKeyJwk` (the moltrust.ch convention) or a raw
 *  OKP JWK — so the PUBLISHED did.json entry is directly consumable here. */
export function publicKeyFromJwk(jwk: PublicJwk): crypto.KeyObject {
  if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519") {
    throw new Error("unsupported key: expected OKP/Ed25519 JWK");
  }
  // `format: "jwk"` expects node's ambient JsonWebKey type (not in our lib set);
  // the structural object is correct at runtime.
  return crypto.createPublicKey({ key: jwk as unknown as crypto.JsonWebKeyInput["key"], format: "jwk" });
}

/** Resolve the public key from a did.json verificationMethod entry (by its kid). */
export function publicKeyFromVerificationMethod(vm: Ed25519VerificationMethod): crypto.KeyObject {
  if (!vm.publicKeyJwk) throw new Error(`verificationMethod ${vm.id} has no publicKeyJwk`);
  return publicKeyFromJwk(vm.publicKeyJwk);
}

/** Verify a detached JWS over `payload` using an Ed25519 public key. `publicKey`
 *  may be an SPKI PEM string OR the `publicKeyJwk` object straight out of
 *  did.json (JsonWebKey2020 OKP/Ed25519) — the published entry is parseable as-is.
 *  The key comes from DID resolution / config, NEVER from the caller. */
export function verifyPayload(
  payload: unknown,
  sig: JwsSignature,
  publicKey: string | PublicJwk,
): boolean {
  if (sig.alg !== "EdDSA") return false; // reject alg:none / HMAC confusion
  const parts = sig.jws.split(".");
  if (parts.length !== 3 || parts[1] !== "") return false; // detached form: h..s
  const header = JSON.parse(Buffer.from(parts[0]!, "base64url").toString());
  if (header.alg !== "EdDSA") return false;
  const canonical = canonicalize(payload);
  if (sha256Hex(canonical) !== sig.payloadDigestSha256) return false;
  const signingInput = `${parts[0]}.${b64url(canonical)}`;
  let key: crypto.KeyObject;
  try {
    key = typeof publicKey === "string" ? crypto.createPublicKey(publicKey) : publicKeyFromJwk(publicKey);
  } catch {
    return false;
  }
  if (key.asymmetricKeyType !== "ed25519") return false;
  try {
    return crypto.verify(null, Buffer.from(signingInput), key, Buffer.from(parts[2]!, "base64url"));
  } catch {
    return false;
  }
}

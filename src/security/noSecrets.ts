// HARD SECURITY GATE (spec §HARD SECURITY GATES + cross-review F5/F8).
//
// MoltProof accepts ONLY public inputs. This scanner rejects any request whose
// keys or values look like a private key / seed / API key BEFORE the value can
// enter the process, and it NEVER logs or echoes the offending value. Both the
// HTTP routes and the MCP layer run through this (shared service layer, F10).
//
// Ambiguity note: a bare 0x-prefixed 64-hex string is NOT rejected by value —
// it is indistinguishable from a legitimate tx/block hash (a valid public
// input). Such material is only rejected when it appears under a secret-named
// key. Everything unambiguous (PEM blocks, xprv, sk_* / ghp_ tokens, BIP-39
// mnemonics, WalletConnect URIs) is rejected by value anywhere.

const SECRET_KEY_NAMES = new Set(
  [
    "privatekey",
    "private_key",
    "priv",
    "secret",
    "secretkey",
    "seed",
    "mnemonic",
    "apikey",
    "api_key",
    "password",
    "passwd",
    "keystore",
    "pkcs8",
    "signingkey",
    "signing_key",
    "sessionkey",
    "wc_uri",
    "walletconnect",
    "x-api-key",
  ].map((s) => s.toLowerCase()),
);

const UNAMBIGUOUS_VALUE = [
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
  /-----BEGIN [A-Z ]*KEY-----/,
  /\bxprv[a-km-zA-HJ-NP-Z1-9]{50,}/, // BIP32 extended private key
  /\b(sk_live_|sk-ant-|ghp_|github_pat_|whsec_|sk_test_)[A-Za-z0-9_]{8,}/,
  /\bwc:[0-9a-f]{6,}@\d/, // WalletConnect pairing URI
];

// A BIP-39 mnemonic: 12/15/18/21/24 lowercase words. Approximated structurally
// (we don't ship the wordlist): >=12 space-separated lowercase alpha tokens.
function looksLikeMnemonic(v: string): boolean {
  const words = v.trim().split(/\s+/);
  if (words.length < 12 || words.length > 24) return false;
  return words.every((w) => /^[a-z]{3,8}$/.test(w));
}

export interface SecretHit {
  hit: boolean;
  field?: string; // the offending FIELD NAME only — never the value
  reason?: "secret-named-field" | "secret-shaped-value";
}

export function scanForSecret(input: unknown, keyPath = ""): SecretHit {
  if (input == null) return { hit: false };

  if (typeof input === "string") {
    if (UNAMBIGUOUS_VALUE.some((re) => re.test(input)) || looksLikeMnemonic(input)) {
      return { hit: true, field: keyPath || "(value)", reason: "secret-shaped-value" };
    }
    return { hit: false };
  }
  if (typeof input === "number" || typeof input === "boolean") return { hit: false };

  if (Array.isArray(input)) {
    for (let i = 0; i < input.length; i++) {
      const r = scanForSecret(input[i], `${keyPath}[${i}]`);
      if (r.hit) return r;
    }
    return { hit: false };
  }
  if (typeof input === "object") {
    for (const [k, v] of Object.entries(input as Record<string, unknown>)) {
      if (SECRET_KEY_NAMES.has(k.toLowerCase())) {
        return { hit: true, field: k, reason: "secret-named-field" };
      }
      const r = scanForSecret(v, keyPath ? `${keyPath}.${k}` : k);
      if (r.hit) return r;
    }
  }
  return { hit: false };
}

/** Scan the parts of an HTTP request that carry caller data. */
export function scanRequestParts(parts: {
  params?: Record<string, unknown>;
  query?: Record<string, unknown>;
  headers?: Record<string, unknown>;
  body?: unknown;
}): SecretHit {
  // Only inspect headers that could plausibly carry a key.
  const sensitiveHeaders: Record<string, unknown> = {};
  for (const h of ["authorization", "x-api-key", "x-seed", "cookie"]) {
    const val = parts.headers?.[h];
    if (val != null) sensitiveHeaders[h] = val;
  }
  for (const src of [parts.params, parts.query, sensitiveHeaders, parts.body]) {
    const r = scanForSecret(src);
    if (r.hit) return r;
  }
  return { hit: false };
}

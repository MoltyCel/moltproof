import { describe, it, expect } from "vitest";
import { isPrivateAddress, safeFetchJson, SsrfError } from "../src/security/safeFetch.js";

describe("SSRF guard: private address detection", () => {
  it("flags loopback, link-local (cloud metadata), private, CGNAT", () => {
    expect(isPrivateAddress("127.0.0.1")).toBe(true);
    expect(isPrivateAddress("169.254.169.254")).toBe(true); // AWS/GCP metadata
    expect(isPrivateAddress("10.1.2.3")).toBe(true);
    expect(isPrivateAddress("172.16.0.1")).toBe(true);
    expect(isPrivateAddress("192.168.1.1")).toBe(true);
    expect(isPrivateAddress("100.64.0.1")).toBe(true); // CGNAT
    expect(isPrivateAddress("::1")).toBe(true);
    expect(isPrivateAddress("fe80::1")).toBe(true);
    expect(isPrivateAddress("fd00::1")).toBe(true);
  });
  it("allows public addresses", () => {
    expect(isPrivateAddress("1.1.1.1")).toBe(false);
    expect(isPrivateAddress("8.8.8.8")).toBe(false);
  });
});

describe("SSRF guard: safeFetchJson", () => {
  it("rejects a non-https scheme", async () => {
    await expect(safeFetchJson("file:///etc/passwd", { allowlist: ["x"] })).rejects.toBeInstanceOf(SsrfError);
  });
  it("rejects a host not on the allowlist", async () => {
    await expect(safeFetchJson("https://evil.example/did.json", { allowlist: ["moltrust.ch"] })).rejects.toBeInstanceOf(SsrfError);
  });
  it("rejects an internal-hostname target even if scheme ok", async () => {
    await expect(safeFetchJson("https://localhost/did.json", { allowlist: ["moltrust.ch"] })).rejects.toBeInstanceOf(SsrfError);
  });
});

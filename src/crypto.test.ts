import { describe, it, expect } from "vitest";
import { createHmac } from "node:crypto";
import { base64UrlDecode, base64UrlEncode, decodeJwtPayload, deriveSealKey, open, seal, sha256Hex, signHs512Jwt } from "./crypto";

describe("signHs512Jwt", () => {
  const key = new Uint8Array(64).map((_, i) => (i * 37) & 0xff);

  it("produces a compact JWS whose signature node:crypto verifies, with kid in the header", async () => {
    const jwt = await signHs512Jwt({ username: "me@example.com", password: "p@ss wörd" }, key, "kid-1");
    const [h, p, s] = jwt.split(".");
    expect(JSON.parse(Buffer.from(h, "base64url").toString())).toEqual({ alg: "HS512", typ: "JWT", kid: "kid-1" });
    expect(JSON.parse(Buffer.from(p, "base64url").toString())).toEqual({ username: "me@example.com", password: "p@ss wörd" });
    expect(s).toBe(createHmac("sha512", Buffer.from(key)).update(`${h}.${p}`).digest("base64url"));
    expect(jwt).not.toMatch(/[+/=]/);
  });

  it("decodes a payload without verifying", () => {
    const token = `${Buffer.from('{"alg":"HS512"}').toString("base64url")}.${Buffer.from('{"sub":"abc"}').toString("base64url")}.sig`;
    expect(decodeJwtPayload(token)).toEqual({ sub: "abc" });
    expect(() => decodeJwtPayload("nope")).toThrow(/JWT/);
  });
});

describe("base64url", () => {
  it("round-trips arbitrary bytes and handles missing padding", () => {
    const bytes = new Uint8Array(70_000).map((_, i) => (i * 31) & 0xff);
    expect(base64UrlDecode(base64UrlEncode(bytes))).toEqual(bytes);
    expect(base64UrlDecode("YQ")).toEqual(new Uint8Array([97]));
    expect(base64UrlDecode("_-8")).toEqual(new Uint8Array([0xff, 0xef]));
  });
});

describe("KV sealing (AES-GCM)", () => {
  it("round-trips and fails on the wrong key or tampering", async () => {
    const key = await deriveSealKey("secret");
    const other = await deriveSealKey("secret2");
    const sealed = await seal(key, '{"accessToken":"abc"}');
    expect(await open(key, sealed)).toBe('{"accessToken":"abc"}');
    await expect(open(other, sealed)).rejects.toThrow();
    await expect(open(key, "AAAA")).rejects.toThrow(/too short/);
  });
});

describe("sha256Hex", () => {
  it("matches the known digest of 'abc'", async () => {
    expect(await sha256Hex("abc")).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  });
});

/**
 * TokenVault against a fake identity service that rotates refresh tokens the
 * way MyFitnessPal does: every refresh kills the token that was used, so any
 * lost or raced rotation would strand the chain — exactly what the vault
 * exists to prevent.
 */
import { describe, it, expect } from "vitest";
import { IDENTITY_BASE, refreshTokenSet } from "./mfp-api";
import { TokenVault, type VaultStorage } from "./token-vault";

const CREDS = { clientId: "cid", clientSecret: "csec" };
const USER_HASH = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
const NOW_MS = Date.parse("2026-09-01T12:00:00Z");

const b64url = (s: string) => Buffer.from(s).toString("base64url");

function makeIdentityFake() {
  const state = {
    refreshes: 0,
    attempts: 0,
    counter: 0,
    valid: new Set<string>(["rt-grant"]),
  };
  const json = (status: number, body: unknown) =>
    new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
  const fetchImpl: typeof fetch = async (input, init) => {
    const url = new URL(String(input));
    if (url.origin !== IDENTITY_BASE || url.pathname !== "/oauth/token") return json(404, {});
    const form = new URLSearchParams(String(init?.body));
    if (form.get("grant_type") !== "refresh_token") return json(400, { error: "grant" });
    if (form.get("client_secret") !== CREDS.clientSecret) return json(401, { error: "invalid_client" });
    state.attempts++;
    const rt = form.get("refresh_token") ?? "";
    if (!state.valid.has(rt)) return json(401, { error: "invalid_grant" });
    state.refreshes++;
    state.valid.delete(rt); // rotation: the used token dies
    state.counter++;
    state.valid.add(`rt-${state.counter}`);
    return json(200, { access_token: `at-${state.counter}`, refresh_token: `rt-${state.counter}`, expires_in: 900 });
  };
  return { fetchImpl, state };
}

class MemStorage implements VaultStorage {
  map = new Map<string, unknown>();
  async get(key: string) {
    return this.map.get(key);
  }
  async put(key: string, value: unknown) {
    this.map.set(key, value);
  }
  async delete(key: string) {
    return this.map.delete(key);
  }
}

function vault(fake: ReturnType<typeof makeIdentityFake>, storage: VaultStorage, now: () => number = () => NOW_MS) {
  return new TokenVault({ storage, creds: CREDS, sealSecret: "seal-secret", fetchImpl: fake.fetchImpl, now });
}

const req = (seed = "rt-grant", force?: boolean) => ({ userHash: USER_HASH, seedRefreshToken: seed, force });

describe("TokenVault", () => {
  it("seeds the chain from the grant token, then serves the cached access token", async () => {
    const fake = makeIdentityFake();
    const storage = new MemStorage();
    const v = vault(fake, storage);
    expect(await v.getToken(req())).toMatchObject({ ok: true, accessToken: "at-1" });
    expect(await v.getToken(req())).toMatchObject({ ok: true, accessToken: "at-1" });
    expect(fake.state.refreshes).toBe(1);
    // A different vault over the same storage (DO restarted) needs no refresh.
    expect(await vault(fake, storage).getToken(req())).toMatchObject({ ok: true, accessToken: "at-1" });
    expect(fake.state.refreshes).toBe(1);
  });

  it("stores only sealed data — no token material in the clear", async () => {
    const fake = makeIdentityFake();
    const storage = new MemStorage();
    await vault(fake, storage).getToken(req());
    expect(storage.map.size).toBeGreaterThan(0);
    for (const value of storage.map.values()) {
      expect(String(value)).not.toMatch(/at-|rt-/);
    }
  });

  it("refreshes with the rotated token once expired, not the dead seed", async () => {
    const fake = makeIdentityFake();
    const storage = new MemStorage();
    await vault(fake, storage).getToken(req());
    const later = vault(fake, storage, () => NOW_MS + 2_000_000);
    expect(await later.getToken(req())).toMatchObject({ ok: true, accessToken: "at-2" });
    expect(fake.state.refreshes).toBe(2);
    expect(fake.state.attempts).toBe(2); // never even tried the dead grant token
  });

  it("shares one rotation between concurrent requests", async () => {
    const fake = makeIdentityFake();
    const v = vault(fake, new MemStorage());
    const results = await Promise.all(Array.from({ length: 5 }, () => v.getToken(req())));
    for (const r of results) expect(r).toMatchObject({ ok: true, accessToken: "at-1" });
    expect(fake.state.refreshes).toBe(1);
  });

  it("force rotates even while the access token is fresh", async () => {
    const fake = makeIdentityFake();
    const storage = new MemStorage();
    const v = vault(fake, storage);
    await v.getToken(req());
    expect(await v.getToken(req("rt-grant", true))).toMatchObject({ ok: true, accessToken: "at-2" });
    expect(fake.state.refreshes).toBe(2);
  });

  it("reports a dead chain with the same seed as an auth failure", async () => {
    const fake = makeIdentityFake();
    const storage = new MemStorage();
    const v = vault(fake, storage);
    await v.getToken(req());
    fake.state.valid.clear(); // MFP revoked everything (password change)
    const r = await v.getToken(req("rt-grant", true));
    expect(r).toMatchObject({ ok: false, auth: true, status: 401 });
  });

  it("recovers a dead chain when a new seed arrives (the user reconnected)", async () => {
    const fake = makeIdentityFake();
    const storage = new MemStorage();
    await vault(fake, storage).getToken(req());
    fake.state.valid.delete("rt-1"); // the chain dies
    fake.state.valid.add("rt-reconnect"); // a fresh grant from a new sign-in
    const r = await vault(fake, storage).getToken(req("rt-reconnect", true));
    expect(r).toMatchObject({ ok: true, accessToken: "at-2" });
    // And the new chain keeps rotating from there.
    const r2 = await vault(fake, storage).getToken(req("rt-reconnect", true));
    expect(r2).toMatchObject({ ok: true, accessToken: "at-3" });
  });

  it("purges the chain and reseeds from the grant on next use", async () => {
    const fake = makeIdentityFake();
    const storage = new MemStorage();
    const v = vault(fake, storage);
    await v.getToken(req());
    await v.purge();
    expect(await v.peek()).toEqual({ expiresAt: undefined });
    fake.state.valid.add("rt-grant2");
    expect(await v.getToken(req("rt-grant2"))).toMatchObject({ ok: true, accessToken: "at-2" });
  });

  it("migrates via the legacy KV token when the grant seed is already dead, without replaying the seed", async () => {
    const fake = makeIdentityFake();
    fake.state.valid.clear();
    fake.state.valid.add("rt-legacy"); // the old sealed-KV chain's rotated token
    const v = vault(fake, new MemStorage());
    const r = await v.getToken({ ...req("rt-grant"), legacyRefreshToken: "rt-legacy" });
    expect(r).toMatchObject({ ok: true, accessToken: "at-1" });
    // The dead grant seed was never sent — replaying a consumed token can trip
    // reuse detection and revoke the whole family.
    expect(fake.state.attempts).toBe(1);
  });

  it("ignores a stale legacy token once a chain exists", async () => {
    const fake = makeIdentityFake();
    const storage = new MemStorage();
    await vault(fake, storage).getToken(req());
    const later = vault(fake, storage, () => NOW_MS + 2_000_000);
    const r = await later.getToken({ ...req(), legacyRefreshToken: "rt-stale" });
    expect(r).toMatchObject({ ok: true, accessToken: "at-2" });
    expect(fake.state.attempts).toBe(2); // chain refreshes only; rt-stale never sent
  });

  it("falls through dead chain and dead legacy to a genuinely new seed", async () => {
    const fake = makeIdentityFake();
    const storage = new MemStorage();
    await vault(fake, storage).getToken(req());
    fake.state.valid.clear(); // chain revoked
    fake.state.valid.add("rt-reconnect");
    const r = await vault(fake, storage).getToken({ ...req("rt-reconnect", true), legacyRefreshToken: "rt-dead-legacy" });
    expect(r).toMatchObject({ ok: true, accessToken: "at-2" });
  });

  it("peek reports the stored expiry without touching the network", async () => {
    const fake = makeIdentityFake();
    const storage = new MemStorage();
    await vault(fake, storage).getToken(req());
    const attempts = fake.state.attempts;
    expect(await vault(fake, storage).peek()).toEqual({ expiresAt: NOW_MS + 900_000 });
    expect(fake.state.attempts).toBe(attempts);
  });
});

describe("refreshTokenSet expiry", () => {
  const jwtWithExp = (expMs: number) => `${b64url('{"alg":"none"}')}.${b64url(JSON.stringify({ exp: Math.floor(expMs / 1000) }))}.sig`;

  const fakeIssuing = (accessToken: string, expiresIn = 900) => {
    const fetchImpl: typeof fetch = async () =>
      new Response(JSON.stringify({ access_token: accessToken, refresh_token: "rt-next", expires_in: expiresIn }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    return fetchImpl;
  };

  it("trusts a JWT exp longer than expires_in (less refresh churn, sturdier chain)", async () => {
    const exp = NOW_MS + 2 * 60 * 60 * 1000;
    const t = await refreshTokenSet(CREDS, "rt-old", { deviceId: "d", fetchImpl: fakeIssuing(jwtWithExp(exp)), now: () => NOW_MS });
    expect(t.expiresAt).toBe(exp);
  });

  it("ignores an implausible exp (>24h) and keeps expires_in", async () => {
    const t = await refreshTokenSet(CREDS, "rt-old", {
      deviceId: "d",
      fetchImpl: fakeIssuing(jwtWithExp(NOW_MS + 48 * 60 * 60 * 1000)),
      now: () => NOW_MS,
    });
    expect(t.expiresAt).toBe(NOW_MS + 900_000);
  });

  it("keeps expires_in for an opaque access token", async () => {
    const t = await refreshTokenSet(CREDS, "rt-old", { deviceId: "d", fetchImpl: fakeIssuing("opaque-token"), now: () => NOW_MS });
    expect(t.expiresAt).toBe(NOW_MS + 900_000);
  });
});

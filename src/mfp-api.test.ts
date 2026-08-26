/**
 * End-to-end tests of the client against a fake MyFitnessPal backend that
 * speaks the real wire format: the identity service verifies the HS512 JWT
 * the client signs (with node:crypto), issues/rotates tokens, and the API
 * enforces bearer + mfp-user-id headers, rejects unknown diary types/fields
 * on demand, and paginates with Link headers.
 */
import { describe, it, expect } from "vitest";
import { createHmac } from "node:crypto";
import { API_BASE, DIARY_FIELD_SETS, IDENTITY_BASE, MfpAuthError, MfpClient, deviceIdFor, loginWithPassword } from "./mfp-api";

const CREDS = { clientId: "cid", clientSecret: "csec" };
const SIGNING_KEY = new Uint8Array(64).map((_, i) => (i * 7) & 0xff);
const KID = "kid-1";
const DOMAIN_USER = "2320694511409";
const NOW_MS = Date.parse("2026-08-26T12:00:00Z"); // "today" in UTC = 2026-08-26
const TZ = "UTC";

const b64url = (s: string | Uint8Array) => Buffer.from(s).toString("base64url");
const idToken = (sub: string) => `${b64url('{"alg":"HS512"}')}.${b64url(JSON.stringify({ sub }))}.sig`;

type RawItem = Record<string, unknown>;

interface FakeOptions {
  password?: string;
  /** "any": reject every request with fields[]; "rich": reject only the long set. */
  rejectFields?: "any" | "rich";
  rejectTypes?: string[];
  pageSize?: number;
  items?: (date: string) => RawItem[];
  measurements?: (date: string) => RawItem[];
  tokenTtlSec?: number;
}

function defaultItems(date: string): RawItem[] {
  return [
    { id: `${date}-f1`, type: "food_entry", date, meal_name: "Breakfast", meal_position: 0, food: { id: "f1", description: "Oats" }, servings: 1, serving_size: { value: 40, unit: "g" }, nutritional_contents: { energy: { unit: "calories", value: 150 }, protein: 5 } },
    { id: `${date}-f2`, type: "food_entry", date, meal_name: "Lunch", meal_position: 1, food: { id: "f2", description: "Chicken" }, servings: 1, serving_size: { value: 150, unit: "g" }, nutritional_contents: { energy: { unit: "calories", value: 250 }, protein: 45 } },
    { type: "diary_meal", date, diary_meal: "Breakfast", nutritional_contents: { energy: { unit: "calories", value: 150 }, protein: 5 } },
    { type: "diary_meal", date, diary_meal: "Lunch", nutritional_contents: { energy: { unit: "calories", value: 250 }, protein: 45 } },
    { id: `${date}-e1`, type: "exercise_entry", date, exercise: { id: "x", description: "Run" }, duration: 1800, energy: { unit: "calories", value: 300 } },
    { type: "water", date, cups: 4, milliliters: 946 },
    { type: "steps_aggregate", date, steps: 7000, primary: true },
  ];
}

function makeFake(opts: FakeOptions = {}) {
  const state = {
    requests: [] as string[],
    diaryRequests: [] as string[],
    logins: 0,
    refreshes: 0,
    tokenCounter: 0,
    accessTokens: new Set<string>(),
    refreshTokens: new Set<string>(["rt-grant"]),
    revoked: new Set<string>(),
  };
  const issue = () => {
    state.tokenCounter++;
    const at = `at-${state.tokenCounter}`;
    const rt = `rt-${state.tokenCounter}`;
    state.accessTokens.add(at);
    state.refreshTokens.add(rt);
    return { access_token: at, refresh_token: rt, expires_in: opts.tokenTtlSec ?? 900, id_token: idToken("identity-123"), token_type: "Bearer" };
  };
  const json = (status: number, body: unknown, headers: Record<string, string> = {}) =>
    new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });
  const bad = (msg: string) => json(400, { error: msg });

  const fetchImpl: typeof fetch = async (input, init) => {
    const url = new URL(String(input));
    const path = url.pathname;
    state.requests.push(`${init?.method ?? "GET"} ${path}${url.search}`);
    const headers = new Headers(init?.headers as HeadersInit);
    if (headers.get("mfp-client-id") !== "mfp-mobile-android-google") return bad("missing mfp-client-id");
    if (!headers.get("user-agent")?.startsWith("MyFitnessPal/")) return bad("missing user-agent");

    if (url.origin === IDENTITY_BASE) {
      if (path === "/oauth/token") {
        const form = new URLSearchParams(String(init?.body));
        const grant = form.get("grant_type");
        if (grant === "client_credentials") {
          return form.get("client_id") === CREDS.clientId && form.get("client_secret") === CREDS.clientSecret
            ? json(200, { access_token: "client-token", expires_in: 900, token_type: "Bearer" })
            : json(401, { error: "invalid_client" });
        }
        if (grant === "authorization_code") {
          if (form.get("redirect_uri") !== "mfp://identity/callback") return bad("redirect_uri");
          return form.get("code") === "code-xyz" ? json(200, issue()) : json(400, { error: "invalid_grant" });
        }
        if (grant === "refresh_token") {
          const rt = form.get("refresh_token") ?? "";
          if (form.get("client_secret") !== CREDS.clientSecret) return json(401, { error: "invalid_client" });
          if (!state.refreshTokens.has(rt) || state.revoked.has(rt)) return json(401, { error: "invalid_grant" });
          state.refreshes++;
          state.refreshTokens.delete(rt); // rotation: the old refresh token dies
          return json(200, issue());
        }
        return bad("grant");
      }
      if (path === "/clientKeys") {
        if (headers.get("Authorization") !== `Basic ${btoa("cid:csec")}`) return json(401, { error: "basic" });
        return json(200, {
          _embedded: {
            clientKeys: [
              { key: { kty: "oct", use: "enc", kid: "enc-1", k: "AAAA", alg: "dir" } },
              { key: { kty: "oct", use: "sig", kid: KID, k: b64url(SIGNING_KEY), alg: "HS512" } },
            ],
          },
        });
      }
      if (path === "/oauth/authorize") {
        state.logins++;
        if (headers.get("Authorization") !== "Bearer client-token") return json(401, { error: "client token" });
        const form = new URLSearchParams(String(init?.body));
        if (form.get("response_type") !== "code" || form.get("scope") !== "openid" || !form.get("nonce")) return bad("params");
        const [h, p, s] = (form.get("credentials") ?? "").split(".");
        if (s !== createHmac("sha512", Buffer.from(SIGNING_KEY)).update(`${h}.${p}`).digest("base64url")) return json(401, { error: "bad signature" });
        if (JSON.parse(Buffer.from(h, "base64url").toString()).kid !== KID) return json(401, { error: "bad kid" });
        const payload = JSON.parse(Buffer.from(p, "base64url").toString());
        if (payload.username !== "me@example.com" || payload.password !== (opts.password ?? "pw")) {
          // What the live identity service does for bad credentials.
          return new Response(null, { status: 302, headers: { Location: "mfp://identity/callback?error=access_denied&error_description=Access+denied+by+resource+owner+or+authorization+server" } });
        }
        return new Response(null, { status: 302, headers: { Location: "mfp://identity/callback?code=code-xyz&state=x" } });
      }
      if (path.startsWith("/users/")) {
        const bearer = headers.get("Authorization")?.replace("Bearer ", "") ?? "";
        if (!state.accessTokens.has(bearer) || state.revoked.has(bearer)) return json(401, { error: "unauthorized" });
        return json(200, {
          userId: 123,
          region: "GB",
          status: "ACTIVE",
          profile: { firstName: "Aidan", lastName: null, height: 70.9, weight: 194, birthdate: "1990-05-04", gender: "M", locale: "en-GB" },
          profileEmails: { emails: [{ email: "me@example.com", primary: true }] },
          accountLinks: [
            { domain: "UACF", domainUserId: "1" },
            { domain: "MFP", domainUserId: DOMAIN_USER },
          ],
        });
      }
      return json(404, {});
    }

    if (url.origin !== API_BASE) return json(404, { error: "host" });
    const bearer = headers.get("Authorization")?.replace("Bearer ", "") ?? "";
    if (!state.accessTokens.has(bearer) || state.revoked.has(bearer)) return json(401, { error: "unauthorized" });
    if (headers.get("mfp-user-id") !== DOMAIN_USER) return bad("mfp-user-id");
    if (headers.get("api-version") !== "2.0.50") return bad("api-version");

    if (path === "/v2/diary") {
      state.diaryRequests.push(url.search);
      const fields = url.searchParams.getAll("fields[]");
      const types = (url.searchParams.get("types") ?? "").split(",").filter(Boolean);
      if (opts.rejectFields === "any" && fields.length) return bad("unknown field");
      if (opts.rejectFields === "rich" && fields.length > 4) return bad("unknown field");
      if (opts.rejectTypes?.some((t) => types.includes(t))) return bad("unknown type");
      const date = url.searchParams.get("entry_date") ?? "";
      const all = (opts.items ?? defaultItems)(date).filter((i) => !types.length || types.includes(String(i.type)));
      const pageSize = opts.pageSize ?? 100;
      const page = parseInt(url.searchParams.get("page") ?? "1", 10);
      const slice = all.slice((page - 1) * pageSize, page * pageSize);
      const hasNext = page * pageSize < all.length;
      const link: Record<string, string> = hasNext ? { Link: `<${API_BASE}/v2/diary?page=${page + 1}&entry_date=${date}&types=${types.join(",")}&max_items=${pageSize}>; rel=next` } : {};
      return json(200, { items: slice }, link);
    }
    if (path === "/v2/measurements") {
      return json(200, { items: (opts.measurements ?? (() => []))(url.searchParams.get("entry_date") ?? "") });
    }
    return json(404, { error: "not found" });
  };

  return {
    fetchImpl,
    state,
    revokeAccess: () => {
      for (const t of state.accessTokens) state.revoked.add(t);
    },
  };
}

class FakeKV {
  store = new Map<string, string>();
  async get(key: string) {
    return this.store.get(key) ?? null;
  }
  async put(key: string, value: string) {
    this.store.set(key, value);
  }
  async delete(key: string) {
    this.store.delete(key);
  }
  async list({ prefix }: { prefix?: string; cursor?: string }) {
    return { keys: Array.from(this.store.keys()).filter((k) => !prefix || k.startsWith(prefix)).map((name) => ({ name })), list_complete: true as const, cursor: undefined };
  }
}

function client(fake: ReturnType<typeof makeFake>, extra: Partial<ConstructorParameters<typeof MfpClient>[0]> = {}, now: () => number = () => NOW_MS) {
  return new MfpClient({
    creds: CREDS,
    userId: "identity-123",
    domainUserId: DOMAIN_USER,
    refreshToken: "rt-grant",
    userHash: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
    timeZone: TZ,
    fetchImpl: fake.fetchImpl,
    now,
    ...extra,
  });
}

describe("loginWithPassword (identity flow)", () => {
  it("signs the credentials JWT with the served key, exchanges the code, and resolves the MFP domain user", async () => {
    const fake = makeFake();
    const r = await loginWithPassword(CREDS, "me@example.com", "pw", { deviceId: deviceIdFor("abc"), fetchImpl: fake.fetchImpl, now: () => NOW_MS });
    expect(r.userId).toBe("identity-123");
    expect(r.domainUserId).toBe(DOMAIN_USER);
    expect(r.email).toBe("me@example.com");
    expect(r.accessToken).toBe("at-1");
    expect(r.refreshToken).toBe("rt-1");
    expect(r.expiresAt).toBe(NOW_MS + 900_000);
    expect(fake.state.requests.map((r) => r.split("?")[0])).toEqual([
      "POST /oauth/token",
      "GET /clientKeys",
      "POST /oauth/authorize",
      "POST /oauth/token",
      "GET /users/identity-123",
    ]);
  });

  it("surfaces a wrong password (access_denied redirect) as a readable MfpAuthError", async () => {
    const fake = makeFake({ password: "other" });
    await expect(loginWithPassword(CREDS, "me@example.com", "pw", { deviceId: "d", fetchImpl: fake.fetchImpl })).rejects.toThrow(MfpAuthError);
    await expect(loginWithPassword(CREDS, "me@example.com", "pw", { deviceId: "d", fetchImpl: fake.fetchImpl })).rejects.toThrow(
      /rejected the sign-in: Access denied by resource owner or authorization server — check the email/,
    );
  });

  it("derives a UUID-shaped device id from the user hash", () => {
    expect(deviceIdFor("abcdef0123456789abcdef0123456789")).toBe("abcdef01-2345-6789-abcd-ef0123456789");
  });
});

describe("token lifecycle", () => {
  it("refreshes with the grant token on first use, then rotates via KV", async () => {
    const kv = new FakeKV();
    const fake = makeFake();
    const c = client(fake, { cache: kv as unknown as KVNamespace, sealSecret: "s" });
    expect(await c.getAccessToken()).toBe("at-1");
    expect(fake.state.refreshes).toBe(1);
    // A fresh client (new DO) finds the sealed token in KV: no refresh.
    const c2 = client(fake, { cache: kv as unknown as KVNamespace, sealSecret: "s" });
    expect(await c2.getAccessToken()).toBe("at-1");
    expect(fake.state.refreshes).toBe(1);
    // Later, expired: the rotated refresh token (rt-1) is used, not the dead grant token.
    const c3 = client(fake, { cache: kv as unknown as KVNamespace, sealSecret: "s" }, () => NOW_MS + 2_000_000);
    expect(await c3.getAccessToken()).toBe("at-2");
    expect(fake.state.refreshes).toBe(2);
    for (const v of kv.store.values()) expect(v).not.toMatch(/at-|rt-/);
  });

  it("uses the grant's access token while fresh and re-authenticates once on a 401", async () => {
    const fake = makeFake();
    fake.state.accessTokens.add("at-grant");
    const c = client(fake, { accessToken: "at-grant", accessTokenExpiresAt: NOW_MS + 600_000 });
    await c.getDiary("2026-08-26");
    expect(fake.state.refreshes).toBe(0);
    fake.revokeAccess();
    await c.getDiary("2026-08-26", { noCache: true });
    expect(fake.state.refreshes).toBe(1);
    expect(await c.getAccessToken()).toBe("at-1");
  });

  it("reports a dead refresh token as MfpAuthError", async () => {
    const fake = makeFake();
    fake.state.refreshTokens.clear();
    await expect(client(fake).getAccessToken()).rejects.toThrow(MfpAuthError);
  });
});

describe("getDiary", () => {
  it("fetches with the rich request when the API accepts it, and paginates via Link", async () => {
    const fake = makeFake({ pageSize: 3 });
    const f = await client(fake).getDiary("2026-08-25");
    expect(f.items.length).toBe(7);
    expect(f.pages).toBe(3);
    expect(f.types).toEqual(["food_entry", "diary_meal", "exercise_entry", "water", "steps_aggregate"]);
    expect(f.fields).toEqual([...DIARY_FIELD_SETS[0]]);
    expect(fake.state.diaryRequests[0]).toContain("fields%5B%5D=nutritional_contents");
  });

  it("steps down to a smaller field set when the API rejects the rich one, and remembers it", async () => {
    const kv = new FakeKV();
    const fake = makeFake({ rejectFields: "rich" });
    const c = client(fake, { cache: kv as unknown as KVNamespace, sealSecret: "s" });
    const f = await c.getDiary("2026-08-25");
    expect(f.fields).toEqual([...DIARY_FIELD_SETS[1]]);
    expect(f.items.length).toBe(7);
    expect(fake.state.diaryRequests.length).toBe(2);
    // Next day goes straight to the remembered combination, even from a new client.
    const c2 = client(fake, { cache: kv as unknown as KVNamespace, sealSecret: "s" });
    await c2.getDiary("2026-08-24");
    expect(fake.state.diaryRequests.length).toBe(3);
  });

  it("falls back to one type at a time and reports the rejected ones", async () => {
    const fake = makeFake({ rejectTypes: ["steps_aggregate"] });
    const f = await client(fake).getDiary("2026-08-25");
    expect(f.rejected_types).toEqual(["steps_aggregate"]);
    expect(f.types).toEqual(["food_entry", "diary_meal", "exercise_entry", "water"]);
    expect(f.items.length).toBe(6);
    expect(f.items.some((i) => i.type === "steps_aggregate")).toBe(false);
  });

  it("caches completed days but never today", async () => {
    const kv = new FakeKV();
    const fake = makeFake();
    const c = client(fake, { cache: kv as unknown as KVNamespace, sealSecret: "s" });
    await c.getDiary("2026-08-25");
    await c.getDiary("2026-08-26");
    const before = fake.state.diaryRequests.length;
    const again = await c.getDiary("2026-08-25");
    expect(again.cached).toBe(true);
    await c.getDiary("2026-08-26");
    expect(fake.state.diaryRequests.length).toBe(before + 1);
    expect(await c.purgeCache()).toBeGreaterThanOrEqual(3); // token, diary-config, one day
  });

  it("honours an explicit types/fields request without discovery", async () => {
    const fake = makeFake();
    const f = await client(fake).getDiary("2026-08-25", { types: ["water"], fields: ["cups"] });
    expect(f.items).toEqual([{ type: "water", date: "2026-08-25", cups: 4, milliliters: 946 }]);
    expect(fake.state.diaryRequests[0]).toContain("types=water");
    expect(fake.state.diaryRequests[0]).toContain("fields%5B%5D=cups");
  });
});

describe("measurements, identity profile, probes", () => {
  it("reads measurements and the identity profile, and probes without throwing", async () => {
    const fake = makeFake({ measurements: (d) => [{ id: "m1", type: "weight", value: 88.2, unit: "kilograms", date: d }] });
    const c = client(fake);
    expect(await c.getMeasurements("2026-08-25")).toEqual([{ id: "m1", type: "weight", value: 88.2, unit: "kilograms", date: "2026-08-25" }]);
    const user = await c.getIdentityUser();
    expect(user.accountLinks?.[1].domainUserId).toBe(DOMAIN_USER);
    const ok = await c.probe("v2/measurements", { entry_date: "2026-08-25" });
    expect(ok.ok).toBe(true);
    const missing = await c.probe("v2/nutrient-goals");
    expect(missing).toMatchObject({ ok: false, status: 404 });
  });
});

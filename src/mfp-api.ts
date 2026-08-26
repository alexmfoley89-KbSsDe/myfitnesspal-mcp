/**
 * Client for MyFitnessPal's mobile-app backend — the same v2 REST API the
 * (closed) partner programme documents at myfitnesspalapi.com, reached with
 * the mobile app's own OAuth client (credit: seonixx/myfitnesspal and
 * jnelle/MyFitnesspal-API-Golang for the identity flow).
 *
 * Sign-in (once, on the /authorize page):
 *   1. POST identity/oauth/token  grant_type=client_credentials     -> client token
 *   2. GET  identity/clientKeys   (Basic client_id:client_secret)   -> HS512 signing key + kid
 *   3. POST identity/oauth/authorize  credentials=<HS512 JWT {username,password}>
 *      Authorization: Bearer <client token>                         -> 302 mfp://identity/callback?code=…
 *   4. POST identity/oauth/token  grant_type=authorization_code     -> access + refresh + id tokens
 *   5. GET  identity/users/{sub}?fetch_profile=true&fetch_emails=true -> MFP domain user id, profile
 *
 * Thereafter the Worker only ever uses the refresh token. API calls go to
 * api.myfitnesspal.com/v2 with `Authorization: Bearer`, `mfp-user-id` and
 * `mfp-client-id`.
 *
 * Responsibilities here: token lifecycle (memory → sealed KV → refresh),
 * transport with retry / re-auth, Link-header pagination, a self-tuning diary
 * fetch (the exact `types`/`fields[]` the mobile token accepts are not
 * documented, so it discovers a working combination and remembers it), and
 * caching of completed diary days. Shaping for Claude lives in shape.ts.
 */
import { decodeJwtPayload, base64UrlDecode, deriveSealKey, open, seal, signHs512Jwt } from "./crypto";

export const IDENTITY_BASE = "https://identity-api.myfitnesspal.com";
export const API_BASE = "https://api.myfitnesspal.com";
const REDIRECT_URI = "mfp://identity/callback";

/** Identifies the calling client to the API; must match the OAuth client. */
export const MFP_CLIENT_ID_HEADER = "mfp-mobile-android-google";
export const API_VERSION = "2.0.50";
export const USER_AGENT =
  "MyFitnessPal/25.19.0 (mfp-mobile-android-google) (Android 11; Pixel 5 / Android Android SDK built for arm64) (preload=false;locale=en_US)";

/** Diary item types the v2 API knows about (partner docs + mobile client). */
export const DIARY_TYPES = ["food_entry", "diary_meal", "exercise_entry", "water", "steps_aggregate"] as const;
export type DiaryType = (typeof DIARY_TYPES)[number];

/**
 * `fields[]` sets tried in order until the API accepts one. The first is the
 * richest guess; the last sends no `fields[]` at all and takes the defaults.
 */
export const DIARY_FIELD_SETS: ReadonlyArray<readonly string[]> = [
  [
    "nutritional_contents",
    "food",
    "serving_size",
    "servings",
    "meal_name",
    "meal_position",
    "exercise",
    "energy",
    "duration",
    "start_time",
    "cups",
    "milliliters",
    "steps",
    "consumed_at",
    "logged_at",
    "tags",
  ],
  ["nutritional_contents", "food", "exercise", "energy"],
  [],
];

/** Completed days never change: cache them for a long time. */
const DAY_CACHE_TTL_SECONDS = 30 * 24 * 60 * 60;
/** The discovered types/fields combination is remembered for a day. */
const CONFIG_TTL_SECONDS = 24 * 60 * 60;
/** Refresh the access token this long before it expires. */
const TOKEN_SAFETY_MS = 60 * 1000;
/** Stop following `Link: rel=next` after this many pages. */
const MAX_PAGES = 10;

const RETRYABLE_HTTP = new Set([408, 429, 500, 502, 503, 504]);
const MAX_HTTP_RETRIES = 2;

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

export class MfpApiError extends Error {
  constructor(
    message: string,
    public readonly status?: number,
    public readonly path?: string,
    public readonly body?: string,
  ) {
    super(message);
    this.name = "MfpApiError";
  }
}

/** Sign-in or token refresh was rejected — the connector must be reconnected. */
export class MfpAuthError extends MfpApiError {
  constructor(message: string, status?: number, body?: string) {
    super(message, status, "oauth", body);
    this.name = "MfpAuthError";
  }
}

export interface OAuthClientCredentials {
  clientId: string;
  clientSecret: string;
}

export interface TokenSet {
  accessToken: string;
  refreshToken: string;
  /** Unix ms. */
  expiresAt: number;
}

export interface IdentityUser {
  userId?: string | number;
  region?: string;
  status?: string;
  profile?: Record<string, unknown>;
  profileEmails?: { emails?: Array<{ email?: string; primary?: boolean }> };
  accountLinks?: Array<{ domain?: string; domainUserId?: string | number }>;
  [k: string]: unknown;
}

export interface LoginResult extends TokenSet {
  /** Identity user id (`sub`). */
  userId: string;
  /** MFP domain user id (the `mfp-user-id` header). */
  domainUserId: string;
  email?: string;
  user: IdentityUser;
}

interface TokenResponse {
  access_token?: string;
  refresh_token?: string;
  expires_in?: number;
  id_token?: string;
  token_type?: string;
  [k: string]: unknown;
}

interface ClientKey {
  key?: { kty?: string; use?: string; kid?: string; k?: string; alg?: string };
  clientId?: string;
  keyId?: string;
}

/** Headers the mobile app sends on every request. */
function appHeaders(deviceId: string, extra: Record<string, string> = {}): Record<string, string> {
  return {
    Accept: "application/json",
    "user-agent": USER_AGENT,
    device_id: deviceId,
    "mfp-device-id": deviceId,
    "mfp-client-id": MFP_CLIENT_ID_HEADER,
    "api-version": API_VERSION,
    "accept-language": "en-US",
    ...extra,
  };
}

/** Stable pseudo device id derived from the user hash (looks like a UUID). */
export function deviceIdFor(userHash: string): string {
  const h = userHash.padEnd(32, "0");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20, 32)}`;
}

async function readBody(res: Response): Promise<string> {
  try {
    return (await res.text()).slice(0, 600);
  } catch {
    return "";
  }
}

function tokenSetFrom(t: TokenResponse, now: number, fallbackRefresh?: string): TokenSet {
  if (!t.access_token) throw new MfpAuthError("Token response did not include an access_token", undefined, JSON.stringify(t).slice(0, 300));
  const expiresIn = typeof t.expires_in === "number" && t.expires_in > 0 ? t.expires_in : 900;
  return {
    accessToken: t.access_token,
    refreshToken: t.refresh_token ?? fallbackRefresh ?? "",
    expiresAt: now + expiresIn * 1000,
  };
}

// ---------------------------------------------------------------------------
// Identity: sign-in with username/password (used by the /authorize page)
// ---------------------------------------------------------------------------

export async function clientCredentialsToken(
  creds: OAuthClientCredentials,
  deviceId: string,
  fetchImpl: typeof fetch = fetch,
): Promise<string> {
  const res = await fetchImpl(`${IDENTITY_BASE}/oauth/token`, {
    method: "POST",
    headers: appHeaders(deviceId, { "Content-Type": "application/x-www-form-urlencoded" }),
    body: new URLSearchParams({ client_id: creds.clientId, client_secret: creds.clientSecret, grant_type: "client_credentials" }),
  });
  if (!res.ok) throw new MfpAuthError(`MyFitnessPal client credentials were rejected (HTTP ${res.status})`, res.status, await readBody(res));
  const json = (await res.json()) as TokenResponse;
  if (!json.access_token) throw new MfpAuthError("Client-credentials response had no access_token");
  return json.access_token;
}

export async function fetchSigningKey(
  creds: OAuthClientCredentials,
  deviceId: string,
  fetchImpl: typeof fetch = fetch,
): Promise<{ key: Uint8Array; kid: string }> {
  const basic = btoa(`${creds.clientId}:${creds.clientSecret}`);
  const res = await fetchImpl(`${IDENTITY_BASE}/clientKeys`, {
    headers: appHeaders(deviceId, { Authorization: `Basic ${basic}` }),
  });
  if (!res.ok) throw new MfpAuthError(`Could not fetch MyFitnessPal signing keys (HTTP ${res.status})`, res.status, await readBody(res));
  const json = (await res.json()) as { _embedded?: { clientKeys?: ClientKey[] } };
  const sig = (json._embedded?.clientKeys ?? []).find((k) => k.key?.use === "sig" && k.key?.alg === "HS512" && k.key.k && k.key.kid);
  if (!sig?.key?.k || !sig.key.kid) throw new MfpAuthError("No HS512 signing key in MyFitnessPal clientKeys response");
  return { key: base64UrlDecode(sig.key.k), kid: sig.key.kid };
}

/**
 * Full password sign-in. Returns tokens plus the MFP domain user id; the
 * password is not retained anywhere.
 */
export async function loginWithPassword(
  creds: OAuthClientCredentials,
  username: string,
  password: string,
  opts: { deviceId: string; fetchImpl?: typeof fetch; now?: () => number },
): Promise<LoginResult> {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const now = opts.now ?? (() => Date.now());
  const deviceId = opts.deviceId;

  const [clientToken, signing] = await Promise.all([
    clientCredentialsToken(creds, deviceId, fetchImpl),
    fetchSigningKey(creds, deviceId, fetchImpl),
  ]);
  const credentials = await signHs512Jwt({ username, password }, signing.key, signing.kid);

  const authRes = await fetchImpl(`${IDENTITY_BASE}/oauth/authorize`, {
    method: "POST",
    redirect: "manual",
    headers: appHeaders(deviceId, {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: `Bearer ${clientToken}`,
    }),
    body: new URLSearchParams({
      client_id: creds.clientId,
      credentials,
      nonce: String(now() * 1000),
      redirect_uri: REDIRECT_URI,
      response_type: "code",
      scope: "openid",
    }),
  });

  const location = authRes.headers.get("Location") ?? authRes.headers.get("location");
  if (!(authRes.status >= 300 && authRes.status < 400) || !location) {
    const body = await readBody(authRes);
    const hint = authRes.status === 401 || authRes.status === 400 || authRes.status === 403 ? "check the email/username and password" : "unexpected response";
    throw new MfpAuthError(`MyFitnessPal sign-in failed (HTTP ${authRes.status}; ${hint})`, authRes.status, body);
  }
  let code: string | null;
  let redirectError: string | null = null;
  try {
    const parsed = new URL(location);
    code = parsed.searchParams.get("code");
    redirectError = parsed.searchParams.get("error_description") ?? parsed.searchParams.get("error");
  } catch {
    code = /[?&]code=([^&]+)/.exec(location)?.[1] ?? null;
    const m = /[?&]error(?:_description)?=([^&]+)/.exec(location);
    redirectError = m ? decodeURIComponent(m[1].replace(/\+/g, " ")) : null;
  }
  if (!code) {
    // Wrong credentials come back as a redirect with error=access_denied
    // rather than a 401 — verified against the live identity service.
    if (redirectError) {
      throw new MfpAuthError(`MyFitnessPal rejected the sign-in: ${redirectError.replace(/\+/g, " ")} — check the email/username and password.`, authRes.status);
    }
    throw new MfpAuthError(`MyFitnessPal sign-in redirect carried no code (${location.slice(0, 120)})`, authRes.status);
  }

  const tokenRes = await fetchImpl(`${IDENTITY_BASE}/oauth/token`, {
    method: "POST",
    headers: appHeaders(deviceId, { "Content-Type": "application/x-www-form-urlencoded" }),
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      client_id: creds.clientId,
      client_secret: creds.clientSecret,
      redirect_uri: REDIRECT_URI,
    }),
  });
  if (!tokenRes.ok) throw new MfpAuthError(`MyFitnessPal code exchange failed (HTTP ${tokenRes.status})`, tokenRes.status, await readBody(tokenRes));
  const tokenJson = (await tokenRes.json()) as TokenResponse;
  const tokens = tokenSetFrom(tokenJson, now());
  if (!tokens.refreshToken) throw new MfpAuthError("MyFitnessPal did not issue a refresh token", tokenRes.status);

  let userId: string | undefined;
  if (tokenJson.id_token) {
    try {
      userId = String(decodeJwtPayload(tokenJson.id_token).sub ?? "");
    } catch {
      userId = undefined;
    }
  }
  if (!userId) throw new MfpAuthError("MyFitnessPal id_token did not identify the user");

  const user = await fetchIdentityUser(userId, tokens.accessToken, deviceId, fetchImpl);
  const domainUserId = String((user.accountLinks ?? []).find((l) => l.domain === "MFP")?.domainUserId ?? "");
  if (!domainUserId) throw new MfpAuthError("MyFitnessPal account has no MFP domain link");
  const email = user.profileEmails?.emails?.find((e) => e.primary)?.email ?? user.profileEmails?.emails?.[0]?.email;

  return { ...tokens, userId, domainUserId, email, user };
}

export async function fetchIdentityUser(
  userId: string,
  accessToken: string,
  deviceId: string,
  fetchImpl: typeof fetch = fetch,
): Promise<IdentityUser> {
  const res = await fetchImpl(`${IDENTITY_BASE}/users/${encodeURIComponent(userId)}?fetch_profile=true&fetch_emails=true`, {
    headers: appHeaders(deviceId, { Authorization: `Bearer ${accessToken}` }),
  });
  if (!res.ok) throw new MfpApiError(`Identity user lookup failed (HTTP ${res.status})`, res.status, "users", await readBody(res));
  return (await res.json()) as IdentityUser;
}

// ---------------------------------------------------------------------------
// API client
// ---------------------------------------------------------------------------

export interface MfpClientOptions {
  creds: OAuthClientCredentials;
  userId: string;
  domainUserId: string;
  /** Refresh token from the grant (the newest rotated one is kept in KV). */
  refreshToken: string;
  /** Access token from the grant, if still fresh. */
  accessToken?: string;
  accessTokenExpiresAt?: number;
  userHash: string;
  timeZone: string;
  cache?: KVNamespace;
  sealSecret?: string;
  fetchImpl?: typeof fetch;
  now?: () => number;
}

export interface DiaryFetch {
  date: string;
  items: Record<string, unknown>[];
  /** The types/fields combination that succeeded. */
  types: string[];
  fields: string[];
  pages: number;
  /** Types that had to be dropped because the API rejected them. */
  rejected_types?: string[];
  cached: boolean;
}

interface DiaryConfig {
  types: string[];
  fields: string[];
}

export interface ProbeResult {
  path: string;
  status: number | null;
  ok: boolean;
  sample?: string;
  error?: string;
}

export class MfpClient {
  private readonly creds: OAuthClientCredentials;
  readonly userId: string;
  readonly domainUserId: string;
  private readonly grantRefreshToken: string;
  private readonly userHash: string;
  readonly timeZone: string;
  private readonly cache?: KVNamespace;
  private readonly sealSecret?: string;
  private readonly fetchImpl: typeof fetch;
  private readonly now: () => number;
  private readonly deviceId: string;

  private token?: TokenSet;
  private sealKeyPromise?: Promise<CryptoKey>;
  private refreshInFlight?: Promise<TokenSet>;
  private identityUser?: IdentityUser;
  private diaryConfig?: DiaryConfig;

  constructor(opts: MfpClientOptions) {
    this.creds = opts.creds;
    this.userId = opts.userId;
    this.domainUserId = opts.domainUserId;
    this.grantRefreshToken = opts.refreshToken;
    this.userHash = opts.userHash;
    this.timeZone = opts.timeZone;
    this.cache = opts.cache;
    this.sealSecret = opts.sealSecret;
    this.fetchImpl = opts.fetchImpl ?? ((input, init) => fetch(input, init));
    this.now = opts.now ?? (() => Date.now());
    this.deviceId = deviceIdFor(opts.userHash);
    if (opts.accessToken && opts.accessTokenExpiresAt) {
      this.token = { accessToken: opts.accessToken, refreshToken: opts.refreshToken, expiresAt: opts.accessTokenExpiresAt };
    }
  }

  // -------------------------------------------------------------------------
  // Cache primitives (all values sealed; failures never break a request)
  // -------------------------------------------------------------------------

  get cacheEnabled(): boolean {
    return Boolean(this.cache && this.sealSecret);
  }

  private sealKey(): Promise<CryptoKey> {
    if (!this.sealKeyPromise) this.sealKeyPromise = deriveSealKey(this.sealSecret!);
    return this.sealKeyPromise;
  }

  private key(...parts: Array<string | number>): string {
    return `v1:${this.userHash}:${parts.join(":")}`;
  }

  private async cacheGet<T>(key: string): Promise<T | undefined> {
    if (!this.cacheEnabled) return undefined;
    try {
      const sealed = await this.cache!.get(key, "text");
      if (!sealed) return undefined;
      return JSON.parse(await open(await this.sealKey(), sealed)) as T;
    } catch {
      return undefined;
    }
  }

  private async cachePut(key: string, value: unknown, ttlSeconds: number): Promise<void> {
    if (!this.cacheEnabled) return;
    try {
      const sealed = await seal(await this.sealKey(), JSON.stringify(value));
      await this.cache!.put(key, sealed, { expirationTtl: Math.max(60, Math.floor(ttlSeconds)) });
    } catch {
      // A failed write just means no caching this time.
    }
  }

  /** Delete every cached entry for this user (tokens, config, diary days). */
  async purgeCache(): Promise<number> {
    this.token = undefined;
    this.diaryConfig = undefined;
    this.identityUser = undefined;
    if (!this.cache) return 0;
    const prefix = this.key("");
    let count = 0;
    let cursor: string | undefined;
    do {
      const page = await this.cache.list({ prefix, cursor });
      await Promise.all(page.keys.map((k) => this.cache!.delete(k.name)));
      count += page.keys.length;
      cursor = page.list_complete ? undefined : page.cursor;
    } while (cursor);
    return count;
  }

  // -------------------------------------------------------------------------
  // Tokens
  // -------------------------------------------------------------------------

  private usable(t: TokenSet | undefined): t is TokenSet {
    return Boolean(t && t.accessToken && t.expiresAt - TOKEN_SAFETY_MS > this.now());
  }

  /** A valid access token: memory → sealed KV → refresh. */
  async getAccessToken(force = false): Promise<string> {
    if (!force && this.usable(this.token)) return this.token.accessToken;

    const stored = await this.cacheGet<TokenSet>(this.key("token"));
    if (!force && this.usable(stored)) {
      this.token = stored;
      return stored.accessToken;
    }

    // The newest refresh token wins: KV (rotated) > memory > grant.
    const refreshToken = stored?.refreshToken || this.token?.refreshToken || this.grantRefreshToken;
    if (!this.refreshInFlight) {
      this.refreshInFlight = this.refresh(refreshToken).finally(() => (this.refreshInFlight = undefined));
    }
    const fresh = await this.refreshInFlight;
    this.token = fresh;
    await this.cachePut(this.key("token"), fresh, 30 * 24 * 60 * 60);
    return fresh.accessToken;
  }

  /** Current token state, for diagnostics. */
  async peekToken(): Promise<{ source: "memory" | "kv" | "none"; expiresAt?: number }> {
    if (this.token) return { source: "memory", expiresAt: this.token.expiresAt };
    const stored = await this.cacheGet<TokenSet>(this.key("token"));
    return stored ? { source: "kv", expiresAt: stored.expiresAt } : { source: "none" };
  }

  private async refresh(refreshToken: string): Promise<TokenSet> {
    if (!refreshToken) throw new MfpAuthError("No refresh token available — reconnect the connector");
    const res = await this.fetchImpl(`${IDENTITY_BASE}/oauth/token`, {
      method: "POST",
      headers: appHeaders(this.deviceId, { "Content-Type": "application/x-www-form-urlencoded" }),
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: refreshToken,
        client_id: this.creds.clientId,
        client_secret: this.creds.clientSecret,
      }),
    });
    if (!res.ok) {
      throw new MfpAuthError(`MyFitnessPal token refresh failed (HTTP ${res.status}) — reconnect the connector`, res.status, await readBody(res));
    }
    return tokenSetFrom((await res.json()) as TokenResponse, this.now(), refreshToken);
  }

  // -------------------------------------------------------------------------
  // Transport
  // -------------------------------------------------------------------------

  private async authHeaders(extra: Record<string, string> = {}): Promise<Record<string, string>> {
    return appHeaders(this.deviceId, {
      Authorization: `Bearer ${await this.getAccessToken()}`,
      "mfp-user-id": this.domainUserId,
      ...extra,
    });
  }

  /**
   * Authenticated request to api.myfitnesspal.com (or an absolute URL, e.g.
   * a `Link: rel=next` page). Array query values are repeated as `name[]`.
   * On 401 the token is refreshed and the call retried once; transient
   * statuses back off and retry.
   */
  async request(
    path: string,
    opts: { method?: string; query?: Record<string, string | string[] | undefined>; body?: unknown; base?: "api" | "identity" } = {},
    state: { attempt: number; retriedAuth: boolean } = { attempt: 0, retriedAuth: false },
  ): Promise<{ status: number; json: unknown; headers: Headers }> {
    const url = new URL(
      /^https?:\/\//.test(path) ? path : `${opts.base === "identity" ? IDENTITY_BASE : API_BASE}/${path.replace(/^\/+/, "")}`,
    );
    for (const [k, v] of Object.entries(opts.query ?? {})) {
      if (v === undefined) continue;
      if (Array.isArray(v)) for (const item of v) url.searchParams.append(k.endsWith("[]") ? k : `${k}[]`, item);
      else url.searchParams.set(k, v);
    }

    let res: Response;
    try {
      res = await this.fetchImpl(url.toString(), {
        method: opts.method ?? "GET",
        headers: await this.authHeaders(opts.body !== undefined ? { "Content-Type": "application/json" } : {}),
        body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
      });
    } catch (err) {
      if (state.attempt < MAX_HTTP_RETRIES) {
        await sleep(backoffMs(state.attempt));
        return this.request(path, opts, { ...state, attempt: state.attempt + 1 });
      }
      throw new MfpApiError(`Network error calling ${url.pathname}: ${err instanceof Error ? err.message : String(err)}`, undefined, url.pathname);
    }

    if (res.status === 401 && !state.retriedAuth) {
      await this.getAccessToken(true);
      return this.request(path, opts, { ...state, retriedAuth: true });
    }
    if (RETRYABLE_HTTP.has(res.status) && state.attempt < MAX_HTTP_RETRIES) {
      await sleep(backoffMs(state.attempt, res.headers.get("Retry-After")));
      return this.request(path, opts, { ...state, attempt: state.attempt + 1 });
    }

    const text = await res.text();
    let json: unknown = null;
    if (text) {
      try {
        json = JSON.parse(text);
      } catch {
        json = text;
      }
    }
    if (!res.ok) {
      throw new MfpApiError(`MyFitnessPal ${url.pathname} returned HTTP ${res.status}: ${text.slice(0, 300)}`, res.status, url.pathname, text.slice(0, 600));
    }
    return { status: res.status, json, headers: res.headers };
  }

  /** GET a collection, following `Link: rel=next` (or `page_token`) until exhausted. */
  private async collect(path: string, query: Record<string, string | string[] | undefined>): Promise<{ items: Record<string, unknown>[]; pages: number }> {
    const items: Record<string, unknown>[] = [];
    let next: string | undefined = path;
    let nextQuery: Record<string, string | string[] | undefined> | undefined = { max_items: "100", ...query };
    let pages = 0;
    while (next && pages < MAX_PAGES) {
      const res: { status: number; json: unknown; headers: Headers } = await this.request(next, { query: nextQuery });
      pages++;
      const body = res.json as { items?: unknown; item?: unknown } | null;
      if (Array.isArray(body?.items)) items.push(...(body!.items as Record<string, unknown>[]));
      else if (body?.item && typeof body.item === "object") items.push(body.item as Record<string, unknown>);
      else if (Array.isArray(body)) items.push(...(body as Record<string, unknown>[]));
      const link = res.headers.get("link") ?? res.headers.get("Link");
      const m = link ? /<([^>]+)>\s*;\s*rel="?next"?/i.exec(link) : null;
      next = m?.[1];
      nextQuery = undefined;
    }
    return { items, pages };
  }

  // -------------------------------------------------------------------------
  // Data
  // -------------------------------------------------------------------------

  /** Identity profile (name, birthdate, gender, height, weight, locale). Memoised. */
  async getIdentityUser(): Promise<IdentityUser> {
    if (this.identityUser) return this.identityUser;
    const res = await this.request(`users/${encodeURIComponent(this.userId)}`, {
      base: "identity",
      query: { fetch_profile: "true", fetch_emails: "true" },
    });
    this.identityUser = res.json as IdentityUser;
    return this.identityUser;
  }

  private async loadDiaryConfig(): Promise<DiaryConfig | undefined> {
    if (this.diaryConfig) return this.diaryConfig;
    const stored = await this.cacheGet<DiaryConfig>(this.key("diary-config"));
    if (stored) this.diaryConfig = stored;
    return stored;
  }

  private async saveDiaryConfig(config: DiaryConfig): Promise<void> {
    this.diaryConfig = config;
    await this.cachePut(this.key("diary-config"), config, CONFIG_TTL_SECONDS);
  }

  /**
   * One diary day. The mobile token's accepted `types` / `fields[]` are not
   * documented, so on first use this tries the richest request and steps
   * down (fewer fields → no fields → one type at a time) until something
   * works, then remembers the winning combination. Completed days are cached.
   */
  async getDiary(date: string, opts: { types?: readonly string[]; fields?: readonly string[]; noCache?: boolean } = {}): Promise<DiaryFetch> {
    const wantTypes = [...(opts.types ?? DIARY_TYPES)];
    const cacheable = !opts.noCache && date < todayIn(this.timeZone, this.now());
    const cacheKey = this.key("diary", date, wantTypes.join(","), opts.fields ? opts.fields.join(",") : "auto");
    if (cacheable) {
      const hit = await this.cacheGet<DiaryFetch>(cacheKey);
      if (hit) return { ...hit, cached: true };
    }

    const attempt = async (types: string[], fields: readonly string[]) => {
      const { items, pages } = await this.collect("v2/diary", {
        entry_date: date,
        types: types.join(","),
        fields: fields.length ? [...fields] : undefined,
      });
      return { items, pages };
    };
    const isClientError = (err: unknown) => err instanceof MfpApiError && err.status !== undefined && err.status >= 400 && err.status < 500 && err.status !== 401 && err.status !== 429;

    let result: DiaryFetch | undefined;

    // Fast path: a combination that worked before.
    const known = opts.fields ? { types: wantTypes, fields: [...opts.fields] } : await this.loadDiaryConfig();
    if (known) {
      const types = wantTypes.filter((t) => known.types.includes(t));
      if (types.length) {
        try {
          const r = await attempt(types, known.fields);
          result = { date, items: r.items, types, fields: known.fields, pages: r.pages, cached: false };
          const rejected = wantTypes.filter((t) => !types.includes(t));
          if (rejected.length) result.rejected_types = rejected;
        } catch (err) {
          if (!isClientError(err) || opts.fields) throw err;
        }
      }
    }

    // Discovery. MFP's 400 for an unsupported type names it
    // ("Unrecognized diary entry type(s): water"), so first drop exactly the
    // named types and keep the fields; only step down the field set when the
    // error doesn't name a type.
    if (!result) {
      let types = [...wantTypes];
      const rejected: string[] = [];
      let lastErr: unknown;
      outer: for (const fields of DIARY_FIELD_SETS) {
        for (let guard = 0; guard < 8; guard++) {
          try {
            const r = await attempt(types, fields);
            result = { date, items: r.items, types, fields: [...fields], pages: r.pages, cached: false };
            break outer;
          } catch (err) {
            if (!isClientError(err)) throw err;
            lastErr = err;
            const named = namedRejectedTypes(err, types);
            if (!named.length) break; // not a type problem: try a smaller field set
            rejected.push(...named);
            types = types.filter((t) => !named.includes(t));
            if (!types.length) throw err;
          }
        }
      }

      // Still failing and the errors never named a type: probe one type at a
      // time with no fields, then re-try the field sets with the survivors.
      if (!result) {
        const items: Record<string, unknown>[] = [];
        const ok: string[] = [];
        let pages = 0;
        for (const type of types) {
          try {
            const r = await attempt([type], []);
            items.push(...r.items);
            pages += r.pages;
            ok.push(type);
          } catch (err) {
            if (!isClientError(err)) throw err;
            rejected.push(type);
          }
        }
        if (!ok.length) throw lastErr instanceof Error ? lastErr : new MfpApiError("MyFitnessPal rejected every diary request");
        result = { date, items, types: ok, fields: [], pages, cached: false };
        for (const fields of DIARY_FIELD_SETS) {
          if (!fields.length) break;
          try {
            const r = await attempt(ok, fields);
            result = { date, items: r.items, types: ok, fields: [...fields], pages: r.pages, cached: false };
            break;
          } catch (err) {
            if (!isClientError(err)) throw err;
          }
        }
      }

      if (rejected.length) result.rejected_types = Array.from(new Set(rejected));
      if (!opts.fields) await this.saveDiaryConfig({ types: result.types, fields: result.fields });
    }

    if (cacheable) await this.cachePut(cacheKey, result, DAY_CACHE_TTL_SECONDS);
    return result;
  }

  /** Measurements (weight is the only documented type) for one day. */
  async getMeasurements(date: string, types: string[] = ["weight"]): Promise<Record<string, unknown>[]> {
    const cacheable = date < todayIn(this.timeZone, this.now());
    const cacheKey = this.key("measurements", date, types.join(","));
    if (cacheable) {
      const hit = await this.cacheGet<Record<string, unknown>[]>(cacheKey);
      if (hit) return hit;
    }
    const { items } = await this.collect("v2/measurements", { entry_date: date, types: types.join(",") });
    if (cacheable) await this.cachePut(cacheKey, items, DAY_CACHE_TTL_SECONDS);
    return items;
  }

  /** Try a request and report the outcome instead of throwing (diagnostics). */
  async probe(path: string, query?: Record<string, string | string[] | undefined>, base: "api" | "identity" = "api"): Promise<ProbeResult> {
    try {
      const res = await this.request(path, { query, base });
      return { path, status: res.status, ok: true, sample: JSON.stringify(res.json).slice(0, 400) };
    } catch (err) {
      if (err instanceof MfpApiError) return { path, status: err.status ?? null, ok: false, error: err.message.slice(0, 300) };
      return { path, status: null, ok: false, error: err instanceof Error ? err.message : String(err) };
    }
  }
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/**
 * Diary types named in an MFP 4xx body, e.g.
 * `Unrecognized diary entry type(s): water, steps` → ["water", "steps"].
 * Only types we actually asked for are returned.
 */
export function namedRejectedTypes(err: unknown, requested: readonly string[]): string[] {
  if (!(err instanceof MfpApiError)) return [];
  const text = `${err.body ?? ""} ${err.message}`;
  const m = /unrecogni[sz]ed diary entry type\(?s?\)?\s*:\s*([a-z0-9_,\s"']+)/i.exec(text);
  if (!m) return [];
  const named = m[1]
    .split(/[,\s"']+/)
    .map((t) => t.trim().toLowerCase())
    .filter(Boolean);
  return requested.filter((t) => named.includes(t.toLowerCase()));
}

function todayIn(timeZone: string, nowMs: number): string {
  return new Intl.DateTimeFormat("en-CA", { timeZone, year: "numeric", month: "2-digit", day: "2-digit" }).format(new Date(nowMs));
}

function backoffMs(attempt: number, retryAfter?: string | null): number {
  if (retryAfter) {
    const secs = parseInt(retryAfter, 10);
    if (!Number.isNaN(secs)) return Math.min(secs * 1000, 10_000);
  }
  return Math.min(2 ** attempt * 400 + Math.random() * 200, 5_000);
}

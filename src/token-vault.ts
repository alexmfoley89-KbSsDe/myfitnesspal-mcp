/**
 * TokenVault — custodian of one user's MyFitnessPal token chain.
 *
 * MFP rotates the refresh token on every refresh: the old token dies the
 * moment a new one is issued, so a raced refresh or a lost write breaks the
 * chain for good and the user has to sign in again. The vault fixes the class
 * of failure by being the *only* writer: it lives inside a per-user Durable
 * Object (token-custody.ts), serialises refreshes, and durably records the
 * rotated token — loudly failing rather than silently dropping it — before
 * anyone gets the new access token.
 *
 * The grant's refresh token is only a *seed*: it starts a chain, and a
 * different seed (the user reconnected in Claude) can replace a dead one.
 * Everything is AES-GCM sealed before it touches storage.
 */
import { MfpApiError, MfpAuthError, deviceIdFor, refreshTokenSet, type OAuthClientCredentials, type TokenSet } from "./mfp-api";
import { deriveSealKey, open, seal, sha256Hex } from "./crypto";

/** The slice of DurableObjectStorage the vault needs (tests use a Map). */
export interface VaultStorage {
  get(key: string): Promise<unknown>;
  put(key: string, value: unknown): Promise<void>;
  delete(key: string): Promise<unknown>;
}

export interface VaultRequest {
  /** Namespaces the device id; the DO instance is addressed by this too. */
  userHash: string;
  /** Refresh token from the connector grant — seeds or replaces the chain. */
  seedRefreshToken: string;
  /**
   * Migration glue: the rotated refresh token from the legacy sealed-KV path,
   * tried when the chain (or, on first contact, the grant seed) is dead — an
   * existing deployment's grant seed was usually rotated away long ago.
   */
  legacyRefreshToken?: string;
  /** Refresh even if the stored access token still looks fresh. */
  force?: boolean;
}

/**
 * Result union instead of thrown errors: typed errors don't survive the DO
 * RPC boundary, so the caller rebuilds MfpAuthError/MfpApiError from this.
 */
export type VaultTokenResult =
  | { ok: true; accessToken: string; expiresAt: number }
  | { ok: false; auth: boolean; status?: number; message: string };

interface Chain {
  tokens: TokenSet;
  /** SHA-256 of the seed that started this chain, to recognise a reconnect. */
  seedHash: string;
}

const CHAIN_KEY = "chain";
/** Refresh this long before the access token expires. */
const TOKEN_SAFETY_MS = 60 * 1000;

export class TokenVault {
  private readonly storage: VaultStorage;
  private readonly creds: OAuthClientCredentials;
  private readonly sealSecret: string;
  private readonly fetchImpl?: typeof fetch;
  private readonly now: () => number;
  private sealKeyPromise?: Promise<CryptoKey>;
  private inFlight?: Promise<TokenSet>;

  constructor(opts: { storage: VaultStorage; creds: OAuthClientCredentials; sealSecret: string; fetchImpl?: typeof fetch; now?: () => number }) {
    this.storage = opts.storage;
    this.creds = opts.creds;
    this.sealSecret = opts.sealSecret;
    this.fetchImpl = opts.fetchImpl;
    this.now = opts.now ?? (() => Date.now());
  }

  async getToken(req: VaultRequest): Promise<VaultTokenResult> {
    try {
      const chain = await this.load();
      if (!req.force && chain && this.usable(chain.tokens)) {
        return { ok: true, accessToken: chain.tokens.accessToken, expiresAt: chain.tokens.expiresAt };
      }
      // The DO is single-threaded but awaits interleave; one rotation at a time.
      if (!this.inFlight) {
        this.inFlight = this.rotate(req, chain).finally(() => (this.inFlight = undefined));
      }
      const tokens = await this.inFlight;
      return { ok: true, accessToken: tokens.accessToken, expiresAt: tokens.expiresAt };
    } catch (err) {
      return {
        ok: false,
        auth: err instanceof MfpAuthError,
        status: err instanceof MfpApiError ? err.status : undefined,
        message: err instanceof Error ? err.message : String(err),
      };
    }
  }

  async peek(): Promise<{ expiresAt?: number }> {
    const chain = await this.load();
    return { expiresAt: chain?.tokens.expiresAt };
  }

  async purge(): Promise<void> {
    this.inFlight = undefined;
    await this.storage.delete(CHAIN_KEY);
  }

  private usable(t: TokenSet): boolean {
    return Boolean(t.accessToken && t.expiresAt - TOKEN_SAFETY_MS > this.now());
  }

  private async rotate(req: VaultRequest, chain: Chain | undefined): Promise<TokenSet> {
    const refreshOpts = { deviceId: deviceIdFor(req.userHash), fetchImpl: this.fetchImpl, now: this.now };

    // Candidates in order of freshness. `origin` identifies the token that
    // would start the resulting chain, recorded so a later dead chain can tell
    // a genuinely new seed (user reconnected — worth trying) from the token
    // that started it (consumed at the first rotation — certainly dead).
    const candidates: Array<{ token: string; origin: string }> = [];
    if (chain) candidates.push({ token: chain.tokens.refreshToken, origin: chain.seedHash });
    if (req.legacyRefreshToken) candidates.push({ token: req.legacyRefreshToken, origin: await sha256Hex(req.legacyRefreshToken) });
    candidates.push({ token: req.seedRefreshToken, origin: await sha256Hex(req.seedRefreshToken) });

    const tried = new Set<string>();
    let lastErr: unknown;
    for (const [i, c] of candidates.entries()) {
      if (!c.token || tried.has(c.token)) continue;
      // Anything descending from the failing chain's own origin is dead too.
      if (chain && i > 0 && c.origin === chain.seedHash) continue;
      tried.add(c.token);
      try {
        const tokens = await refreshTokenSet(this.creds, c.token, refreshOpts);
        await this.save({ tokens, seedHash: c.origin });
        return tokens;
      } catch (err) {
        // Only a rejected token justifies falling through to an older seed;
        // network/5xx errors must not burn candidates.
        if (!(err instanceof MfpAuthError)) throw err;
        lastErr = err;
      }
    }
    throw lastErr instanceof Error ? lastErr : new MfpAuthError("No refresh token available — reconnect the connector");
  }

  private sealKey(): Promise<CryptoKey> {
    if (!this.sealKeyPromise) this.sealKeyPromise = deriveSealKey(this.sealSecret);
    return this.sealKeyPromise;
  }

  private async load(): Promise<Chain | undefined> {
    try {
      const sealed = await this.storage.get(CHAIN_KEY);
      if (typeof sealed !== "string" || !sealed) return undefined;
      return JSON.parse(await open(await this.sealKey(), sealed)) as Chain;
    } catch {
      // Undecryptable (rotated SESSION_ENCRYPTION_KEY) or corrupt: treat as
      // absent — the next rotation reseeds from the grant.
      return undefined;
    }
  }

  /** Persisting a rotation must never fail silently: the old token is already dead. */
  private async save(chain: Chain): Promise<void> {
    const sealed = await seal(await this.sealKey(), JSON.stringify(chain));
    await this.storage.put(CHAIN_KEY, sealed);
  }
}

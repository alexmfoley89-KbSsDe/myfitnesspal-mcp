import type { OAuthHelpers } from "@cloudflare/workers-oauth-provider";

/**
 * Props are produced when the user signs in with their MyFitnessPal account
 * on the /authorize page, encrypted into the issued token by
 * workers-oauth-provider, and handed back to the MCP agent on every
 * authenticated request via `this.props`.
 *
 * Unlike Renpho, MFP's identity service issues a real OAuth refresh token, so
 * the password is used exactly once (at sign-in) and never stored.
 */
export type Props = {
  /** What the user typed at sign-in (email or username), lower-cased. */
  email: string;
  /** Identity-service user id (the `sub` of the id_token). */
  userId: string;
  /** MFP domain user id — the `mfp-user-id` header value for api.myfitnesspal.com. */
  domainUserId: string;
  /** Refresh token issued at sign-in (the latest rotated one lives in sealed KV). */
  refreshToken: string;
  /** Access token issued at sign-in, to save one refresh on first use. */
  accessToken: string;
  /** Unix ms expiry of `accessToken`. */
  accessTokenExpiresAt: number;
  /** SHA-256 of the login; namespaces every cache key so users never collide. */
  userHash: string;
};

/** Worker bindings. Mirrors wrangler.jsonc; `wrangler types` regenerates this. */
export interface Env {
  OAUTH_KV: KVNamespace;
  /** Sealed MFP tokens + cached diary days. */
  MFP_CACHE: KVNamespace;
  OAUTH_PROVIDER: OAuthHelpers;
  MCP_OBJECT: DurableObjectNamespace;
  /** Secret used to AES-GCM seal everything written to MFP_CACHE. */
  SESSION_ENCRYPTION_KEY: string;
  /** OAuth client credentials of the MyFitnessPal mobile app. */
  MFP_CLIENT_ID: string;
  MFP_CLIENT_SECRET: string;
  /** Public origin of this Worker (for serverInfo icons/websiteUrl). */
  PUBLIC_URL: string;
  /** IANA tz used to resolve "today" for date defaults. */
  TIME_ZONE: string;
  /** Optional comma-separated allow-list of MFP emails/usernames permitted to connect. */
  ALLOWED_EMAILS: string;
}

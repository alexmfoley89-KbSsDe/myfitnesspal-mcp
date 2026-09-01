/**
 * Entry point. Wires three things together:
 *   1. workers-oauth-provider  — makes this Worker an OAuth server to Claude.
 *   2. AuthHandler             — the MyFitnessPal sign-in page (one-time credential exchange).
 *   3. MyFitnessPalMCP (McpAgent / Durable Object) — serves the MCP tools.
 *
 * Add the deployed URL (".../mcp") to Claude as a custom connector; clicking
 * "Connect" shows the sign-in and the tools light up on web/desktop/mobile.
 */
import OAuthProvider from "@cloudflare/workers-oauth-provider";
import { McpAgent } from "agents/mcp";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { AuthHandler } from "./auth-handler";
import { deriveSealKey, open } from "./crypto";
import { MfpApiError, MfpAuthError, MfpClient, type TokenProvider } from "./mfp-api";
import { registerTools } from "./tools";
import type { Env, Props } from "./types";

export { MfpTokenCustody } from "./token-custody";

export class MyFitnessPalMCP extends McpAgent<Env, Record<string, never>, Props> {
  // `this.env` is set by the Durable Object base constructor, so it is
  // available to field initialisers. PUBLIC_URL lets clients that render
  // server branding (Claude's connector list) show the icon served at /icon.png.
  server = new McpServer({
    name: "MyFitnessPal",
    title: "MyFitnessPal",
    version: "0.1.0",
    ...(this.env?.PUBLIC_URL
      ? {
          websiteUrl: this.env.PUBLIC_URL,
          icons: [{ src: `${this.env.PUBLIC_URL.replace(/\/$/, "")}/icon.png`, mimeType: "image/png", sizes: ["512x512"] }],
        }
      : {}),
  });

  private client?: MfpClient;

  async init() {
    registerTools(this.server, () => this.getClient(), this.env.TIME_ZONE || "Europe/London");
  }

  /** One client per Durable Object instance so the access token stays warm in memory. */
  private getClient(): MfpClient {
    if (!this.client) {
      this.client = new MfpClient({
        creds: { clientId: this.env.MFP_CLIENT_ID, clientSecret: this.env.MFP_CLIENT_SECRET },
        userId: this.props.userId,
        domainUserId: this.props.domainUserId,
        refreshToken: this.props.refreshToken,
        accessToken: this.props.accessToken,
        accessTokenExpiresAt: this.props.accessTokenExpiresAt,
        userHash: this.props.userHash,
        timeZone: this.env.TIME_ZONE || "Europe/London",
        cache: this.env.MFP_CACHE,
        sealSecret: this.env.SESSION_ENCRYPTION_KEY,
        tokenProvider: this.tokenProvider(),
      });
    }
    return this.client;
  }

  /**
   * All refreshes go through the per-user custody DO — one writer, so the
   * rotating MFP refresh token is never raced between sessions or lost.
   */
  private tokenProvider(): TokenProvider {
    const ns = this.env.MFP_TOKEN_CUSTODY;
    const stub = ns.get(ns.idFromName(this.props.userHash));
    const seed = { userHash: this.props.userHash, seedRefreshToken: this.props.refreshToken };
    let legacy: Promise<string | undefined> | undefined;
    return {
      getToken: async ({ force }) => {
        legacy ??= this.legacyRefreshToken();
        const r = await stub.getToken({ ...seed, legacyRefreshToken: await legacy, force });
        // Typed errors don't survive the RPC boundary; rebuild them so
        // tools.ts keeps matching on MfpAuthError for its hints.
        if (!r.ok) throw r.auth ? new MfpAuthError(r.message, r.status) : new MfpApiError(r.message, r.status);
        return { accessToken: r.accessToken, expiresAt: r.expiresAt };
      },
      peek: () => stub.peek(),
      purge: async () => {
        await stub.purge();
      },
    };
  }

  /**
   * Migration glue for deployments that predate the custody DO: the rotated
   * refresh token lived sealed in KV, and the grant's seed is long dead. Hand
   * the KV token to the vault as a fallback seed so existing connections
   * survive the upgrade without a re-sign-in. Deletable once the KV entries
   * age out (30-day TTL).
   */
  private async legacyRefreshToken(): Promise<string | undefined> {
    try {
      const sealed = await this.env.MFP_CACHE.get(`v1:${this.props.userHash}:token`, "text");
      if (!sealed) return undefined;
      const key = await deriveSealKey(this.env.SESSION_ENCRYPTION_KEY);
      const stored = JSON.parse(await open(key, sealed)) as { refreshToken?: string };
      return stored.refreshToken || undefined;
    } catch {
      return undefined;
    }
  }
}

export default new OAuthProvider({
  apiRoute: "/mcp",
  apiHandler: MyFitnessPalMCP.serve("/mcp") as any,
  defaultHandler: AuthHandler as any,
  authorizeEndpoint: "/authorize",
  tokenEndpoint: "/token",
  clientRegistrationEndpoint: "/register",
});

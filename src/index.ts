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
import { MfpClient } from "./mfp-api";
import { registerTools } from "./tools";
import type { Env, Props } from "./types";

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
      });
    }
    return this.client;
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

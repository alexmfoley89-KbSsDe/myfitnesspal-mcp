/**
 * Default handler for the OAuth provider. workers-oauth-provider owns the
 * Claude <-> Worker side (client registration, tokens); this handler owns the
 * human side: a sign-in page where the user enters their MyFitnessPal
 * credentials, which we exchange — once — for MFP OAuth tokens via the mobile
 * app's identity flow. Only the resulting refresh token is kept (in the
 * grant's encrypted props); the password never leaves this request.
 *
 * Flow:
 *   GET  /authorize  -> render the sign-in form with Claude's AuthRequest encoded in a hidden field
 *   POST /authorize  -> MFP sign-in, completeAuthorization, redirect back to Claude
 */
import { Hono } from "hono";
import type { AuthRequest, OAuthHelpers } from "@cloudflare/workers-oauth-provider";
import type { Env, Props } from "./types";
import { ICON_PNG_BASE64 } from "./icon";
import { MfpAuthError, deviceIdFor, loginWithPassword } from "./mfp-api";
import { sha256Hex } from "./crypto";

type Bindings = Env & { OAUTH_PROVIDER: OAuthHelpers };

const app = new Hono<{ Bindings: Bindings }>();

// Baseline security headers on every response from this handler.
app.use("*", async (c, next) => {
  await next();
  c.header("X-Content-Type-Options", "nosniff");
  c.header("X-Frame-Options", "DENY");
  c.header("Referrer-Policy", "no-referrer");
  c.header("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  c.header("Cross-Origin-Opener-Policy", "same-origin");
  c.header("Cache-Control", c.req.path === "/icon.png" ? "public, max-age=86400" : "no-store");
});

function encodeState(req: AuthRequest): string {
  return btoa(JSON.stringify(req)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function decodeState(state: string): AuthRequest {
  const b64 = state.replace(/-/g, "+").replace(/_/g, "/");
  return JSON.parse(atob(b64)) as AuthRequest;
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[ch]!);
}

function allowedEmails(env: Env): Set<string> {
  return new Set(
    (env.ALLOWED_EMAILS ?? "")
      .split(",")
      .map((e) => e.trim().toLowerCase())
      .filter(Boolean),
  );
}

const ICON_PNG_BYTES = Uint8Array.from(atob(ICON_PNG_BASE64), (c) => c.charCodeAt(0));

app.get("/icon.png", (c) => c.body(ICON_PNG_BYTES, 200, { "Content-Type": "image/png" }));

const PAGE_CSS = `
  :root { color-scheme: light dark; --bg:#f6f7fb; --card:#fff; --fg:#111827; --muted:#6b7280; --accent:#0e7490; --border:#e5e7eb; --err-bg:#fef2f2; --err-fg:#991b1b; }
  @media (prefers-color-scheme: dark) { :root { --bg:#0b1220; --card:#111a2e; --fg:#e5e7eb; --muted:#9ca3af; --accent:#22d3ee; --border:#1f2a44; --err-bg:#3b1111; --err-fg:#fecaca; } }
  * { box-sizing: border-box; }
  body { margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center; background:var(--bg); color:var(--fg); font:16px/1.5 -apple-system, "Segoe UI", Roboto, sans-serif; padding:24px; }
  .card { width:100%; max-width:420px; background:var(--card); border:1px solid var(--border); border-radius:16px; padding:28px; box-shadow:0 10px 30px rgba(0,0,0,.08); }
  .brand { display:flex; align-items:center; gap:12px; margin-bottom:6px; }
  .brand img { width:44px; height:44px; border-radius:10px; }
  h1 { font-size:20px; margin:0; }
  p { margin:8px 0 0; color:var(--muted); font-size:14px; }
  label { display:block; margin-top:16px; font-size:14px; font-weight:600; }
  input[type=text], input[type=password] { width:100%; margin-top:6px; padding:10px 12px; border:1px solid var(--border); border-radius:10px; background:transparent; color:inherit; font-size:16px; }
  button { width:100%; margin-top:20px; padding:12px; border:0; border-radius:10px; background:var(--accent); color:#fff; font-size:16px; font-weight:600; cursor:pointer; }
  .err { margin-top:16px; padding:10px 12px; border-radius:10px; background:var(--err-bg); color:var(--err-fg); font-size:14px; }
  .fine { margin-top:18px; font-size:12px; color:var(--muted); }
  code { font-size:13px; }
`;

function loginPage(opts: { state: string; clientName: string; error?: string; email?: string }): string {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Connect MyFitnessPal</title><link rel="icon" href="/icon.png"><style>${PAGE_CSS}</style></head>
<body><main class="card">
  <div class="brand"><img src="/icon.png" alt=""><h1>Connect MyFitnessPal</h1></div>
  <p><strong>${escapeHtml(opts.clientName)}</strong> is asking for read access to your MyFitnessPal diary (foods, nutrition, water, exercise, weight).</p>
  <p>Sign in with your MyFitnessPal email (or username) and password.</p>
  ${opts.error ? `<div class="err" role="alert">${escapeHtml(opts.error)}</div>` : ""}
  <form method="post" action="/authorize" autocomplete="on">
    <input type="hidden" name="oauth" value="${escapeHtml(opts.state)}">
    <label for="email">MyFitnessPal email or username</label>
    <input id="email" name="email" type="text" required autocomplete="username" value="${escapeHtml(opts.email ?? "")}">
    <label for="password">Password</label>
    <input id="password" name="password" type="password" required autocomplete="current-password">
    <button type="submit">Sign in &amp; connect</button>
  </form>
  <p class="fine">Your password is exchanged once, right now, for a MyFitnessPal access token; it is not stored. Only refresh tokens are kept — encrypted in the connector grant and in the connector's per-user token store, which self-deletes after 30 days without use. Disconnect the connector in Claude to revoke.</p>
</main></body></html>`;
}

app.get("/", (c) => {
  const mcpUrl = new URL("/mcp", c.req.url).toString();
  return c.html(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>MyFitnessPal MCP</title><link rel="icon" href="/icon.png"><style>${PAGE_CSS}</style></head>
<body><main class="card">
  <div class="brand"><img src="/icon.png" alt=""><h1>MyFitnessPal MCP</h1></div>
  <p>A remote MCP server that gives Claude read access to your MyFitnessPal nutrition diary.</p>
  <p>Add this URL as a custom connector in Claude (Settings → Connectors):</p>
  <p><code>${escapeHtml(mcpUrl)}</code></p>
</main></body></html>`);
});

// Step 1: Claude hits /authorize. Parse its request, show the sign-in form.
app.get("/authorize", async (c) => {
  const oauthReq = await c.env.OAUTH_PROVIDER.parseAuthRequest(c.req.raw);
  if (!oauthReq.clientId || !oauthReq.redirectUri) {
    return c.text("Missing OAuth parameters — start the connection from Claude (Settings → Connectors).", 400);
  }
  const client = await c.env.OAUTH_PROVIDER.lookupClient(oauthReq.clientId).catch(() => null);
  if (!client) return c.text("Unknown OAuth client — reconnect the connector from Claude.", 400);
  return c.html(loginPage({ state: encodeState(oauthReq), clientName: client.clientName ?? "An MCP client" }));
});

// Step 2: the user submits MFP credentials.
app.post("/authorize", async (c) => {
  const form = await c.req.parseBody();
  const state = typeof form.oauth === "string" ? form.oauth : "";
  const email = typeof form.email === "string" ? form.email.trim() : "";
  const password = typeof form.password === "string" ? form.password : "";

  let oauthReq: AuthRequest;
  try {
    oauthReq = decodeState(state);
  } catch {
    return c.text("Invalid or missing authorization state — restart the connection from Claude.", 400);
  }
  const client = await c.env.OAUTH_PROVIDER.lookupClient(oauthReq.clientId).catch(() => null);
  const clientName = client?.clientName ?? "An MCP client";
  const render = (error: string, status: 400 | 401 | 403 | 500 | 502) =>
    c.html(loginPage({ state, clientName, error, email }), status);

  if (!email || !password) return render("Email/username and password are required.", 400);
  if (!c.env.MFP_CLIENT_ID || !c.env.MFP_CLIENT_SECRET) {
    return render("This deployment is missing the MFP_CLIENT_ID / MFP_CLIENT_SECRET secrets.", 500);
  }

  const allowed = allowedEmails(c.env);
  if (allowed.size && !allowed.has(email.toLowerCase())) {
    return render("This deployment only accepts the account(s) its owner listed in ALLOWED_EMAILS.", 403);
  }

  const userHash = await sha256Hex(email.toLowerCase());
  let login;
  try {
    login = await loginWithPassword(
      { clientId: c.env.MFP_CLIENT_ID, clientSecret: c.env.MFP_CLIENT_SECRET },
      email,
      password,
      { deviceId: deviceIdFor(userHash) },
    );
  } catch (err) {
    if (err instanceof MfpAuthError) return render(err.message, 401);
    return render(`Could not reach MyFitnessPal: ${err instanceof Error ? err.message : String(err)}`, 502);
  }

  const props: Props = {
    email: email.toLowerCase(),
    userId: login.userId,
    domainUserId: login.domainUserId,
    refreshToken: login.refreshToken,
    accessToken: login.accessToken,
    accessTokenExpiresAt: login.expiresAt,
    userHash,
  };
  const { redirectTo } = await c.env.OAUTH_PROVIDER.completeAuthorization({
    request: oauthReq,
    userId: email.toLowerCase(),
    scope: oauthReq.scope,
    metadata: { label: login.email ?? email },
    props,
  });
  return c.redirect(redirectTo);
});

export { app as AuthHandler };

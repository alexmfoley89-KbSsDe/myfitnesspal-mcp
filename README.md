# MyFitnessPal MCP — nutrition data for your Claude training coach

A remote [MCP](https://modelcontextprotocol.io) server, deployed on Cloudflare
Workers, that exposes your **MyFitnessPal** diary — every food with portion and
time, per-meal and daily totals for energy, macros and micros, water, logged
exercise, steps and weight — to Claude. Add it once as a custom connector and
it works on Claude **web, desktop, and mobile**. Pairs with the Strava,
Google Health and Renpho connectors so your coach sees training load, recovery,
body composition *and* fuelling.

> **How it talks to MFP:** MyFitnessPal has no public API (the partner
> programme is closed). This server uses the mobile app's own OAuth identity
> flow and the same `api.myfitnesspal.com/v2` API the app uses — the one the
> archived partner docs at myfitnesspalapi.com describe. No browser, no cookies,
> no scraping, no captcha. Credit for the identity flow:
> [seonixx/myfitnesspal](https://github.com/seonixx/myfitnesspal) and
> [jnelle/MyFitnesspal-API-Golang](https://github.com/jnelle/MyFitnesspal-API-Golang).
> Unofficial; MFP can change it at any time.

## Tools

| Tool | What it answers |
|------|-----------------|
| `get_daily_nutrition` | "What did I eat today?" — per-meal and day totals (energy, protein, carbs, net carbs, fibre, sugar, fat subtypes, cholesterol, sodium, potassium, %DV micros), every food with portion and timestamp, water, exercise, steps, weight entries |
| `get_food_log` | Individual food entries over a range, filterable by meal or a text search — what was eaten around sessions, recurring foods |
| `get_nutrition_trend` | Daily totals over a window with means over logged days, min/max energy, protein/carb/fat energy split, weekly averages, water/exercise/steps |
| `get_exercise_log` | MFP-logged exercise (duration, calories, distance, HR) and daily steps |
| `get_weight_log` | Weight entries recorded in MFP |
| `get_profile` | Name, sex, birthdate/age, height, locale + token status |
| `run_diagnostics` | End-to-end probe: token refresh, profile, which diary types/fields the account accepts (with raw samples), measurements, candidate goal endpoints |
| `query_endpoint` | Escape hatch: call **any** `api.myfitnesspal.com` / identity endpoint with the connector's auth applied |
| `refresh_data` | Drop cached days + remembered request shape, refresh the token |
| `delete_my_data` | Delete everything cached for your account |

> **Troubleshooting:** if a tool errors or data looks missing, run
> `run_diagnostics` first. It reports the exact `types`/`fields[]`
> combination MFP accepts for your account and a raw sample per item type.

---

## How it works

```
Claude (web/desktop/mobile)
  └─ custom connector → /mcp
       └─ workers-oauth-provider  (this Worker IS Claude's OAuth server)
            └─ AuthHandler        (MFP sign-in page: one-time credential → token exchange)
                 └─ MyFitnessPalMCP (Durable Object) → MfpClient → api.myfitnesspal.com/v2
```

### Sign-in (once, on the connector's /authorize page)

1. `POST identity-api.myfitnesspal.com/oauth/token` — client-credentials
   token for the mobile app's OAuth client.
2. `GET identity-api…/clientKeys` — the HS512 signing key MFP uses for
   password sign-ins.
3. `POST identity-api…/oauth/authorize` with `credentials=<JWT{username,
   password}>` — returns a redirect to `mfp://identity/callback?code=…`.
4. `POST …/oauth/token` (authorization_code) — **access + refresh + id
   tokens**.
5. `GET identity-api…/users/{sub}` — the MFP domain user id (`mfp-user-id`
   header) and profile.

Only the **refresh token** (and the first access token) is kept, encrypted
inside the OAuth grant's props; the password is never stored. Thereafter the
Worker refreshes silently; the newest rotated refresh token lives sealed in
KV.

### Reading the diary

`GET api.myfitnesspal.com/v2/diary?entry_date=YYYY-MM-DD&types=…&fields[]=…`
with `Authorization: Bearer`, `mfp-user-id`, `mfp-client-id` and the app's
`api-version`/`user-agent` headers. Item types: `food_entry`, `diary_meal`,
`exercise_entry`, `water`, `steps_aggregate`. Pagination follows the
`Link: rel=next` header.

The exact `types`/`fields[]` the mobile token accepts aren't documented, so
the client **discovers** them: it tries the richest request, then a smaller
field set, then no fields, then one type at a time — and remembers the winning
combination for a day. Anything rejected is reported on the tool result.
Completed days are immutable and cached (sealed) for 30 days; today is always
live. Each day is one upstream call, so windows are capped at 92 days.

### Field mapping

`nutritional_contents` → unit-suffixed keys: `energy_kcal` (kJ converted),
`protein_g`, `carbohydrates_g`, `net_carbs_g`, `fiber_g`, `sugar_g`, `fat_g`,
`saturated_fat_g`, `monounsaturated_fat_g`, `polyunsaturated_fat_g`,
`trans_fat_g`, `cholesterol_mg`, `sodium_mg`, `potassium_mg`, and
`calcium/iron/vitamin_a/vitamin_c/vitamin_d_pct_dv` (MFP stores those as
percent of daily value). Unknown nutrients are kept under `extra`.

Day totals come from MFP's own `diary_meal` summaries when present
(`totals_source: "diary_meal"`), otherwise from summing `food_entry` rows.

### Caching & encryption

Everything written to the `MFP_CACHE` KV namespace — tokens, the discovered
request shape, diary days — is **AES-256-GCM sealed** with a key derived from
`SESSION_ENCRYPTION_KEY`, keyed per user. Without the secret, caching is
disabled. Cache failures never break a request.

---

## Where the client credentials come from

The identity flow needs the OAuth client id/secret embedded in the MyFitnessPal
Android app. They are not reproduced here; the Go client linked above ships
them in its `.env.sample`. Set them as Worker secrets `MFP_CLIENT_ID` and
`MFP_CLIENT_SECRET`. If MFP rotates them, sign-in stops working until they
are updated.

## Deploy

### Option A — GitHub Actions

[`.github/workflows/deploy.yml`](.github/workflows/deploy.yml) deploys on every
push to `master`. Secrets live in Cloudflare; GitHub only holds
`CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID`.

1. Create two KV namespaces (`MFP_OAUTH_KV`, `MFP_CACHE`) and put their ids in
   [`wrangler.jsonc`](wrangler.jsonc).
2. Add the two GitHub secrets and push.
3. In Cloudflare (*Workers & Pages → myfitnesspal-mcp → Settings → Variables
   and Secrets*) add secrets `SESSION_ENCRYPTION_KEY` (any long random string),
   `MFP_CLIENT_ID`, `MFP_CLIENT_SECRET`. Optionally set the `ALLOWED_EMAILS`
   variable to your MFP email so nobody else can connect to your deployment.

### Option B — local wrangler

```sh
npm install
npx wrangler kv namespace create MFP_OAUTH_KV   # paste the id into wrangler.jsonc
npx wrangler kv namespace create MFP_CACHE      # paste the id into wrangler.jsonc
npx wrangler secret put SESSION_ENCRYPTION_KEY
npx wrangler secret put MFP_CLIENT_ID
npx wrangler secret put MFP_CLIENT_SECRET
npx wrangler deploy
```

## Connect in Claude

1. **Settings → Connectors → Add custom connector.**
2. URL: `https://myfitnesspal-mcp.<subdomain>.workers.dev/mcp`
3. Click **Connect** → sign in with your MyFitnessPal email/username and
   password → done.

Then: *"Run diagnostics on MyFitnessPal, then show me yesterday's nutrition."*

## Local development

```sh
cp .dev.vars.example .dev.vars   # set the secrets
npm run dev                      # http://localhost:8787
npm test                         # vitest (fake identity + API backend)
npm run typecheck
npm run icon
```

## Notes & limits

- **Unofficial.** The app's private client is used with your own credentials
  for personal use; MFP may rotate the client or change the API.
- **Health Connect already syncs MFP meal summaries** to Google Health; what
  this adds is the per-food log with timestamps, micros, water, MFP exercise
  and weight.
- **Nutrient goals** have no confirmed endpoint yet — `run_diagnostics`
  sweeps candidates and `query_endpoint` can explore.
- **Subrequest limits.** Every diary day is one upstream call; on the Workers
  free plan (50 subrequests/request) keep uncached windows short. Cached days
  are cheap.
- **Password changes** invalidate the refresh token — disconnect and
  reconnect the connector.

## Privacy

- Your password is exchanged once for tokens and never stored; the refresh
  token lives encrypted inside the OAuth grant.
- Diary data is cached only in your own KV namespace, sealed, and deletable
  with `delete_my_data`; nothing is sent to any third party.

## License

MIT

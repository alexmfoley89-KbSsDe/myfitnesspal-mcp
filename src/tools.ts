/**
 * Coaching-oriented MCP tools over the MyFitnessPal diary. Each answers a
 * question a coach actually asks ("what did I eat today and when?", "am I
 * hitting protein?", "how has intake tracked over the block?") and returns
 * compact JSON. Raw diary items are shaped by shape.ts, which is pure and
 * unit-tested; this file only orchestrates fetches and windows.
 */
import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { DIARY_TYPES, MfpApiError, MfpAuthError, MfpClient, type DiaryFetch, type IdentityUser } from "./mfp-api";
import { addDaysIso, enumerateDays, isoDaysAgo, todayIso } from "./dates";
import {
  MACRO_KEYS,
  NUTRIENT_KEYS,
  dailyTotals,
  normalizeDiaryDay,
  pickNutrients,
  weeklyTotals,
  windowStats,
  type DiaryDay,
  type NutrientKey,
} from "./shape";

/** These tools only read upstream data and reach an external API. */
const READ_ONLY = { readOnlyHint: true, openWorldHint: true } as const;

const ISO_DATE = z.string().regex(/^\d{4}-\d{2}-\d{2}$/);
const NUTRIENT = z.enum(NUTRIENT_KEYS as [NutrientKey, ...NutrientKey[]]);

/** One diary day is one API call (plus pagination); keep windows bounded. */
const MAX_WINDOW_DAYS = 92;
/** Parallel diary fetches per tool call. */
const CONCURRENCY = 6;

const round = (v: number, dp = 1) => Math.round(v * 10 ** dp) / 10 ** dp;

function jsonResult(data: unknown) {
  return { content: [{ type: "text" as const, text: JSON.stringify(data) }] };
}

/** Map an error to an actionable hint, when we recognise it. */
function hintFor(err: unknown): string | undefined {
  if (err instanceof MfpAuthError) return "MyFitnessPal no longer accepts the stored refresh token (password changed, session revoked, or token expired). Disconnect and reconnect the connector.";
  if (err instanceof MfpApiError) {
    if (err.status === 429) return "MyFitnessPal is rate-limiting; wait a minute and retry. Completed days are cached, so retries are cheap.";
    if (err.status && err.status >= 500) return "MyFitnessPal's servers are struggling; retry shortly.";
    if (err.status === 400 || err.status === 422) return "MyFitnessPal rejected the request shape. run_diagnostics shows which diary types/fields this account accepts; query_endpoint lets you try variations.";
  }
  const message = err instanceof Error ? err.message : String(err);
  if (/subrequest/i.test(message)) return "Too many upstream calls for one request — use a shorter window (each day is one call) and retry; cached days don't count.";
  if (/before start_date/.test(message)) return "Swap the dates: end_date must be on or after start_date.";
  return undefined;
}

function errorResult(err: unknown) {
  const message = err instanceof Error ? err.message : String(err);
  const hint = hintFor(err);
  return { content: [{ type: "text" as const, text: hint ? `Error: ${message}\n\nHint: ${hint}` : `Error: ${message}` }], isError: true };
}

// ---------------------------------------------------------------------------
// Windows & fetching
// ---------------------------------------------------------------------------

const WINDOW_SCHEMA = {
  start_date: ISO_DATE.optional().describe("Inclusive start, YYYY-MM-DD. Defaults to `days` before end_date."),
  end_date: ISO_DATE.optional().describe("Inclusive end, YYYY-MM-DD. Defaults to today."),
  days: z.number().int().min(1).max(MAX_WINDOW_DAYS).optional().describe(`Window length when start_date is omitted (max ${MAX_WINDOW_DAYS}; each day is one upstream call, completed days are cached).`),
};

interface Window {
  start_date: string;
  end_date: string;
  dates: string[];
}

function resolveWindow(args: { start_date?: string; end_date?: string; days?: number }, timeZone: string, defaultDays: number): Window {
  const end_date = args.end_date ?? todayIso(timeZone);
  const days = args.days ?? defaultDays;
  const start_date = args.start_date ?? (args.end_date ? addDaysIso(end_date, -(days - 1)) : isoDaysAgo(days - 1, timeZone));
  const dates = enumerateDays(start_date, end_date);
  if (dates.length > MAX_WINDOW_DAYS) throw new Error(`Window is ${dates.length} days; the maximum is ${MAX_WINDOW_DAYS}.`);
  return { start_date, end_date, dates };
}

async function mapPool<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i]);
    }
  });
  await Promise.all(workers);
  return out;
}

interface FetchedDays {
  days: DiaryDay[];
  fetches: DiaryFetch[];
}

async function fetchDays(client: MfpClient, dates: string[]): Promise<FetchedDays> {
  const fetches = await mapPool(dates, CONCURRENCY, (date) => client.getDiary(date));
  return { days: fetches.map((f) => normalizeDiaryDay(f.date, f.items)), fetches };
}

function fetchNotes(fetches: DiaryFetch[]): string | undefined {
  const rejected = new Set(fetches.flatMap((f) => f.rejected_types ?? []));
  return rejected.size
    ? `MyFitnessPal rejected the diary type(s) ${Array.from(rejected).join(", ")} for this account; those items are absent. run_diagnostics shows the accepted request shape.`
    : undefined;
}

function compact<T extends Record<string, unknown>>(obj: T): T {
  return JSON.parse(JSON.stringify(obj)) as T;
}

// ---------------------------------------------------------------------------
// Profile
// ---------------------------------------------------------------------------

function ageFromBirthdate(birthdate: string | undefined, now = new Date()): number | undefined {
  if (!birthdate) return undefined;
  const m = /^(\d{4})-(\d{2})-(\d{2})/.exec(birthdate);
  if (!m) return undefined;
  const [y, mo, d] = [parseInt(m[1], 10), parseInt(m[2], 10), parseInt(m[3], 10)];
  let age = now.getUTCFullYear() - y;
  if (now.getUTCMonth() + 1 < mo || (now.getUTCMonth() + 1 === mo && now.getUTCDate() < d)) age--;
  return age >= 0 && age < 130 ? age : undefined;
}

function normalizeProfile(user: IdentityUser, domainUserId: string) {
  const p = (user.profile ?? {}) as Record<string, unknown>;
  const heightIn = typeof p.height === "number" ? p.height : undefined;
  return compact({
    mfp_user_id: domainUserId,
    identity_user_id: user.userId !== undefined ? String(user.userId) : undefined,
    display_name: p.displayName ?? p.fullName,
    first_name: p.firstName,
    last_name: p.lastName ?? undefined,
    email: user.profileEmails?.emails?.find((e) => e.primary)?.email ?? user.profileEmails?.emails?.[0]?.email,
    gender: p.gender,
    birthdate: p.birthdate,
    age: ageFromBirthdate(typeof p.birthdate === "string" ? p.birthdate : undefined),
    height_cm: heightIn !== undefined ? round(heightIn * 2.54, 1) : undefined,
    profile_weight: typeof p.weight === "number" ? { value: p.weight, note: "as stored on the identity profile (MFP stores this in lb); use get_weight_log for logged weights" } : undefined,
    locale: p.locale,
    region: user.region,
    country: (p.location as { country?: string } | undefined)?.country,
    status: user.status,
  });
}

/**
 * Register all tools on the MCP server. `getClient` defers client
 * construction to call-time so props/bindings are live.
 */
export function registerTools(server: McpServer, getClient: () => MfpClient, timeZone: string) {
  server.registerTool(
    "get_daily_nutrition",
    {
      title: "Daily Nutrition",
      description:
        "Get one diary day: per-meal and whole-day totals (energy, protein, carbs, net carbs, fibre, sugar, fat and fat subtypes, cholesterol, sodium, potassium, calcium/iron/vitamins as %DV), every food logged with portion, water, logged exercise and steps. Custom meals (e.g. an on-bike fuelling meal) come through as their own meal. Caveat: `logged_at` is when the entry was logged, not eaten; treat `consumed_at` as eating time only if present and plausible. Defaults to today.",
      inputSchema: {
        date: ISO_DATE.optional().describe("Diary day, YYYY-MM-DD. Defaults to today."),
        include_foods: z.boolean().default(true).describe("Include the individual food entries (set false for totals only)."),
        nutrients: z.array(NUTRIENT).min(1).optional().describe("Nutrients to include on each food row (default: the macro set; meal/day totals always carry everything)."),
      },
      annotations: READ_ONLY,
    },
    async ({ date, include_foods, nutrients }) => {
      try {
        const client = getClient();
        const day = date ?? todayIso(timeZone);
        const fetch = await client.getDiary(day);
        const diary = normalizeDiaryDay(day, fetch.items);
        const keys = nutrients ?? MACRO_KEYS;
        const weight = await client.getMeasurements(day).catch(() => undefined);
        return jsonResult(
          compact({
            date: day,
            totals: diary.totals,
            totals_source: diary.totals_source,
            meals: diary.meals,
            foods: include_foods ? diary.foods.map((f) => ({ ...f, nutrition: pickNutrients(f.nutrition, keys) })) : undefined,
            water: diary.water,
            exercise: diary.exercise,
            steps: diary.steps,
            weight_entries: weight?.length ? weight : undefined,
            other_items: diary.other,
            note: fetchNotes([fetch]),
            cached: fetch.cached || undefined,
          }),
        );
      } catch (err) {
        return errorResult(err);
      }
    },
  );

  server.registerTool(
    "get_food_log",
    {
      title: "Food Log",
      description:
        "List individual food entries over a date range (default: last 7 days), oldest first, with meal, portion, timestamps and chosen nutrients. Filter by meal name or a text search over food descriptions. Use it to find recurring foods or per-meal detail. Caveat: `logged_at` is logging time, not eating time — meal name is the reliable signal for when food was eaten.",
      inputSchema: {
        ...WINDOW_SCHEMA,
        meal: z.string().optional().describe("Only this meal (e.g. \"Breakfast\", \"Snacks\"); case-insensitive."),
        search: z.string().optional().describe("Case-insensitive substring match on food description/brand."),
        nutrients: z.array(NUTRIENT).min(1).optional().describe("Nutrients per row (default: the macro set)."),
        limit: z.number().int().min(1).max(500).default(300).describe("Max rows (newest kept when truncating)."),
      },
      annotations: READ_ONLY,
    },
    async ({ start_date, end_date, days, meal, search, nutrients, limit }) => {
      try {
        const client = getClient();
        const w = resolveWindow({ start_date, end_date, days }, timeZone, 7);
        const { days: diaryDays, fetches } = await fetchDays(client, w.dates);
        const keys = nutrients ?? MACRO_KEYS;
        const needle = search?.toLowerCase();
        const mealNeedle = meal?.toLowerCase();
        let rows = diaryDays.flatMap((d) =>
          d.foods
            .filter((f) => !mealNeedle || (f.meal ?? "").toLowerCase() === mealNeedle)
            .filter((f) => !needle || `${f.description ?? ""} ${f.brand ?? ""}`.toLowerCase().includes(needle))
            .map((f) => compact({ date: d.date, meal: f.meal, description: f.description, brand: f.brand, servings: f.servings, serving_size: f.serving_size, consumed_at: f.consumed_at, logged_at: f.logged_at, nutrition: pickNutrients(f.nutrition, keys) })),
        );
        const total = rows.length;
        if (rows.length > limit) rows = rows.slice(rows.length - limit);
        return jsonResult(
          compact({
            window: { start_date: w.start_date, end_date: w.end_date, days: w.dates.length, time_zone: timeZone },
            days_logged: diaryDays.filter((d) => d.totals_source !== "none").length,
            returned: rows.length,
            total_matching: total,
            truncated_to_limit: rows.length < total || undefined,
            note: fetchNotes(fetches),
            foods: rows,
          }),
        );
      } catch (err) {
        return errorResult(err);
      }
    },
  );

  server.registerTool(
    "get_nutrition_trend",
    {
      title: "Nutrition Trend",
      description:
        "Daily intake totals over a window (default 30 days) with means over logged days, min/max energy, the protein/carb/fat energy split, weekly averages, plus water, exercise calories and steps per day. Use it to judge fuelling against training load and to spot under-logged days (logged=false).",
      inputSchema: {
        ...WINDOW_SCHEMA,
        nutrients: z.array(NUTRIENT).min(1).optional().describe("Nutrients to carry in the daily/weekly rows (default: the macro set; the stats block always has everything)."),
      },
      annotations: READ_ONLY,
    },
    async ({ start_date, end_date, days, nutrients }) => {
      try {
        const client = getClient();
        const w = resolveWindow({ start_date, end_date, days }, timeZone, 30);
        const { days: diaryDays, fetches } = await fetchDays(client, w.dates);
        const totals = diaryDays.map(dailyTotals);
        const keys = nutrients ?? MACRO_KEYS;
        const slim = (n: Record<string, unknown>) => {
          const out: Record<string, unknown> = {};
          for (const [k, v] of Object.entries(n)) if (!NUTRIENT_KEYS.includes(k as NutrientKey) || keys.includes(k as NutrientKey)) out[k] = v;
          return out;
        };
        return jsonResult(
          compact({
            window: { start_date: w.start_date, end_date: w.end_date, days: w.dates.length, time_zone: timeZone },
            stats: windowStats(totals),
            weekly: weeklyTotals(totals).map((wk) => ({ ...wk, mean: slim(wk.mean) })),
            daily: totals.map((d) => ({ ...d, nutrition: pickNutrients(d.nutrition, keys) ?? {} })),
            note: fetchNotes(fetches),
            reading_guide: [
              "Means are over logged days only; days with logged=false are unlogged, not zero-intake.",
              "energy_kcal is food intake; exercise_kcal is what MFP logged as burned (often inflated) — do not net them without checking the source.",
              "macro_split_pct uses 4/4/9 kcal per g of protein/carbohydrate/fat.",
            ],
          }),
        );
      } catch (err) {
        return errorResult(err);
      }
    },
  );

  server.registerTool(
    "get_exercise_log",
    {
      title: "Exercise & Steps Log",
      description:
        "Exercise entries logged in MyFitnessPal (name, start time, duration, calories, distance, heart rate where present) plus daily steps over a window (default 14 days). Note: sessions synced from Strava/Garmin may appear here with MFP's own calorie estimate.",
      inputSchema: WINDOW_SCHEMA,
      annotations: READ_ONLY,
    },
    async ({ start_date, end_date, days }) => {
      try {
        const client = getClient();
        const w = resolveWindow({ start_date, end_date, days }, timeZone, 14);
        const { days: diaryDays, fetches } = await fetchDays(client, w.dates);
        const rows = diaryDays.filter((d) => d.exercise.length || d.steps).map((d) => compact({ date: d.date, exercise: d.exercise.length ? d.exercise : undefined, steps: d.steps }));
        const totalKcal = diaryDays.reduce((a, d) => a + d.exercise.reduce((b, e) => b + (e.energy_kcal ?? 0), 0), 0);
        const totalMin = diaryDays.reduce((a, d) => a + d.exercise.reduce((b, e) => b + (e.duration_min ?? 0), 0), 0);
        return jsonResult(
          compact({
            window: { start_date: w.start_date, end_date: w.end_date, days: w.dates.length, time_zone: timeZone },
            sessions: diaryDays.reduce((a, d) => a + d.exercise.length, 0),
            total_exercise_kcal: round(totalKcal, 0),
            total_exercise_min: round(totalMin, 0),
            note: fetchNotes(fetches),
            days: rows,
          }),
        );
      } catch (err) {
        return errorResult(err);
      }
    },
  );

  server.registerTool(
    "get_weight_log",
    {
      title: "Weight Log",
      description:
        "Weight entries recorded in MyFitnessPal over a window (default 30 days) — the app's own check-ins and anything synced in from scales. Body-composition detail lives in the Renpho/Google Health connectors; this is MFP's view.",
      inputSchema: WINDOW_SCHEMA,
      annotations: READ_ONLY,
    },
    async ({ start_date, end_date, days }) => {
      try {
        const client = getClient();
        const w = resolveWindow({ start_date, end_date, days }, timeZone, 30);
        const perDay = await mapPool(w.dates, CONCURRENCY, async (date) => ({ date, items: await client.getMeasurements(date).catch((err: unknown) => ({ error: err instanceof Error ? err.message : String(err) })) }));
        const entries = perDay.flatMap((d) => (Array.isArray(d.items) ? d.items.map((m) => ({ date: d.date, ...m })) : []));
        const errors = perDay.filter((d) => !Array.isArray(d.items)).map((d) => `${d.date}: ${(d.items as { error: string }).error}`);
        return jsonResult(
          compact({
            window: { start_date: w.start_date, end_date: w.end_date, days: w.dates.length, time_zone: timeZone },
            entries,
            errors: errors.length ? errors.slice(0, 5) : undefined,
          }),
        );
      } catch (err) {
        return errorResult(err);
      }
    },
  );

  server.registerTool(
    "get_profile",
    {
      title: "Profile",
      description: "MyFitnessPal account profile: name, sex, birthdate/age, height, locale/region, and the connector's token status.",
      inputSchema: {},
      annotations: READ_ONLY,
    },
    async () => {
      try {
        const client = getClient();
        const user = await client.getIdentityUser();
        const token = await client.peekToken();
        return jsonResult(
          compact({
            profile: normalizeProfile(user, client.domainUserId),
            token: { source: token.source, expires_at: token.expiresAt ? new Date(token.expiresAt).toISOString() : undefined },
          }),
        );
      } catch (err) {
        return errorResult(err);
      }
    },
  );

  // Self-check: exercises every step of the pipeline and reports the request
  // shape MFP accepts for this account, so "the connector is broken" becomes a
  // precise diagnosis and unknown endpoints can be discovered.
  server.registerTool(
    "run_diagnostics",
    {
      title: "Run Diagnostics",
      description:
        "Probe the MyFitnessPal connection end to end: token status and refresh, identity profile, which diary types/fields this account accepts (with item counts and a raw sample per type for a chosen day), the measurements endpoint, and a sweep of candidate goal endpoints. Use this when data looks missing or a tool errors.",
      inputSchema: { date: ISO_DATE.optional().describe("Diary day to probe (default: yesterday, which is normally fully logged).") },
      annotations: READ_ONLY,
    },
    async ({ date }) => {
      const client = getClient();
      const out: Record<string, unknown> = { now: new Date().toISOString(), time_zone: timeZone, cache_enabled: client.cacheEnabled };
      const probe = async <T>(name: string, fn: () => Promise<T>): Promise<T | undefined> => {
        try {
          const value = await fn();
          out[name] = value;
          return value;
        } catch (err) {
          out[name] = { error: err instanceof Error ? err.message : String(err), hint: hintFor(err) };
          return undefined;
        }
      };

      out.token_before = await client.peekToken();
      const token = await probe("token", async () => {
        await client.getAccessToken(true);
        const t = await client.peekToken();
        return { refreshed: true, expires_at: t.expiresAt ? new Date(t.expiresAt).toISOString() : undefined };
      });
      if (!token) return jsonResult(out);

      await probe("identity_user", async () => normalizeProfile(await client.getIdentityUser(), client.domainUserId));

      const day = date ?? isoDaysAgo(1, timeZone);
      await probe("diary", async () => {
        const f = await client.getDiary(day, { noCache: true });
        const counts: Record<string, number> = {};
        const samples: Record<string, string> = {};
        for (const item of f.items) {
          const t = String(item.type ?? "unknown");
          counts[t] = (counts[t] ?? 0) + 1;
          // A string preview, deliberately: truncated JSON must not be re-parsed.
          if (!samples[t]) {
            const text = JSON.stringify(item);
            samples[t] = text.length > 1200 ? `${text.slice(0, 1200)}… (${text.length} chars)` : text;
          }
        }
        const diary = normalizeDiaryDay(day, f.items);
        return compact({
          date: day,
          accepted_types: f.types,
          accepted_fields: f.fields.length ? f.fields : "(server defaults)",
          rejected_types: f.rejected_types,
          pages: f.pages,
          items_by_type: counts,
          totals: diary.totals,
          totals_source: diary.totals_source,
          meals: diary.meals.map((m) => m.meal),
          foods: diary.foods.length,
          raw_sample_per_type: samples,
        });
      });

      await probe("measurements", () => client.getMeasurements(day));

      await probe("candidate_endpoints", async () => {
        const today = todayIso(timeZone);
        const candidates: Array<{ path: string; query?: Record<string, string>; base?: "api" | "identity" }> = [
          { path: "v2/nutrient-goals" },
          { path: "v2/nutrient-goals", query: { date: today } },
          { path: "v2/goals" },
          { path: "v2/user-goals" },
          { path: `v2/users/${client.domainUserId}` },
          { path: "v2/diary/water", query: { date: today } },
          { path: "v2/user-properties" },
          { path: "v2/water-goals" },
        ];
        return Promise.all(candidates.map((c) => client.probe(c.path, c.query, c.base)));
      });

      return jsonResult(out);
    },
  );

  // Escape hatch: call any endpoint of the MFP API directly.
  server.registerTool(
    "query_endpoint",
    {
      title: "Query Any MyFitnessPal Endpoint (advanced)",
      description:
        `Call an arbitrary api.myfitnesspal.com (or identity-api.myfitnesspal.com) endpoint with the connector's auth and app headers applied, returning the JSON. For data without a dedicated tool (nutrient goals, food search \`v2/search/nutrition?q=…\`, recipes, meal collections) or to try diary variations (\`v2/diary?entry_date=…&types=…&fields[]=…\`). Known diary types: ${DIARY_TYPES.join(", ")}. Prefer GET; the API also has write endpoints — do not POST unless the user explicitly asked to log something.`,
      inputSchema: {
        path: z.string().regex(/^[A-Za-z0-9_\-/.]+$/).max(200).describe("Path relative to the API root, e.g. \"v2/diary\"."),
        query: z.record(z.union([z.string(), z.array(z.string())])).optional().describe("Query parameters; arrays are sent as repeated `name[]` (e.g. fields)."),
        method: z.enum(["GET", "POST"]).default("GET"),
        body: z.record(z.unknown()).optional().describe("JSON body for POST."),
        base: z.enum(["api", "identity"]).default("api").describe("api = api.myfitnesspal.com, identity = identity-api.myfitnesspal.com."),
      },
      annotations: { readOnlyHint: false, destructiveHint: true, openWorldHint: true },
    },
    async ({ path, query, method, body, base }) => {
      try {
        const res = await getClient().request(path, { method, query, body, base });
        const text = JSON.stringify(res.json);
        const MAX = 200_000;
        if (text.length > MAX) return jsonResult({ path, status: res.status, truncated: true, bytes: text.length, preview: text.slice(0, MAX) });
        return jsonResult({ path, status: res.status, data: res.json, link: res.headers.get("link") ?? undefined });
      } catch (err) {
        return errorResult(err);
      }
    },
  );

  server.registerTool(
    "refresh_data",
    {
      title: "Refresh Token & Cache",
      description:
        "Drop the cached diary days, the remembered request shape and the access token for this account, then refresh the token. Use after edits to past days in the app, or when data looks stale.",
      inputSchema: {},
      annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: true },
    },
    async () => {
      try {
        const client = getClient();
        const purged = await client.purgeCache();
        await client.getAccessToken(true);
        const t = await client.peekToken();
        return jsonResult({ purged_cache_entries: purged, token_expires_at: t.expiresAt ? new Date(t.expiresAt).toISOString() : undefined });
      } catch (err) {
        return errorResult(err);
      }
    },
  );

  server.registerTool(
    "delete_my_data",
    {
      title: "Delete My Cached Data",
      description:
        "Delete everything this connector has cached for your account (tokens and diary days). Your data in MyFitnessPal is untouched. To fully revoke access, also disconnect the connector in Claude — that deletes the stored refresh token.",
      inputSchema: {},
      annotations: { readOnlyHint: false, destructiveHint: true, openWorldHint: false },
    },
    async () => {
      try {
        const deleted = await getClient().purgeCache();
        return jsonResult({
          deleted_cache_entries: deleted,
          note: "Cached data cleared. Disconnect the connector in Claude (Settings → Connectors) to delete the stored refresh token as well.",
        });
      } catch (err) {
        return errorResult(err);
      }
    },
  );
}

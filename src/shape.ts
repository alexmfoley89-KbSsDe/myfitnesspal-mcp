/**
 * Pure shaping of MyFitnessPal diary items into a compact, self-describing
 * form for Claude: unit-suffixed nutrient keys, per-meal and per-day totals,
 * lean food/exercise/water rows. Anything unrecognised is kept under `extra`
 * so nothing is lost when MFP adds fields.
 */
import { weekStartOf } from "./dates";

export type RawItem = Record<string, unknown>;

/**
 * MFP `nutritional_contents` key → output key. Energy arrives as
 * `{unit, value}` and is normalised to kcal. Calcium/iron/vitamins are
 * percent-of-daily-value in MFP's food database, so they keep a `_pct_dv`
 * suffix rather than a mass unit.
 */
export const NUTRIENT_FIELDS: ReadonlyArray<readonly [raw: string, out: NutrientKey]> = [
  ["protein", "protein_g"],
  ["carbohydrates", "carbohydrates_g"],
  ["net_carbs", "net_carbs_g"],
  ["fiber", "fiber_g"],
  ["sugar", "sugar_g"],
  ["fat", "fat_g"],
  ["saturated_fat", "saturated_fat_g"],
  ["monounsaturated_fat", "monounsaturated_fat_g"],
  ["polyunsaturated_fat", "polyunsaturated_fat_g"],
  ["trans_fat", "trans_fat_g"],
  ["cholesterol", "cholesterol_mg"],
  ["sodium", "sodium_mg"],
  ["potassium", "potassium_mg"],
  ["calcium", "calcium_pct_dv"],
  ["iron", "iron_pct_dv"],
  ["vitamin_a", "vitamin_a_pct_dv"],
  ["vitamin_c", "vitamin_c_pct_dv"],
  ["vitamin_d", "vitamin_d_pct_dv"],
] as const;

export type NutrientKey =
  | "energy_kcal"
  | "protein_g"
  | "carbohydrates_g"
  | "net_carbs_g"
  | "fiber_g"
  | "sugar_g"
  | "fat_g"
  | "saturated_fat_g"
  | "monounsaturated_fat_g"
  | "polyunsaturated_fat_g"
  | "trans_fat_g"
  | "cholesterol_mg"
  | "sodium_mg"
  | "potassium_mg"
  | "calcium_pct_dv"
  | "iron_pct_dv"
  | "vitamin_a_pct_dv"
  | "vitamin_c_pct_dv"
  | "vitamin_d_pct_dv";

export const NUTRIENT_KEYS: NutrientKey[] = ["energy_kcal", ...NUTRIENT_FIELDS.map(([, out]) => out)];

/** The macros most coaching questions need; the default for trend tools. */
export const MACRO_KEYS: NutrientKey[] = ["energy_kcal", "protein_g", "carbohydrates_g", "fat_g", "fiber_g", "sugar_g", "sodium_mg"];

export type Nutrition = Partial<Record<NutrientKey, number>> & { extra?: Record<string, unknown> };

const round = (v: number, dp = 1) => Math.round(v * 10 ** dp) / 10 ** dp;

function num(v: unknown): number | undefined {
  if (typeof v === "number" && Number.isFinite(v)) return v;
  if (typeof v === "string" && v.trim() !== "" && Number.isFinite(Number(v))) return Number(v);
  return undefined;
}

function str(v: unknown): string | undefined {
  if (v === null || v === undefined) return undefined;
  const s = String(v);
  return s === "" ? undefined : s;
}

/** Energy `{unit, value}` (or a bare number) → kcal. */
export function energyKcal(v: unknown): number | undefined {
  if (v && typeof v === "object") {
    const e = v as { unit?: string; value?: unknown };
    const value = num(e.value);
    if (value === undefined) return undefined;
    return /kilojoule|kj/i.test(e.unit ?? "") ? round(value / 4.184, 0) : round(value, 0);
  }
  const n = num(v);
  return n === undefined ? undefined : round(n, 0);
}

/** `nutritional_contents` → Nutrition. Returns undefined when nothing usable is present. */
export function normalizeNutrition(raw: unknown): Nutrition | undefined {
  if (!raw || typeof raw !== "object") return undefined;
  const src = raw as Record<string, unknown>;
  const out: Nutrition = {};
  const kcal = energyKcal(src.energy);
  if (kcal !== undefined) out.energy_kcal = kcal;
  const consumed = new Set(["energy", "additional_columns"]);
  for (const [rawKey, outKey] of NUTRIENT_FIELDS) {
    consumed.add(rawKey);
    const v = num(src[rawKey]);
    if (v !== undefined) out[outKey] = round(v, 1);
  }
  const extra: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(src)) {
    if (consumed.has(k) || v === null || v === undefined || v === 0 || v === "") continue;
    extra[k] = v;
  }
  if (Object.keys(extra).length) out.extra = extra;
  return Object.keys(out).length ? out : undefined;
}

/** Sum a list of Nutrition objects key-by-key (extras are dropped). */
export function sumNutrition(list: Array<Nutrition | undefined>): Nutrition {
  const out: Nutrition = {};
  for (const n of list) {
    if (!n) continue;
    for (const key of NUTRIENT_KEYS) {
      const v = n[key];
      if (typeof v === "number") out[key] = round((out[key] ?? 0) + v, 1);
    }
  }
  return out;
}

export function pickNutrients(n: Nutrition | undefined, keys: NutrientKey[]): Nutrition | undefined {
  if (!n) return undefined;
  const out: Nutrition = {};
  for (const k of keys) if (typeof n[k] === "number") out[k] = n[k];
  return Object.keys(out).length ? out : undefined;
}

// ---------------------------------------------------------------------------
// Diary items
// ---------------------------------------------------------------------------

export interface FoodEntry {
  id?: string;
  meal?: string;
  meal_position?: number;
  description?: string;
  brand?: string;
  food_id?: string;
  servings?: number;
  serving_size?: string;
  consumed_at?: string;
  logged_at?: string;
  nutrition?: Nutrition;
  extra?: Record<string, unknown>;
}

export interface MealSummary {
  meal: string;
  meal_position?: number;
  foods?: number;
  nutrition: Nutrition;
}

export interface ExerciseEntry {
  id?: string;
  name?: string;
  exercise_type?: string;
  exercise_id?: string;
  start_time?: string;
  duration_min?: number;
  energy_kcal?: number;
  distance?: { value: number; unit?: string };
  avg_heart_rate?: number;
  max_heart_rate?: number;
  sets?: number;
  reps_per_set?: number;
  weight_per_set?: { value: number; unit?: string };
  tags?: string[];
  extra?: Record<string, unknown>;
}

export interface WaterEntry {
  cups?: number;
  milliliters?: number;
}

export interface StepsEntry {
  steps?: number;
  energy_kcal?: number;
  primary?: boolean;
  source?: string;
}

export interface DiaryDay {
  date: string;
  totals: Nutrition;
  /** Where `totals` came from: MFP's own meal summaries or a sum of food entries. */
  totals_source: "diary_meal" | "food_entry" | "none";
  meals: MealSummary[];
  foods: FoodEntry[];
  water?: WaterEntry;
  exercise: ExerciseEntry[];
  steps?: StepsEntry;
  /** Items of a type this shaper doesn't know, passed through raw. */
  other?: RawItem[];
}

const MEAL_ORDER = ["breakfast", "lunch", "dinner", "snacks", "snack"];

function mealSort(a: { meal: string; meal_position?: number }, b: { meal: string; meal_position?: number }): number {
  if (a.meal_position !== undefined && b.meal_position !== undefined) return a.meal_position - b.meal_position;
  const ia = MEAL_ORDER.indexOf(a.meal.toLowerCase());
  const ib = MEAL_ORDER.indexOf(b.meal.toLowerCase());
  return (ia === -1 ? 99 : ia) - (ib === -1 ? 99 : ib);
}

function compactObj<T extends Record<string, unknown>>(obj: T): T {
  return JSON.parse(JSON.stringify(obj)) as T;
}

function measured(v: unknown): { value: number; unit?: string } | undefined {
  if (!v || typeof v !== "object") return undefined;
  const m = v as { value?: unknown; unit?: unknown };
  const value = num(m.value);
  return value === undefined ? undefined : { value, unit: str(m.unit) };
}

const FOOD_CONSUMED = new Set(["id", "type", "date", "meal_name", "meal_position", "food", "servings", "serving_size", "nutritional_contents", "consumed_at", "logged_at", "logged_at_offset", "client_id", "meal_food_id", "geolocation", "image_ids", "tags"]);

export function normalizeFoodEntry(item: RawItem): FoodEntry {
  const food = (item.food ?? {}) as Record<string, unknown>;
  const ss = (item.serving_size ?? {}) as Record<string, unknown>;
  const ssValue = num(ss.value);
  const ssUnit = str(ss.unit);
  const extra: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(item)) {
    if (FOOD_CONSUMED.has(k) || v === null || v === undefined || v === "" || (Array.isArray(v) && !v.length)) continue;
    extra[k] = v;
  }
  return compactObj({
    id: str(item.id),
    meal: str(item.meal_name),
    meal_position: num(item.meal_position),
    description: str(food.description),
    brand: str(food.brand_name),
    food_id: str(food.id),
    servings: num(item.servings),
    serving_size: ssValue !== undefined ? `${ssValue}${ssUnit ? ` ${ssUnit}` : ""}` : undefined,
    consumed_at: str(item.consumed_at),
    logged_at: str(item.logged_at),
    nutrition: normalizeNutrition(item.nutritional_contents) ?? normalizeNutrition(food.nutritional_contents),
    extra: Object.keys(extra).length ? extra : undefined,
  });
}

const EXERCISE_CONSUMED = new Set(["id", "type", "date", "exercise", "start_time", "duration", "energy", "distance", "avg_heart_rate", "max_heart_rate", "sets", "reps_per_set", "weight_per_set", "tags", "device_id", "quantity", "max_speed", "elevation_change"]);

export function normalizeExerciseEntry(item: RawItem): ExerciseEntry {
  const ex = (item.exercise ?? {}) as Record<string, unknown>;
  const duration = num(item.duration);
  const extra: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(item)) {
    if (EXERCISE_CONSUMED.has(k) || v === null || v === undefined || v === "" || (Array.isArray(v) && !v.length)) continue;
    extra[k] = v;
  }
  return compactObj({
    id: str(item.id),
    name: str(ex.description) ?? str(ex.name),
    exercise_type: str(ex.type),
    exercise_id: str(ex.id),
    start_time: str(item.start_time),
    duration_min: duration === undefined ? undefined : round(duration / 60, 1),
    energy_kcal: energyKcal(item.energy),
    distance: measured(item.distance),
    avg_heart_rate: num(item.avg_heart_rate),
    max_heart_rate: num(item.max_heart_rate),
    sets: num(item.sets),
    reps_per_set: num(item.reps_per_set),
    weight_per_set: measured(item.weight_per_set),
    tags: Array.isArray(item.tags) && item.tags.length ? (item.tags as string[]) : undefined,
    extra: Object.keys(extra).length ? extra : undefined,
  });
}

/** Group raw diary items for one day into a DiaryDay. */
export function normalizeDiaryDay(date: string, items: RawItem[]): DiaryDay {
  const foods: FoodEntry[] = [];
  const mealSummaries: MealSummary[] = [];
  const exercise: ExerciseEntry[] = [];
  const other: RawItem[] = [];
  let water: WaterEntry | undefined;
  let steps: StepsEntry | undefined;

  for (const item of items) {
    switch (str(item.type)) {
      case "food_entry":
        foods.push(normalizeFoodEntry(item));
        break;
      case "diary_meal": {
        const nutrition = normalizeNutrition(item.nutritional_contents);
        if (nutrition) mealSummaries.push({ meal: str(item.diary_meal) ?? str(item.meal_name) ?? "Unknown", meal_position: num(item.meal_position), nutrition });
        break;
      }
      case "exercise_entry":
      case "exercise":
        exercise.push(normalizeExerciseEntry(item));
        break;
      case "water": {
        const cups = num(item.cups);
        const ml = num(item.milliliters);
        water = { cups: cups === undefined ? water?.cups : (water?.cups ?? 0) + cups, milliliters: ml === undefined ? water?.milliliters : (water?.milliliters ?? 0) + ml };
        break;
      }
      case "steps_aggregate":
      case "steps": {
        const s = num(item.steps);
        if (s !== undefined && (!steps || item.primary === true || (steps.steps ?? 0) < s)) {
          steps = compactObj({ steps: s, energy_kcal: energyKcal(item.energy), primary: typeof item.primary === "boolean" ? item.primary : undefined, source: str(item.device_id) ?? str(item.client_id) });
        }
        break;
      }
      default:
        other.push(item);
    }
  }

  // Meal totals: MFP's own summaries when present, otherwise summed from foods.
  let meals: MealSummary[];
  let totals_source: DiaryDay["totals_source"];
  if (mealSummaries.length) {
    meals = mealSummaries;
    totals_source = "diary_meal";
    if (foods.length) {
      for (const m of meals) m.foods = foods.filter((f) => (f.meal ?? "").toLowerCase() === m.meal.toLowerCase()).length;
    }
  } else if (foods.length) {
    const byMeal = new Map<string, { position?: number; nutrition: Nutrition[]; count: number }>();
    for (const f of foods) {
      const name = f.meal ?? "Unknown";
      const g = byMeal.get(name) ?? { position: f.meal_position, nutrition: [], count: 0 };
      g.nutrition.push(f.nutrition ?? {});
      g.count++;
      byMeal.set(name, g);
    }
    meals = Array.from(byMeal.entries()).map(([meal, g]) => ({ meal, meal_position: g.position, foods: g.count, nutrition: sumNutrition(g.nutrition) }));
    totals_source = "food_entry";
  } else {
    meals = [];
    totals_source = "none";
  }
  meals.sort(mealSort);
  foods.sort((a, b) => mealSort({ meal: a.meal ?? "", meal_position: a.meal_position }, { meal: b.meal ?? "", meal_position: b.meal_position }));

  return compactObj({
    date,
    totals: sumNutrition(meals.map((m) => m.nutrition)),
    totals_source,
    meals,
    foods,
    water,
    exercise,
    steps,
    other: other.length ? other : undefined,
  });
}

// ---------------------------------------------------------------------------
// Windows
// ---------------------------------------------------------------------------

export interface DailyTotals {
  date: string;
  logged: boolean;
  foods: number;
  nutrition: Nutrition;
  water_ml?: number;
  exercise_kcal?: number;
  exercise_min?: number;
  steps?: number;
}

export function dailyTotals(day: DiaryDay): DailyTotals {
  const exercise_kcal = day.exercise.reduce((a, e) => a + (e.energy_kcal ?? 0), 0);
  const exercise_min = day.exercise.reduce((a, e) => a + (e.duration_min ?? 0), 0);
  return compactObj({
    date: day.date,
    logged: day.totals_source !== "none",
    foods: day.foods.length,
    nutrition: day.totals,
    water_ml: day.water?.milliliters ?? (day.water?.cups !== undefined ? round(day.water.cups * 236.588, 0) : undefined),
    exercise_kcal: day.exercise.length ? round(exercise_kcal, 0) : undefined,
    exercise_min: day.exercise.length ? round(exercise_min, 0) : undefined,
    steps: day.steps?.steps,
  });
}

export interface WindowStats {
  days: number;
  days_logged: number;
  /** Means over logged days only. */
  mean: Nutrition & { water_ml?: number; exercise_kcal?: number; steps?: number };
  min_energy_kcal?: number;
  max_energy_kcal?: number;
  /** Protein/carb/fat share of energy on logged days (4/4/9 kcal per g). */
  macro_split_pct?: { protein: number; carbohydrates: number; fat: number };
}

export function windowStats(days: DailyTotals[]): WindowStats {
  const logged = days.filter((d) => d.logged);
  const mean: WindowStats["mean"] = {};
  if (logged.length) {
    for (const key of NUTRIENT_KEYS) {
      const vals = logged.map((d) => d.nutrition[key]).filter((v): v is number => typeof v === "number");
      if (vals.length) mean[key] = round(vals.reduce((a, b) => a + b, 0) / vals.length, 1);
    }
    for (const key of ["water_ml", "exercise_kcal", "steps"] as const) {
      const vals = logged.map((d) => d[key]).filter((v): v is number => typeof v === "number");
      if (vals.length) mean[key] = round(vals.reduce((a, b) => a + b, 0) / vals.length, 0);
    }
  }
  const energies = logged.map((d) => d.nutrition.energy_kcal).filter((v): v is number => typeof v === "number");
  const p = (mean.protein_g ?? 0) * 4;
  const c = (mean.carbohydrates_g ?? 0) * 4;
  const f = (mean.fat_g ?? 0) * 9;
  const total = p + c + f;
  return compactObj({
    days: days.length,
    days_logged: logged.length,
    mean,
    min_energy_kcal: energies.length ? Math.min(...energies) : undefined,
    max_energy_kcal: energies.length ? Math.max(...energies) : undefined,
    macro_split_pct: total > 0 ? { protein: round((p / total) * 100, 0), carbohydrates: round((c / total) * 100, 0), fat: round((f / total) * 100, 0) } : undefined,
  });
}

export interface WeeklyTotals {
  week_start: string;
  days_logged: number;
  mean: Nutrition & { water_ml?: number; exercise_kcal?: number; steps?: number };
}

export function weeklyTotals(days: DailyTotals[]): WeeklyTotals[] {
  const byWeek = new Map<string, DailyTotals[]>();
  for (const d of days) {
    const ws = weekStartOf(d.date);
    const list = byWeek.get(ws);
    if (list) list.push(d);
    else byWeek.set(ws, [d]);
  }
  return Array.from(byWeek.entries())
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([week_start, list]) => {
      const s = windowStats(list);
      return { week_start, days_logged: s.days_logged, mean: s.mean };
    });
}

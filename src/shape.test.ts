import { describe, it, expect } from "vitest";
import {
  NUTRIENT_KEYS,
  dailyTotals,
  energyKcal,
  normalizeDiaryDay,
  normalizeExerciseEntry,
  normalizeFoodEntry,
  normalizeNutrition,
  pickNutrients,
  sumNutrition,
  weeklyTotals,
  windowStats,
  type RawItem,
} from "./shape";

const nc = (over: Record<string, unknown> = {}) => ({
  energy: { unit: "calories", value: 515 },
  protein: 22.35,
  fat: 25.72,
  saturated_fat: 5.5,
  carbohydrates: 49.72,
  net_carbs: 40.71,
  fiber: 9.01,
  sugar: 26.26,
  sodium: 945.06,
  potassium: 300,
  cholesterol: 420.44,
  calcium: 10,
  iron: 8,
  vitamin_a: 12,
  vitamin_c: 0,
  additional_columns: {},
  ...over,
});

describe("normalizeNutrition / energyKcal", () => {
  it("renames with units, normalises energy to kcal, drops zeros into nothing, keeps unknowns", () => {
    const n = normalizeNutrition(nc({ magnesium: 44 }))!;
    expect(n).toMatchObject({ energy_kcal: 515, protein_g: 22.4, fat_g: 25.7, saturated_fat_g: 5.5, carbohydrates_g: 49.7, net_carbs_g: 40.7, fiber_g: 9, sugar_g: 26.3, sodium_mg: 945.1, potassium_mg: 300, cholesterol_mg: 420.4, calcium_pct_dv: 10, iron_pct_dv: 8, vitamin_a_pct_dv: 12, vitamin_c_pct_dv: 0 });
    expect(n.extra).toEqual({ magnesium: 44 });
    expect(normalizeNutrition(null)).toBeUndefined();
    expect(normalizeNutrition({})).toBeUndefined();
  });

  it("converts kilojoules and accepts bare numbers", () => {
    expect(energyKcal({ unit: "kilojoules", value: 2092 })).toBe(500);
    expect(energyKcal({ unit: "kJ", value: 4184 })).toBe(1000);
    expect(energyKcal(123.4)).toBe(123);
    expect(energyKcal("x")).toBeUndefined();
  });

  it("sums and picks", () => {
    const sum = sumNutrition([{ energy_kcal: 500, protein_g: 20.5 }, { energy_kcal: 300, protein_g: 10.25, fat_g: 5 }, undefined]);
    expect(sum).toEqual({ energy_kcal: 800, protein_g: 30.8, fat_g: 5 });
    expect(pickNutrients(sum, ["protein_g", "fiber_g"])).toEqual({ protein_g: 30.8 });
    expect(pickNutrients(undefined, ["protein_g"])).toBeUndefined();
    expect(NUTRIENT_KEYS[0]).toBe("energy_kcal");
  });
});

const foodItem = (over: Record<string, unknown> = {}): RawItem => ({
  id: "fe1",
  type: "food_entry",
  date: "2026-08-25",
  meal_name: "Breakfast",
  meal_position: 0,
  food: { id: "f-oats", description: "Porridge oats", brand_name: "Quaker", version: "v1", nutritional_contents: nc() },
  servings: 1.5,
  serving_size: { value: 40, unit: "g" },
  nutritional_contents: nc({ energy: { unit: "calories", value: 240 }, protein: 8 }),
  consumed_at: "2026-08-25T07:10:00Z",
  logged_at: "2026-08-25T07:12:00Z",
  logged_at_offset: "+01:00",
  client_id: "x",
  image_ids: [],
  tags: [],
  geolocation: {},
  ...over,
});

describe("normalizeFoodEntry / normalizeExerciseEntry", () => {
  it("flattens a food entry, preferring the entry's own nutrition over the food's", () => {
    const f = normalizeFoodEntry(foodItem({ mystery: 1 }));
    expect(f).toEqual({
      id: "fe1",
      meal: "Breakfast",
      meal_position: 0,
      description: "Porridge oats",
      brand: "Quaker",
      food_id: "f-oats",
      servings: 1.5,
      serving_size: "40 g",
      consumed_at: "2026-08-25T07:10:00Z",
      logged_at: "2026-08-25T07:12:00Z",
      nutrition: expect.objectContaining({ energy_kcal: 240, protein_g: 8 }),
      extra: { mystery: 1 },
    });
  });

  it("falls back to the food's nutrition and flattens exercise", () => {
    const f = normalizeFoodEntry(foodItem({ nutritional_contents: undefined }));
    expect(f.nutrition?.energy_kcal).toBe(515);
    const e = normalizeExerciseEntry({ id: "e1", type: "exercise_entry", exercise: { id: "134", description: "Running", type: "cardio" }, start_time: "2026-08-25T18:00:00Z", duration: 1800, energy: { unit: "calories", value: 310 }, distance: { unit: "kilometers", value: 5.2 }, avg_heart_rate: 150, max_heart_rate: null, tags: [] });
    expect(e).toEqual({ id: "e1", name: "Running", exercise_type: "cardio", exercise_id: "134", start_time: "2026-08-25T18:00:00Z", duration_min: 30, energy_kcal: 310, distance: { value: 5.2, unit: "kilometers" }, avg_heart_rate: 150 });
  });
});

describe("normalizeDiaryDay", () => {
  const items: RawItem[] = [
    foodItem({ id: "fe2", meal_name: "Lunch", meal_position: 1, nutritional_contents: nc({ energy: { unit: "calories", value: 600 }, protein: 40 }) }),
    foodItem(),
    foodItem({ id: "fe3", meal_name: "Breakfast", nutritional_contents: nc({ energy: { unit: "calories", value: 100 }, protein: 5 }) }),
    { type: "diary_meal", date: "2026-08-25", diary_meal: "Lunch", nutritional_contents: nc({ energy: { unit: "calories", value: 600 }, protein: 40 }) },
    { type: "diary_meal", date: "2026-08-25", diary_meal: "Breakfast", nutritional_contents: nc({ energy: { unit: "calories", value: 340 }, protein: 13 }) },
    { type: "exercise_entry", id: "e1", exercise: { id: "1", description: "Cycling" }, duration: 3600, energy: { unit: "calories", value: 500 } },
    { type: "water", date: "2026-08-25", cups: 2, milliliters: 473 },
    { type: "water", date: "2026-08-25", cups: 1, milliliters: 236 },
    { type: "steps_aggregate", steps: 8000, primary: false, device_id: "phone" },
    { type: "steps_aggregate", steps: 9500, primary: true, device_id: "watch", energy: { unit: "calories", value: 300 } },
    { type: "fasting_entry", id: "x", hours: 16 },
  ];

  it("uses MFP's meal summaries for totals when present, sorts meals, aggregates water, picks primary steps", () => {
    const day = normalizeDiaryDay("2026-08-25", items);
    expect(day.totals_source).toBe("diary_meal");
    expect(day.totals).toMatchObject({ energy_kcal: 940, protein_g: 53 });
    expect(day.meals.map((m) => [m.meal, m.foods])).toEqual([["Breakfast", 2], ["Lunch", 1]]);
    expect(day.foods.map((f) => f.id)).toEqual(["fe1", "fe3", "fe2"]);
    expect(day.water).toEqual({ cups: 3, milliliters: 709 });
    expect(day.steps).toEqual({ steps: 9500, energy_kcal: 300, primary: true, source: "watch" });
    expect(day.exercise[0].name).toBe("Cycling");
    expect(day.other).toEqual([{ type: "fasting_entry", id: "x", hours: 16 }]);
  });

  it("derives meals from food entries when no summaries exist, and handles an empty day", () => {
    const day = normalizeDiaryDay("2026-08-25", items.filter((i) => i.type === "food_entry"));
    expect(day.totals_source).toBe("food_entry");
    expect(day.meals.map((m) => [m.meal, m.foods, m.nutrition.energy_kcal])).toEqual([["Breakfast", 2, 340], ["Lunch", 1, 600]]);
    expect(day.totals.energy_kcal).toBe(940);
    const empty = normalizeDiaryDay("2026-08-24", []);
    expect(empty).toEqual({ date: "2026-08-24", totals: {}, totals_source: "none", meals: [], foods: [], exercise: [] });
  });

  it("rolls days up into totals, window stats and weeks", () => {
    const day = normalizeDiaryDay("2026-08-25", items);
    const t = dailyTotals(day);
    expect(t).toMatchObject({ date: "2026-08-25", logged: true, foods: 3, water_ml: 709, exercise_kcal: 500, exercise_min: 60, steps: 9500 });
    expect(t.nutrition.energy_kcal).toBe(940);

    const unlogged = dailyTotals(normalizeDiaryDay("2026-08-24", []));
    expect(unlogged.logged).toBe(false);

    const stats = windowStats([t, unlogged, { ...t, date: "2026-08-31", nutrition: { energy_kcal: 2000, protein_g: 150, carbohydrates_g: 250, fat_g: 60 } }]);
    expect(stats.days).toBe(3);
    expect(stats.days_logged).toBe(2);
    expect(stats.mean.energy_kcal).toBe(1470);
    expect(stats.min_energy_kcal).toBe(940);
    expect(stats.max_energy_kcal).toBe(2000);
    expect(stats.macro_split_pct!.protein + stats.macro_split_pct!.carbohydrates + stats.macro_split_pct!.fat).toBeGreaterThanOrEqual(99);

    const weeks = weeklyTotals([unlogged, t, { ...t, date: "2026-08-31" }]);
    expect(weeks.map((w) => [w.week_start, w.days_logged])).toEqual([["2026-08-24", 1], ["2026-08-31", 1]]);
  });
});

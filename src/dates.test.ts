import { describe, it, expect } from "vitest";
import { addDaysIso, daysBetween, enumerateDays, isoDaysAgo, isoInTz, parseIsoDate, todayIso, weekStartOf } from "./dates";

describe("parseIsoDate / addDaysIso", () => {
  it("validates and shifts across month/year/leap boundaries", () => {
    expect(parseIsoDate("2026-06-11")).toEqual({ year: 2026, month: 6, day: 11 });
    expect(() => parseIsoDate("2026/06/11")).toThrow();
    expect(addDaysIso("2026-06-30", 1)).toBe("2026-07-01");
    expect(addDaysIso("2027-01-01", -1)).toBe("2026-12-31");
    expect(addDaysIso("2028-02-28", 1)).toBe("2028-02-29");
    expect(addDaysIso("2026-06-11", -30)).toBe("2026-05-12");
  });
});

describe("isoInTz / todayIso / isoDaysAgo (the UTC-midnight bug class)", () => {
  const instant = new Date("2026-06-11T23:30:00Z");

  it("formats per timezone, not per UTC", () => {
    expect(isoInTz(instant, "UTC")).toBe("2026-06-11");
    expect(isoInTz(instant, "Europe/London")).toBe("2026-06-12");
    expect(isoInTz(instant, "America/New_York")).toBe("2026-06-11");
  });

  it("todayIso / isoDaysAgo honour the injected now", () => {
    const now = new Date("2026-06-11T10:00:00Z");
    expect(todayIso("Europe/London", now)).toBe("2026-06-11");
    expect(isoDaysAgo(7, "Europe/London", now)).toBe("2026-06-04");
    expect(isoDaysAgo(0, "Europe/London", now)).toBe("2026-06-11");
  });
});

describe("enumerateDays / daysBetween / weekStartOf", () => {
  it("enumerates an inclusive range ascending and rejects reversed ranges", () => {
    expect(enumerateDays("2026-06-29", "2026-07-02")).toEqual(["2026-06-29", "2026-06-30", "2026-07-01", "2026-07-02"]);
    expect(enumerateDays("2026-06-29", "2026-06-29")).toEqual(["2026-06-29"]);
    expect(() => enumerateDays("2026-07-02", "2026-06-29")).toThrow(/before start_date/);
    expect(daysBetween("2026-06-01", "2026-06-08")).toBe(7);
  });

  it("anchors weeks on Monday", () => {
    expect(weekStartOf("2026-06-11")).toBe("2026-06-08"); // Thursday
    expect(weekStartOf("2026-06-08")).toBe("2026-06-08");
    expect(weekStartOf("2026-06-07")).toBe("2026-06-01"); // Sunday
  });
});

/**
 * Pure date helpers. MyFitnessPal keys everything by civil date
 * ("YYYY-MM-DD", the user's diary day), so the only real job here is
 * resolving "today"/"N days ago" in the user's timezone and enumerating the
 * days of a window. Kept free of I/O so it can be unit tested.
 */

const ISO_DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

/** Validate and split "YYYY-MM-DD". */
export function parseIsoDate(iso: string): { year: number; month: number; day: number } {
  if (!ISO_DATE_RE.test(iso)) throw new Error(`Invalid date "${iso}" — expected YYYY-MM-DD`);
  const [year, month, day] = iso.split("-").map((n) => parseInt(n, 10));
  if (month < 1 || month > 12 || day < 1 || day > 31) {
    throw new Error(`Invalid date "${iso}" — expected YYYY-MM-DD`);
  }
  return { year, month, day };
}

/** `isoDate` shifted by `delta` whole days. */
export function addDaysIso(isoDate: string, delta: number): string {
  const { year, month, day } = parseIsoDate(isoDate);
  const d = new Date(Date.UTC(year, month - 1, day));
  d.setUTCDate(d.getUTCDate() + delta);
  return d.toISOString().slice(0, 10);
}

/** "YYYY-MM-DD" for an instant, as seen in the given IANA timezone. */
export function isoInTz(date: Date, timeZone: string): string {
  // en-CA formats as YYYY-MM-DD; the timeZone option shifts the calendar day.
  return new Intl.DateTimeFormat("en-CA", {
    timeZone,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  }).format(date);
}

/** "YYYY-MM-DD" for today, in the given timezone. */
export function todayIso(timeZone: string, now: Date = new Date()): string {
  return isoInTz(now, timeZone);
}

/** "YYYY-MM-DD" for a date N days before today, in the given timezone. */
export function isoDaysAgo(days: number, timeZone: string, now: Date = new Date()): string {
  const d = new Date(now);
  d.setUTCDate(d.getUTCDate() - days);
  return isoInTz(d, timeZone);
}

/** Whole calendar days between two ISO dates (b - a). */
export function daysBetween(aIso: string, bIso: string): number {
  const a = parseIsoDate(aIso);
  const b = parseIsoDate(bIso);
  return Math.round((Date.UTC(b.year, b.month - 1, b.day) - Date.UTC(a.year, a.month - 1, a.day)) / 86_400_000);
}

/** Every date from `startIso` to `endIso` inclusive, ascending. */
export function enumerateDays(startIso: string, endIso: string): string[] {
  const n = daysBetween(startIso, endIso);
  if (n < 0) throw new Error(`end_date ${endIso} is before start_date ${startIso}`);
  const out: string[] = [];
  for (let i = 0; i <= n; i++) out.push(addDaysIso(startIso, i));
  return out;
}

/** Monday-anchored "YYYY-MM-DD" for an ISO date. */
export function weekStartOf(isoDate: string): string {
  const d = new Date(`${isoDate}T00:00:00Z`);
  const dow = (d.getUTCDay() + 6) % 7; // Monday = 0
  d.setUTCDate(d.getUTCDate() - dow);
  return d.toISOString().slice(0, 10);
}

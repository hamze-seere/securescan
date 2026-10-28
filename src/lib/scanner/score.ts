import type { Finding, Grade, Severity } from "./types";

export const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 30,
  high: 15,
  medium: 8,
  low: 3,
  info: 0,
};

/** A failed check costs its full weight; a warning costs half. */
export function computeScore(findings: Finding[]): number {
  const penalty = findings.reduce((sum, f) => {
    if (f.status === "fail") return sum + SEVERITY_WEIGHT[f.severity];
    if (f.status === "warn") return sum + SEVERITY_WEIGHT[f.severity] / 2;
    return sum;
  }, 0);
  return Math.max(0, Math.round(100 - penalty));
}

export function computeGrade(findings: Finding[], score: number): Grade {
  const failed = (s: Severity) => findings.some((f) => f.status === "fail" && f.severity === s);
  const passed = (id: string) => findings.some((f) => f.id === id && f.status === "pass");

  // Some problems are serious enough that nothing else matters.
  if (failed("critical")) return "F";

  if (score >= 95 && !failed("high") && !failed("medium") && passed("hsts") && passed("csp")) return "A+";
  if (score >= 85) return "A";
  if (score >= 70) return "B";
  if (score >= 55) return "C";
  if (score >= 40) return "D";
  return "F";
}

/** Counts of real problems (fail/warn) by severity. */
export function summarize(findings: Finding[]): Record<Severity, number> {
  const summary: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) {
    if (f.status === "fail" || f.status === "warn") summary[f.severity]++;
  }
  return summary;
}

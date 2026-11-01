import type { Category, Finding, Grade, Severity } from "./types";

export const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 30,
  high: 15,
  medium: 8,
  low: 3,
  info: 0,
};

/**
 * Most a single category can cost. A site that sets twenty cookies with the same
 * missing flag has one configuration problem, not twenty.
 */
export const CATEGORY_PENALTY_CAP: Partial<Record<Category, number>> = {
  cookies: 20,
};

/** Penalty of one finding: a failed check costs its full weight; a warning costs half. */
export function findingPenalty(f: Finding): number {
  if (f.status === "fail") return SEVERITY_WEIGHT[f.severity];
  if (f.status === "warn") return SEVERITY_WEIGHT[f.severity] / 2;
  return 0;
}

function penaltyByCategory(findings: Finding[]): Map<Category, number> {
  const totals = new Map<Category, number>();
  for (const f of findings) totals.set(f.category, (totals.get(f.category) ?? 0) + findingPenalty(f));
  for (const [category, total] of totals) {
    const cap = CATEGORY_PENALTY_CAP[category];
    if (cap !== undefined) totals.set(category, Math.min(total, cap));
  }
  return totals;
}

export function computeScore(findings: Finding[]): number {
  let penalty = 0;
  for (const p of penaltyByCategory(findings).values()) penalty += p;
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

export interface CategoryScore {
  category: Category;
  /** 0-100: share of this category's weighted checks that passed. */
  score: number;
  /** Points this category took off the overall score. */
  pointsLost: number;
  issues: number;
}

/**
 * Per-category subscores, so a grade can be traced to where the points went.
 * Derived from findings only, so it also works for reports stored before it existed.
 */
export function categoryScores(findings: Finding[]): CategoryScore[] {
  const lost = penaltyByCategory(findings);
  const out = new Map<Category, { possible: number; issues: number }>();
  for (const f of findings) {
    if (f.status === "info") continue;
    const entry = out.get(f.category) ?? { possible: 0, issues: 0 };
    entry.possible += SEVERITY_WEIGHT[f.severity];
    if (f.status === "fail" || f.status === "warn") entry.issues++;
    out.set(f.category, entry);
  }
  return [...out].map(([category, { possible, issues }]) => {
    const pointsLost = lost.get(category) ?? 0;
    return {
      category,
      score: possible > 0 ? Math.max(0, Math.round(100 * (1 - pointsLost / possible))) : 100,
      pointsLost: Math.round(pointsLost * 10) / 10,
      issues,
    };
  });
}

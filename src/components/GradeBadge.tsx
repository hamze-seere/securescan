import type { Grade } from "@/lib/scanner/types";

export const GRADE_COLOR: Record<Grade, string> = {
  "A+": "#5fd99a",
  A: "#5fd99a",
  B: "#b7dd5a",
  C: "#f5c451",
  D: "#ff8f4d",
  F: "#ff5d6c",
};

export function GradeBadge({ grade, size = "sm" }: { grade: Grade; size?: "sm" }) {
  const color = GRADE_COLOR[grade];
  return (
    <span
      className={`grid shrink-0 place-items-center rounded-md font-mono font-semibold ${size === "sm" ? "size-9 text-sm" : ""}`}
      style={{ color, backgroundColor: `${color}1a`, boxShadow: `inset 0 0 0 1px ${color}40` }}
      aria-label={`Grade ${grade}`}
    >
      {grade}
    </span>
  );
}

/** Large circular score dial used at the top of a report. */
export function GradeDial({ grade, score }: { grade: Grade; score: number }) {
  const color = GRADE_COLOR[grade];
  const r = 52;
  const c = 2 * Math.PI * r;
  return (
    <div className="relative size-36 shrink-0" role="img" aria-label={`Grade ${grade}, score ${score} out of 100`}>
      <svg viewBox="0 0 120 120" className="size-full -rotate-90">
        <circle cx="60" cy="60" r={r} fill="none" stroke="#161d22" strokeWidth="8" />
        <circle
          cx="60" cy="60" r={r} fill="none" stroke={color} strokeWidth="8" strokeLinecap="round"
          strokeDasharray={c} strokeDashoffset={c * (1 - score / 100)}
          style={{ transition: "stroke-dashoffset 1s cubic-bezier(.2,.8,.2,1)", filter: `drop-shadow(0 0 6px ${color}55)` }}
        />
      </svg>
      <div className="absolute inset-0 grid place-content-center text-center">
        <span className="font-mono text-5xl font-semibold leading-none tracking-tight" style={{ color }}>{grade}</span>
        <span className="mt-1 font-mono text-xs text-ink-400">{score}/100</span>
      </div>
    </div>
  );
}

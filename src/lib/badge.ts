import type { Grade } from "@/lib/scanner/types";

/** A shields.io-style SVG badge ("securescan | A+") for READMEs. No fonts or scripts are loaded. */

const GRADE_COLOR: Record<Grade, string> = {
  "A+": "#1f9d63", A: "#1f9d63", B: "#6c9a1e", C: "#c89400", D: "#e36a1e", F: "#d92d3f",
};

const escapeXml = (s: string) => s.replace(/[<>&"']/g, (c) => `&#${c.charCodeAt(0)};`);

/** Rough width of Verdana 11px text, which is what badge renderers assume. */
const textWidth = (s: string) => Math.round(s.length * 7 + 10);

export function badgeSvg(grade: Grade | null, label = "securescan"): string {
  const value = grade ?? "not found";
  const color = grade ? GRADE_COLOR[grade] : "#7d8b95";
  const lw = textWidth(label);
  const vw = textWidth(value);
  const w = lw + vw;
  const title = escapeXml(`${label}: ${value}`);
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="20" role="img" aria-label="${title}">` +
    `<title>${title}</title>` +
    `<clipPath id="r"><rect width="${w}" height="20" rx="3"/></clipPath>` +
    `<g clip-path="url(#r)"><rect width="${lw}" height="20" fill="#24292f"/><rect x="${lw}" width="${vw}" height="20" fill="${color}"/></g>` +
    `<g fill="#fff" text-anchor="middle" font-family="Verdana,DejaVu Sans,sans-serif" font-size="11">` +
    `<text x="${lw / 2}" y="14">${escapeXml(label)}</text>` +
    `<text x="${lw + vw / 2}" y="14" font-weight="bold">${escapeXml(value)}</text></g></svg>`;
}

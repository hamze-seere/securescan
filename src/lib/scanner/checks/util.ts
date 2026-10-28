export type Headers = Record<string, string | string[] | undefined>;

/** Returns a header value (joined if it was sent multiple times). */
export function getHeader(headers: Headers, name: string): string | undefined {
  const value = headers[name.toLowerCase()];
  if (value === undefined) return undefined;
  return Array.isArray(value) ? value.join(", ") : value;
}

export function getHeaderList(headers: Headers, name: string): string[] {
  const value = headers[name.toLowerCase()];
  if (value === undefined) return [];
  return Array.isArray(value) ? value : [value];
}

export function truncate(text: string, max = 200): string {
  return text.length > max ? `${text.slice(0, max)}…` : text;
}

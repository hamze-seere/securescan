export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Status = "pass" | "fail" | "warn" | "info";

export type Category =
  | "transport"
  | "headers"
  | "cookies"
  | "disclosure"
  | "exposure"
  | "content"
  | "cors"
  | "email"
  | "dns";

export interface Finding {
  id: string;
  category: Category;
  title: string;
  status: Status;
  /** Severity of the problem. Only counts towards the score when status is "fail" or "warn". */
  severity: Severity;
  description: string;
  evidence?: string;
  recommendation?: string;
}

export interface TlsInfo {
  protocol: string | null;
  cipher: string | null;
  authorized: boolean;
  authorizationError: string | null;
  subject: string | null;
  issuer: string | null;
  validFrom: string | null;
  validTo: string | null;
  daysRemaining: number | null;
  altNames: string[];
}

export interface HttpResponseData {
  url: string;
  status: number;
  /** Lower-cased header names. Multi-value headers (set-cookie) are arrays. */
  headers: Record<string, string | string[]>;
  body: string;
  remoteAddress: string | null;
  tls: TlsInfo | null;
}

export interface FetchResult {
  final: HttpResponseData;
  /** Every URL visited, in order, including redirects. */
  chain: { url: string; status: number }[];
}

export type Grade = "A+" | "A" | "B" | "C" | "D" | "F";

export interface ScanReport {
  id: string;
  target: string;
  finalUrl: string;
  ip: string | null;
  scannedAt: string;
  durationMs: number;
  grade: Grade;
  score: number;
  summary: Record<Severity, number>;
  findings: Finding[];
  tls: TlsInfo | null;
  redirectChain: { url: string; status: number }[];
  responseHeaders: Record<string, string | string[]>;
  /** Set by the API: whether this report can be turned into a share link. */
  shareAvailable?: boolean;
}

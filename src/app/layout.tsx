import type { Metadata, Viewport } from "next";
import { IBM_Plex_Mono, IBM_Plex_Sans } from "next/font/google";
import { headers } from "next/headers";
import "./globals.css";

const plexSans = IBM_Plex_Sans({ subsets: ["latin"], weight: ["400", "500", "600", "700"], variable: "--font-plex-sans" });
const plexMono = IBM_Plex_Mono({ subsets: ["latin"], weight: ["400", "500", "600"], variable: "--font-plex-mono" });

export const metadata: Metadata = {
  title: "SecureScan - Website security posture scanner",
  description:
    "Grade any website's security in seconds: TLS, security headers, cookies, exposed files, CORS and mixed content, with clear fixes.",
};

export const viewport: Viewport = { themeColor: "#07090a" };

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  // Reading headers makes every page render per-request, which the nonce-based CSP in proxy.ts requires.
  await headers();
  return (
    <html lang="en" className={`${plexSans.variable} ${plexMono.variable}`}>
      <body className="min-h-dvh">{children}</body>
    </html>
  );
}

#!/usr/bin/env node
// SecureScan CLI: `securescan <url> [--min-grade B] [--api URL] [--sarif file] [--no-share]`.
// A thin wrapper around the GitHub Action script, so CI and the terminal behave the same.
import { parseArgs } from "node:util";
import { isEntryPoint, main } from "../action/check.mjs";

export const DEFAULT_API = "https://securescan-hamze.vercel.app";

const USAGE = `Usage: securescan <url> [options]

Options:
  --min-grade <grade>  Exit with code 1 below this grade (A+, A, B, C, D, F). Default: B
  --api <url>          SecureScan deployment to use. Default: ${DEFAULT_API}
  --sarif <file>       Also write a SARIF 2.1.0 file
  --no-share           Don't create a shareable report link
  -h, --help           Show this help`;

/** Turns CLI arguments into the INPUT_* variables the Action reads. Returns null for --help. */
export function cliEnv(argv, env = {}) {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      "min-grade": { type: "string" },
      api: { type: "string" },
      sarif: { type: "string" },
      "no-share": { type: "boolean" },
      help: { type: "boolean", short: "h" },
    },
  });
  if (values.help) return null;
  if (positionals.length !== 1) throw new Error(`Expected one URL.\n\n${USAGE}`);
  return {
    ...env,
    INPUT_URL: positionals[0],
    INPUT_API_URL: values.api ?? env.SECURESCAN_API ?? DEFAULT_API,
    INPUT_MIN_GRADE: values["min-grade"] ?? "B",
    INPUT_SHARE: values["no-share"] ? "false" : "true",
    ...(values.sarif ? { INPUT_SARIF: values.sarif } : {}),
    // Not inside GitHub Actions: no step summary or outputs file.
    GITHUB_OUTPUT: "",
    GITHUB_STEP_SUMMARY: "",
  };
}

if (isEntryPoint(import.meta.url, process.argv[1])) {
  try {
    const env = cliEnv(process.argv.slice(2), process.env);
    if (!env) {
      console.log(USAGE);
      process.exit(0);
    }
    process.exit(await main(env));
  } catch (err) {
    console.error(err.message);
    process.exit(2);
  }
}

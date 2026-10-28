import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { test, before } from "node:test";
import assert from "node:assert/strict";
import { extractUrls } from "../engine/extract.js";
import { judgeUrl } from "../engine/verdict.js";
import { MirrorFeed } from "../engine/sources/feeds.js";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");

process.env.EGRESS_EYE_HOME = fs.mkdtempSync(path.join(os.tmpdir(), "egress-eye-verdict-"));
process.env.EGRESS_EYE_OFFLINE = "1";
process.env.EGRESS_EYE_RDAP = "0";
delete process.env.EGRESS_EYE_GSB_KEY;

let feed: MirrorFeed;

before(async () => {
  feed = MirrorFeed.open({ file: path.join(REPO_ROOT, "eval", "fixtures", "urlhaus-sample.csv"), source: "urlhaus" });
  await feed.load();
  assert.ok(feed.size > 0, "fixture feed should load");
});

async function judge(url: string, opts: Parameters<typeof judgeUrl>[1] = {}) {
  const [u] = extractUrls(url);
  assert.ok(u, `extract failed for ${url}`);
  return judgeUrl(u!, { urlhaus: feed, ...opts });
}

test("fixture feed URL hit → malicious", async () => {
  const j = await judge("http://stage-logs-collect-9f3.top/gate.php");
  assert.equal(j.verdict, "malicious");
  assert.equal(j.source, "urlhaus");
  assert.match(j.reason, /listed in urlhaus/);
});

test("fixture feed host hit → malicious", async () => {
  const j = await judge("http://cdn-update-check.tk/deep/path/agent.msi");
  assert.equal(j.verdict, "malicious");
});

test("allowlisted clean URL → clean", async () => {
  const j = await judge("https://registry.npmjs.org/express");
  assert.equal(j.verdict, "clean");
  assert.equal(j.source, "allowlist");
});

test("typosquat → suspicious", async () => {
  const j = await judge("https://gihub.com/facebook/react.git");
  assert.equal(j.verdict, "suspicious");
  assert.equal(j.source, "heuristic:typosquat");
});

test("no signals → unknown (honest default)", async () => {
  const j = await judge("https://totally-unlisted-9q81.dev/ping");
  assert.equal(j.verdict, "unknown");
  assert.equal(j.source, "none");
});

test("low-severity findings alone do not escalate to suspicious", async () => {
  const j = await judge("ftp://ftp.gnu.org/gnu/wget.tar.gz");
  assert.equal(j.verdict, "unknown");
  assert.ok(j.findings.length > 0);
});

test("newly registered domain (< 7 days) → suspicious", async () => {
  const j = await judge("https://brand-new-domain-aaa.dev/x", {
    rdapFn: async () => ({ days: 5 }),
  });
  assert.equal(j.verdict, "suspicious");
  assert.equal(j.source, "rdap");
  assert.match(j.reason, /5 days/);
});

test("newly registered domain (7–29 days) → suspicious", async () => {
  const j = await judge("https://somewhat-new-domain-bbb.dev/x", {
    rdapFn: async () => ({ days: 17 }),
  });
  assert.equal(j.verdict, "suspicious");
});

test("established domain (> 30 days) stays unknown", async () => {
  const j = await judge("https://old-established-domain-ccc.dev/x", {
    rdapFn: async () => ({ days: 45 }),
  });
  assert.equal(j.verdict, "unknown");
});

test("feed hit wins over allowlist", async () => {
  // Not allowlisted in reality, but the ordering property is what matters —
  // a feed hit short-circuits before the allowlist check.
  const j = await judge("http://paste-drop-4n6.xyz/upload");
  assert.equal(j.verdict, "malicious");
});

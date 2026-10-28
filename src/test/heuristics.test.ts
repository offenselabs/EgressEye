import { test } from "node:test";
import assert from "node:assert/strict";
import { extractUrls } from "../engine/extract.js";
import { heuristicFindings, worstSeverity, damerauLevenshtein } from "../engine/heuristics.js";

function findingsFor(url: string) {
  const [u] = extractUrls(url);
  assert.ok(u, `failed to extract ${url}`);
  return heuristicFindings(u!);
}

test("damerau-levenshtein basics", () => {
  assert.equal(damerauLevenshtein("gihub", "github"), 1);
  assert.equal(damerauLevenshtein("ab", "ba"), 1);
  assert.equal(damerauLevenshtein("npmjz.com", "npmjs.com"), 1);
  assert.equal(damerauLevenshtein("npmjs.com", "npmjs.com"), 0);
});

test("typosquat: distance-1 from an allowlisted domain is high severity", () => {
  const f = findingsFor("https://gihub.com/facebook/react.git");
  const ts = f.find((x) => x.code === "typosquat");
  assert.ok(ts);
  assert.equal(ts!.severity, "high");
  assert.equal(worstSeverity(f), "high");
});

test("typosquat: registry.npmjs.org is allowlisted, no finding", () => {
  const f = findingsFor("https://registry.npmjs.org/express");
  assert.deepEqual(f, []);
});

test("ip literal produces a medium finding", () => {
  const f = findingsFor("http://192.168.1.50:9000/drop.sh");
  assert.ok(f.some((x) => x.code === "ip-literal" && x.severity === "medium"));
  assert.ok(f.some((x) => x.code === "non-standard-port" && x.severity === "low"));
  assert.equal(worstSeverity(f), "medium");
});

test("punycode produces a medium finding", () => {
  const f = findingsFor("https://xn--pple-43d.com/login");
  assert.ok(f.some((x) => x.code === "punycode"));
});

test("credentials in URL produce a medium finding", () => {
  const f = findingsFor("https://admin:s3cretpw@example.net/exfil");
  assert.ok(f.some((x) => x.code === "credentials-in-url"));
});

test("risky .zip TLD produces a medium finding", () => {
  const f = findingsFor("https://de.zip/archive");
  assert.ok(f.some((x) => x.code === "risky-tld"));
});

test("clean allowlisted URL produces no findings", () => {
  const f = findingsFor("https://cdn.jsdelivr.net/npm/express@4/package.json");
  assert.deepEqual(f, []);
});

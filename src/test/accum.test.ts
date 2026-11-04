import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { AccumStore, accumEnabled, staleMs, ACCUM_MAX_ENTRIES, ACCUM_TTL_MS } from "../engine/sources/accum.js";
import { MirrorFeed } from "../engine/sources/feeds.js";
import { extractUrls } from "../engine/extract.js";
import { judgeUrl } from "../engine/verdict.js";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");

process.env.EGRESS_EYE_HOME = fs.mkdtempSync(path.join(os.tmpdir(), "egress-eye-accum-"));
process.env.EGRESS_EYE_OFFLINE = "1";
process.env.EGRESS_EYE_RDAP = "0";
delete process.env.EGRESS_EYE_GSB_KEY;
delete process.env.EGRESS_EYE_ACCUMULATE;
delete process.env.EGRESS_EYE_STALE_DAYS;

const FIXTURE_FEED = path.join(REPO_ROOT, "eval", "fixtures", "urlhaus-sample.csv");

after(() => {
  fs.rmSync(process.env.EGRESS_EYE_HOME!, { recursive: true, force: true });
});

const DAY = 86400000;

test("merge dedups and refreshes lastSeen", () => {
  const store = new AccumStore();
  const now = 1_700_000_000_000;
  const first = store.merge(["https://evil.example/a", "evil.example"], "openphish", now);
  assert.deepEqual(first, { added: 2, refreshed: 0 });
  const second = store.merge(["https://evil.example/a"], "openphish", now + DAY);
  assert.deepEqual(second, { added: 0, refreshed: 1 });
  assert.equal(store.size, 2);
  const entry = store.get("https://evil.example/a")!;
  assert.equal(entry.source, "openphish");
  assert.equal(entry.lastSeen, now + DAY);
});

test("prune drops entries past the TTL and the oldest beyond the cap", () => {
  const store = new AccumStore();
  const now = 1_700_000_000_000;
  store.merge(["old.example"], "openphish", now - 200 * DAY);
  store.merge(["fresh.example"], "openphish", now);
  assert.equal(store.prune(now), 1, "entry past the 180-day TTL is pruned");
  assert.equal(store.get("old.example"), null);
  assert.notEqual(store.get("fresh.example"), null);

  const small = new AccumStore();
  const max = 10;
  for (let i = 0; i < 15; i++) {
    small.merge([`h${i}.example`], "openphish", now + i * DAY);
  }
  small.prune(now, max);
  assert.equal(small.size, max, "cap evicts the oldest entries");
  assert.equal(small.get("h0.example"), null, "oldest evicted first");
  assert.notEqual(small.get("h14.example"), null, "newest kept");
});

test("save/load roundtrip preserves keys, sources, and timestamps", () => {
  const store = new AccumStore();
  const now = 1_700_000_000_000;
  store.merge(["https://evil.example/x", "evil.example"], "urlhaus", now);
  store.save();
  const reloaded = new AccumStore();
  assert.equal(reloaded.load(), true);
  assert.equal(reloaded.size, 2);
  const entry = reloaded.get("https://evil.example/x")!;
  assert.equal(entry.source, "urlhaus");
  assert.equal(entry.lastSeen, now);
});

test("config parsing: stale days and disable flag", () => {
  const saved = { acc: process.env.EGRESS_EYE_ACCUMULATE, days: process.env.EGRESS_EYE_STALE_DAYS };
  try {
    process.env.EGRESS_EYE_STALE_DAYS = "7";
    assert.equal(staleMs(), 7 * DAY);
    process.env.EGRESS_EYE_STALE_DAYS = "bogus";
    assert.equal(staleMs(), 30 * DAY, "invalid value falls back to 30 days");
    process.env.EGRESS_EYE_ACCUMULATE = "0";
    assert.equal(accumEnabled(), false);
    process.env.EGRESS_EYE_ACCUMULATE = "1";
    assert.equal(accumEnabled(), true);
  } finally {
    if (saved.acc === undefined) delete process.env.EGRESS_EYE_ACCUMULATE;
    else process.env.EGRESS_EYE_ACCUMULATE = saved.acc;
    if (saved.days === undefined) delete process.env.EGRESS_EYE_STALE_DAYS;
    else process.env.EGRESS_EYE_STALE_DAYS = saved.days;
  }
});

test("accumulated fresh hit → malicious; aged hit → suspicious with honest reason", async () => {
  const savedHome = process.env.EGRESS_EYE_HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "egress-eye-accum-verdict-"));
  process.env.EGRESS_EYE_HOME = home;
  try {
    // Seed the store directly: one fresh entry, one 60-day-old entry.
    const store = new AccumStore();
    const now = Date.now();
    store.merge(["https://fresh-accum.example/one"], "openphish", now);
    store.merge(["https://old-accum.example/two"], "openphish", now - 60 * DAY);
    store.save();

    const feed = MirrorFeed.open({ file: FIXTURE_FEED, source: "urlhaus" });
    await feed.load();

    const [fresh] = extractUrls("visit https://fresh-accum.example/one");
    const freshJudge = await judgeUrl(fresh!, { urlhaus: feed, rdap: false });
    assert.equal(freshJudge.verdict, "malicious", "fresh accumulated entry behaves like a live-mirror hit");
    assert.equal(freshJudge.source, "openphish");
    assert.match(freshJudge.reason, /listed in openphish/);

    const [old] = extractUrls("visit https://old-accum.example/two");
    const oldJudge = await judgeUrl(old!, { urlhaus: feed, rdap: false });
    assert.equal(oldJudge.verdict, "suspicious", "stale entry is downgraded from malicious");
    assert.equal(oldJudge.source, "openphish");
    assert.match(oldJudge.reason, /listed in openphish 60 days ago \(stale/);

    const [unknown] = extractUrls("visit https://never-seen-anywhere.example/three");
    const unknownJudge = await judgeUrl(unknown!, { urlhaus: feed, rdap: false });
    assert.equal(unknownJudge.verdict, "unknown", "absent from both live mirror and accumulation");
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
    process.env.EGRESS_EYE_HOME = savedHome!;
  }
});

test("live-mirror hits take precedence over accumulated history", async () => {
  const savedHome = process.env.EGRESS_EYE_HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "egress-eye-accum-precedence-"));
  process.env.EGRESS_EYE_HOME = home;
  try {
    // The fixture's host, aged far past stale, must not matter: the live
    // mirror still lists it, and a live hit is always fresh.
    const store = new AccumStore();
    store.merge(["http://stage-logs-collect-9f3.top/gate.php"], "openphish", Date.now() - 100 * DAY);
    store.save();

    const feed = MirrorFeed.open({ file: FIXTURE_FEED, source: "urlhaus" });
    await feed.load();
    const [u] = extractUrls("visit http://stage-logs-collect-9f3.top/gate.php");
    const j = await judgeUrl(u!, { urlhaus: feed, rdap: false });
    assert.equal(j.verdict, "malicious");
    assert.equal(j.source, "urlhaus", "live mirror wins over accumulated history");
    assert.doesNotMatch(j.reason, /stale/);
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
    process.env.EGRESS_EYE_HOME = savedHome!;
  }
});

test("EGRESS_EYE_ACCUMULATE=0: store ignored, no file consulted", async () => {
  const savedHome = process.env.EGRESS_EYE_HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "egress-eye-accum-off-"));
  process.env.EGRESS_EYE_HOME = home;
  process.env.EGRESS_EYE_ACCUMULATE = "0";
  try {
    const store = new AccumStore();
    store.merge(["https://fresh-accum-off.example/one"], "openphish", Date.now());
    store.save();
    const feed = MirrorFeed.open({ file: FIXTURE_FEED, source: "urlhaus" });
    await feed.load();
    assert.equal(feed.accumSize, 0, "accumulation disabled — store not loaded");
    const [u] = extractUrls("visit https://fresh-accum-off.example/one");
    const j = await judgeUrl(u!, { urlhaus: feed, rdap: false });
    assert.equal(j.verdict, "unknown");
  } finally {
    delete process.env.EGRESS_EYE_ACCUMULATE;
    fs.rmSync(home, { recursive: true, force: true });
    process.env.EGRESS_EYE_HOME = savedHome!;
  }
});

test("pinned feed files stay accumulation-free", async () => {
  const savedHome = process.env.EGRESS_EYE_HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "egress-eye-accum-pin-"));
  process.env.EGRESS_EYE_HOME = home;
  const saved = { file: process.env.EGRESS_EYE_FEED_FILE, source: process.env.EGRESS_EYE_FEED_SOURCE };
  try {
    const store = new AccumStore();
    store.merge(["https://pin-contaminate.example/one"], "openphish", Date.now());
    store.save();
    const file = path.join(home, "fixture.csv");
    fs.copyFileSync(FIXTURE_FEED, file);
    // Pin via env, exactly how a user pins: the file is then user-owned.
    process.env.EGRESS_EYE_FEED_FILE = file;
    process.env.EGRESS_EYE_FEED_SOURCE = "urlhaus";
    const feed = MirrorFeed.open();
    await feed.load();
    assert.equal(feed.pinEnv, "EGRESS_EYE_FEED_FILE");
    assert.equal(feed.accumSize, 0, "a pinned feed must not consult the accumulated store");
    const stats = feed.accumulate();
    assert.equal(stats.saved, false, "update-feeds never accumulates a pinned feed");
  } finally {
    if (saved.file === undefined) delete process.env.EGRESS_EYE_FEED_FILE;
    else process.env.EGRESS_EYE_FEED_FILE = saved.file;
    if (saved.source === undefined) delete process.env.EGRESS_EYE_FEED_SOURCE;
    else process.env.EGRESS_EYE_FEED_SOURCE = saved.source;
    fs.rmSync(home, { recursive: true, force: true });
    process.env.EGRESS_EYE_HOME = savedHome!;
  }
});

test("feed.accumulate() folds the loaded mirror into the store", async () => {
  const savedHome = process.env.EGRESS_EYE_HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "egress-eye-accum-merge-"));
  process.env.EGRESS_EYE_HOME = home;
  try {
    const feed = MirrorFeed.open({ file: FIXTURE_FEED, source: "urlhaus" });
    await feed.load();
    assert.ok(feed.size > 0, "fixture feed loads");
    const stats = feed.accumulate();
    assert.equal(stats.saved, true);
    assert.ok(stats.added > 0, "fixture entries land in the store");
    const again = feed.accumulate();
    assert.equal(again.added, 0, "second pass is pure refresh");
    assert.ok(again.refreshed > 0);
    assert.ok(feed.accumSize > feed.size, "hosts are accumulated on top of the exact URLs");

    // A fresh open of the same home sees the accumulated entries.
    const reopened = MirrorFeed.open({ file: FIXTURE_FEED, source: "urlhaus" });
    await reopened.load();
    assert.equal(reopened.accumSize, feed.accumSize, "store persists across opens");
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
    process.env.EGRESS_EYE_HOME = savedHome!;
  }
});

test("constants: TTL and cap are the documented values", () => {
  assert.equal(ACCUM_TTL_MS, 180 * DAY);
  assert.equal(ACCUM_MAX_ENTRIES, 200_000);
});

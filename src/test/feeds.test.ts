import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { MirrorFeed } from "../engine/sources/feeds.js";
import { AccumStore, accumFile } from "../engine/sources/accum.js";
import { HookBudget } from "../lib/budget.js";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");

// Isolated home: several tests here open unpinned feeds, which consults the
// accumulated store — it must never be the user's real one.
process.env.EGRESS_EYE_HOME = fs.mkdtempSync(path.join(os.tmpdir(), "egress-eye-feeds-home-"));
process.env.EGRESS_EYE_OFFLINE = "1";
delete process.env.EGRESS_EYE_GSB_KEY;

const tmpDirs: string[] = [];
function tmpFile(name: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "egress-eye-feeds-"));
  tmpDirs.push(dir);
  return path.join(dir, name);
}
after(() => {
  for (const dir of tmpDirs) fs.rmSync(dir, { recursive: true, force: true });
  fs.rmSync(process.env.EGRESS_EYE_HOME!, { recursive: true, force: true });
});

/** Set env vars for the duration of fn, restoring them afterwards. */
async function withEnv<T>(env: Record<string, string | undefined>, fn: () => Promise<T> | T): Promise<T> {
  const saved = new Map<string, string | undefined>();
  for (const [k, v] of Object.entries(env)) {
    saved.set(k, process.env[k]);
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  try {
    return await fn();
  } finally {
    for (const [k, v] of saved) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
}

test("force load never overwrites a pinned feed file", async () => {
  await withEnv({ EGRESS_EYE_FEED_FILE: tmpFile("pinned.txt"), EGRESS_EYE_FEED_SOURCE: undefined }, async () => {
    const file = process.env.EGRESS_EYE_FEED_FILE!;
    fs.writeFileSync(file, "https://listed.example/one\n", "utf8");
    const feed = MirrorFeed.open();
    assert.equal(feed.pinEnv, "EGRESS_EYE_FEED_FILE");
    const ok = await feed.load(true);
    assert.equal(ok, true);
    assert.equal(fs.readFileSync(file, "utf8"), "https://listed.example/one\n", "pinned file must be untouched");
    assert.match(feed.note, /pinned via EGRESS_EYE_FEED_FILE/);
    assert.equal(feed.size, 1, "pinned file still loads and is checked");
  });
});

test("a pinned feed file that does not exist is never downloaded into", async () => {
  await withEnv({ EGRESS_EYE_FEED_FILE: tmpFile("absent.txt"), EGRESS_EYE_FEED_SOURCE: undefined }, async () => {
    const file = process.env.EGRESS_EYE_FEED_FILE!;
    const feed = MirrorFeed.open();
    const ok = await feed.load(true);
    assert.equal(ok, false);
    assert.ok(!fs.existsSync(file), "no file may be created at the pinned path");
    assert.match(feed.note, /pinned via EGRESS_EYE_FEED_FILE/);
  });
});

test("a stale pinned feed file is not re-downloaded", async () => {
  await withEnv({ EGRESS_EYE_FEED_FILE: tmpFile("stale.txt"), EGRESS_EYE_FEED_SOURCE: undefined }, async () => {
    const file = process.env.EGRESS_EYE_FEED_FILE!;
    fs.writeFileSync(file, "https://listed.example/two\n", "utf8");
    fs.utimesSync(file, new Date(), new Date(Date.now() - 3 * 24 * 60 * 60 * 1000));
    const feed = MirrorFeed.open();
    await feed.load();
    assert.equal(fs.readFileSync(file, "utf8"), "https://listed.example/two\n");
    assert.equal(feed.note, "", "no download attempted for a pinned file");
    assert.equal(feed.size, 1);
  });
});

test("unpinned missing file offline: honest note, no file created", async () => {
  await withEnv({ EGRESS_EYE_FEED_FILE: undefined, EGRESS_EYE_URLHAUS_FILE: undefined, EGRESS_EYE_FEED_SOURCE: undefined }, async () => {
    const file = tmpFile("none.txt");
    const feed = MirrorFeed.open({ file, source: "openphish" });
    assert.equal(feed.pinEnv, null);
    const ok = await feed.load();
    assert.equal(ok, false);
    assert.match(feed.note, /no local feed yet/);
    assert.ok(!fs.existsSync(file));
  });
});

test("expired wall-clock budget skips the feed refresh with an honest note", async () => {
  await withEnv({ EGRESS_EYE_FEED_FILE: undefined, EGRESS_EYE_URLHAUS_FILE: undefined, EGRESS_EYE_HOOK_BUDGET_MS: "1" }, async () => {
    const budget = HookBudget.fromEnv(); // clock starts now
    await new Promise((r) => setTimeout(r, 15));
    const file = tmpFile("budget.txt");
    const feed = MirrorFeed.open({ file, source: "openphish" });
    const ok = await feed.load(true, budget);
    assert.equal(ok, false);
    assert.match(feed.note, /wall-clock budget exhausted/);
    assert.ok(!fs.existsSync(file));
  });
});

test("offline stale refresh never touches the accumulated store", async () => {
  await withEnv({ EGRESS_EYE_FEED_FILE: undefined, EGRESS_EYE_URLHAUS_FILE: undefined, EGRESS_EYE_FEED_SOURCE: undefined }, async () => {
    const file = tmpFile("stale-offline.txt");
    fs.writeFileSync(file, "https://listed.example/stale\n", "utf8");
    fs.utimesSync(file, new Date(), new Date(Date.now() - 3 * 24 * 60 * 60 * 1000)); // stale
    // Pre-seed a store with one sentinel entry (fixed lastSeen).
    const store = new AccumStore();
    const fixedTs = 1_700_000_000_000;
    store.merge(["https://sentinel.example/one"], "openphish", fixedTs);
    store.save();
    const before = fs.readFileSync(accumFile(), "utf8");

    const feed = MirrorFeed.open({ file, source: "openphish" });
    await feed.load(); // offline: staleness download is skipped

    assert.equal(feed.size, 1, "stale mirror still loads and is checked");
    assert.equal(fs.readFileSync(accumFile(), "utf8"), before, "no download → no accumulation; store byte-identical");
    const reloaded = new AccumStore();
    reloaded.load();
    assert.equal(reloaded.get("https://sentinel.example/one")?.lastSeen, fixedTs, "sentinel lastSeen untouched");
  });
});

test("CLI update-feeds refuses to run while a feed file is pinned", () => {
  const file = tmpFile("cli-pinned.txt");
  fs.writeFileSync(file, "sentinel\n", "utf8");
  const res = spawnSync(process.execPath, [path.join(REPO_ROOT, "dist", "cli.js"), "update-feeds"], {
    env: { ...process.env, EGRESS_EYE_FEED_FILE: file },
    encoding: "utf8",
  });
  assert.equal(res.status, 1, `expected exit 1, stderr: ${res.stderr}`);
  assert.match(res.stderr, /never writes pinned feed files/);
  assert.equal(fs.readFileSync(file, "utf8"), "sentinel\n");
});

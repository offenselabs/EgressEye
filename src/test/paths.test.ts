import { test } from "node:test";
import assert from "node:assert/strict";
import { sanitizeSessionId } from "../lib/paths.js";

test("valid session ids pass through", () => {
  assert.equal(sanitizeSessionId("abc-123_X.4"), "abc-123_X.4");
  assert.equal(sanitizeSessionId("  spaced-out-id  "), "spaced-out-id");
});

test("path traversal and hostile shapes are refused", () => {
  assert.equal(sanitizeSessionId("../../etc/passwd"), null);
  assert.equal(sanitizeSessionId("a/b"), null);
  assert.equal(sanitizeSessionId("a b"), null);
  assert.equal(sanitizeSessionId(""), null);
  assert.equal(sanitizeSessionId(undefined), null);
  assert.equal(sanitizeSessionId("x".repeat(81)), null);
});

test("Windows reserved device names are refused (CON.jsonl is invalid)", () => {
  for (const name of ["con", "CON", "nul", "aux", "prn", "com1", "lpt9", "con.json"]) {
    assert.equal(sanitizeSessionId(name), null, `${name} must be refused`);
  }
  assert.equal(sanitizeSessionId("constant"), "constant", "non-reserved names containing reserved prefixes pass");
});

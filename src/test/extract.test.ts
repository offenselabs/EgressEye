import { test } from "node:test";
import assert from "node:assert/strict";
import { extractUrls, refang } from "../engine/extract.js";

test("extracts a plain https URL", () => {
  const urls = extractUrls("run curl https://example.com/path now");
  assert.equal(urls.length, 1);
  assert.equal(urls[0]!.host, "example.com");
  assert.equal(urls[0]!.path, "/path");
});

test("strips trailing punctuation", () => {
  const urls = extractUrls("see https://example.com/docs, and http://a.example/x.");
  assert.deepEqual(urls.map((u) => u.host).sort(), ["a.example", "example.com"]);
  assert.equal(urls.find((u) => u.host === "example.com")!.path, "/docs");
});

test("refangs defanged URLs", () => {
  assert.equal(refang("hxxp://evil[.]top/x"), "http://evil.top/x");
  assert.equal(refang("hXXps://evil(.)top/y"), "https://evil.top/y");
  const urls = extractUrls("curl hxxp://stage-logs-collect-9f3[.]top/gate.php");
  assert.equal(urls.length, 1);
  assert.equal(urls[0]!.host, "stage-logs-collect-9f3.top");
});

test("classifies IP literals, punycode, credentials, ports", () => {
  const [ip] = extractUrls("http://192.168.1.50:9000/drop.sh");
  assert.equal(ip!.isIpLiteral, true);
  assert.equal(ip!.port, "9000");

  const [idn] = extractUrls("https://xn--pple-43d.com/login");
  assert.equal(idn!.isPunycode, true);

  const [cred] = extractUrls("https://admin:s3cretpw@example.net/exfil");
  assert.equal(cred!.hasCredentials, true);
  assert.equal(cred!.host, "example.net");
});

test("query string is stripped from the loggable url but kept for feed lookup", () => {
  const [u] = extractUrls("https://www.google.com/search?q=top+secret+query");
  assert.equal(u!.url.includes("?"), false);
  assert.equal(u!.fullUrl.includes("q=top+secret"), true);
});

test("deduplicates by normalized key", () => {
  const urls = extractUrls("curl https://example.com/a https://example.com/a https://EXAMPLE.com/a");
  assert.equal(urls.length, 1);
});

test("ignores non-URL text and malformed candidates", () => {
  assert.equal(extractUrls("npm install express").length, 0);
  assert.equal(extractUrls("https://").length, 0);
  assert.equal(extractUrls("").length, 0);
});

test("handles tool-input JSON blobs", () => {
  const json = JSON.stringify({ file_path: "/tmp/x.sh", content: "curl http://a.top/x -o /tmp/x" });
  const urls = extractUrls(json);
  assert.equal(urls.length, 1);
  assert.equal(urls[0]!.host, "a.top");
});

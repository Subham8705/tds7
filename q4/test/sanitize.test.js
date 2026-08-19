import test from "node:test";
import assert from "node:assert";
import worker from "../src/index.js";

function makeRequest(body) {
  return new Request("http://localhost/sanitize-output", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

test("Valid HTML", async () => {
  const res = await worker.fetch(makeRequest({ channel: "html", output: "<b>Hello</b>" }));
  const json = await res.json();
  assert.deepStrictEqual(json, { safe: true, reason: "SAFE" });
});

test("Invalid Schema - length", async () => {
  const res = await worker.fetch(makeRequest({ channel: "html", output: "a".repeat(20001) }));
  const json = await res.json();
  assert.deepStrictEqual(json, { safe: false, reason: "INVALID_SCHEMA" });
});

test("SCRIPT_TAG", async () => {
  const res = await worker.fetch(makeRequest({ channel: "html", output: "<script>alert(1)</script>" }));
  const json = await res.json();
  assert.deepStrictEqual(json, { safe: false, reason: "SCRIPT_TAG" });
});

test("EVENT_HANDLER", async () => {
  const res = await worker.fetch(makeRequest({ channel: "html", output: "<img src='x' onerror='alert(1)'>" }));
  const json = await res.json();
  assert.deepStrictEqual(json, { safe: false, reason: "EVENT_HANDLER" });
});

test("DANGEROUS_SCHEME - JS url", async () => {
  const res = await worker.fetch(makeRequest({ channel: "html", output: "<a href='javascript:alert(1)'>click</a>" }));
  const json = await res.json();
  assert.deepStrictEqual(json, { safe: false, reason: "DANGEROUS_SCHEME" });
});

test("EXTERNAL_EXFIL - html href", async () => {
  const res = await worker.fetch(makeRequest({ channel: "html", output: "<a href='https://evil.example/data'>click</a>" }));
  const json = await res.json();
  assert.deepStrictEqual(json, { safe: false, reason: "EXTERNAL_EXFIL" });
});

test("EXTERNAL_EXFIL - ok host", async () => {
  const res = await worker.fetch(makeRequest({ channel: "html", output: "<a href='https://cdn-784jyvn.example/data'>click</a>" }));
  const json = await res.json();
  assert.deepStrictEqual(json, { safe: true, reason: "SAFE" });
});

test("SQL_METACHAR - quote", async () => {
  const res = await worker.fetch(makeRequest({ channel: "sql", output: "O'Reilly" }));
  const json = await res.json();
  assert.deepStrictEqual(json, { safe: false, reason: "SQL_METACHAR" });
});

test("SQL_METACHAR - or 1=1", async () => {
  const res = await worker.fetch(makeRequest({ channel: "sql", output: "name or 1=1" }));
  const json = await res.json();
  assert.deepStrictEqual(json, { safe: false, reason: "SQL_METACHAR" });
});

test("SHELL_METACHAR", async () => {
  const res = await worker.fetch(makeRequest({ channel: "shell", output: "echo $USER; rm -rf /" }));
  const json = await res.json();
  assert.deepStrictEqual(json, { safe: false, reason: "SHELL_METACHAR" });
});

test("ENCODED_PAYLOAD - entity", async () => {
  const res = await worker.fetch(makeRequest({ channel: "html", output: "&lt;script&gt;alert(1)&lt;/script&gt;" }));
  const json = await res.json();
  assert.deepStrictEqual(json, { safe: false, reason: "ENCODED_PAYLOAD" });
});

test("ENCODED_PAYLOAD - uri component", async () => {
  const res = await worker.fetch(makeRequest({ channel: "url", output: "javascript%3Aalert(1)" }));
  const json = await res.json();
  assert.deepStrictEqual(json, { safe: false, reason: "ENCODED_PAYLOAD" });
});

test("ENCODED_PAYLOAD - unicode escape", async () => {
  // \u003c is <
  const res = await worker.fetch(makeRequest({ channel: "html", output: "\\u003cscript>alert(1)<\\u002fscript>" }));
  const json = await res.json();
  assert.deepStrictEqual(json, { safe: false, reason: "ENCODED_PAYLOAD" });
});

test("Decode once but no rule trip -> should apply normal rules to original", async () => {
  // original output has encoded 'safe' string, decoded differs, but decoded doesn't trip.
  const res = await worker.fetch(makeRequest({ channel: "html", output: "&lt;b&gt;hello&lt;/b&gt;" }));
  const json = await res.json();
  assert.deepStrictEqual(json, { safe: true, reason: "SAFE" });
});

test("Markdown DANGEROUS_SCHEME", async () => {
  const res = await worker.fetch(makeRequest({ channel: "markdown", output: "[click](javascript:alert(1))" }));
  const json = await res.json();
  assert.deepStrictEqual(json, { safe: false, reason: "DANGEROUS_SCHEME" });
});

test("Markdown EXTERNAL_EXFIL", async () => {
  const res = await worker.fetch(makeRequest({ channel: "markdown", output: "[click](https://evil.com/123)" }));
  const json = await res.json();
  assert.deepStrictEqual(json, { safe: false, reason: "EXTERNAL_EXFIL" });
});

test("Markdown SAFE", async () => {
  const res = await worker.fetch(makeRequest({ channel: "markdown", output: "[click](https://app-feo6cve.example/home)" }));
  const json = await res.json();
  assert.deepStrictEqual(json, { safe: true, reason: "SAFE" });
});

test("URL Protocol relative", async () => {
  const res = await worker.fetch(makeRequest({ channel: "url", output: "//evil.com/x" }));
  const json = await res.json();
  assert.deepStrictEqual(json, { safe: false, reason: "EXTERNAL_EXFIL" });
});

test("URL Relative", async () => {
  const res = await worker.fetch(makeRequest({ channel: "url", output: "/local/page" }));
  const json = await res.json();
  assert.deepStrictEqual(json, { safe: true, reason: "SAFE" });
});

import test from "node:test";
import assert from "node:assert";
import worker from "../src/index.js";

function makeRequest(body) {
  return new Request("http://localhost/action-firewall", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

test("Valid search request", async () => {
  const req = makeRequest({
    provenance: "trusted",
    humanApproved: false,
    action: {
      tool: "search",
      args: { query: "hello" }
    }
  });
  const res = await worker.fetch(req);
  const json = await res.json();
  assert.deepStrictEqual(json, { decision: "allow", reason: "ALLOW" });
});

test("Invalid schema - search with too many keys", async () => {
  const req = makeRequest({
    provenance: "trusted",
    humanApproved: false,
    action: {
      tool: "search",
      args: { query: "hello", extra: "bad" }
    }
  });
  const res = await worker.fetch(req);
  const json = await res.json();
  assert.deepStrictEqual(json, { decision: "block", reason: "INVALID_SCHEMA" });
});

test("Tenant scope - incorrect tenant", async () => {
  const req = makeRequest({
    provenance: "trusted",
    humanApproved: false,
    action: {
      tool: "lookup_record",
      args: { tenantId: "tenant-wrong", recordId: "abc" }
    }
  });
  const res = await worker.fetch(req);
  const json = await res.json();
  assert.deepStrictEqual(json, { decision: "block", reason: "TENANT_SCOPE" });
});

test("Tenant scope - correct tenant", async () => {
  const req = makeRequest({
    provenance: "trusted",
    humanApproved: false,
    action: {
      tool: "lookup_record",
      args: { tenantId: "tenant-b6hhujd", recordId: "abc" }
    }
  });
  const res = await worker.fetch(req);
  const json = await res.json();
  assert.deepStrictEqual(json, { decision: "allow", reason: "ALLOW" });
});

test("send_email - exact email domain", async () => {
  const req = makeRequest({
    provenance: "trusted",
    humanApproved: true,
    action: {
      tool: "send_email",
      args: { to: "user@notify-4rcutch.example", subject: "hi", body: "hello" }
    }
  });
  const res = await worker.fetch(req);
  const json = await res.json();
  assert.deepStrictEqual(json, { decision: "allow", reason: "ALLOW" });
});

test("send_email - bad domain", async () => {
  const req = makeRequest({
    provenance: "trusted",
    humanApproved: true,
    action: {
      tool: "send_email",
      args: { to: "user@bad.example", subject: "hi", body: "hello" }
    }
  });
  const res = await worker.fetch(req);
  const json = await res.json();
  assert.deepStrictEqual(json, { decision: "block", reason: "EGRESS_DENIED" });
});

test("send_email - no human approval", async () => {
  const req = makeRequest({
    provenance: "trusted",
    humanApproved: false,
    action: {
      tool: "send_email",
      args: { to: "user@notify-4rcutch.example", subject: "hi", body: "hello" }
    }
  });
  const res = await worker.fetch(req);
  const json = await res.json();
  assert.deepStrictEqual(json, { decision: "block", reason: "APPROVAL_REQUIRED" });
});

test("render_html - bad script", async () => {
  const req = makeRequest({
    provenance: "trusted",
    humanApproved: false,
    action: {
      tool: "render_html",
      args: { html: "Hello <script>alert(1)</script>" }
    }
  });
  const res = await worker.fetch(req);
  const json = await res.json();
  assert.deepStrictEqual(json, { decision: "block", reason: "UNSAFE_OUTPUT" });
});

test("render_html - bad iframe", async () => {
  const req = makeRequest({
    provenance: "trusted",
    humanApproved: false,
    action: {
      tool: "render_html",
      args: { html: "<iframe src='evil'></iframe>" }
    }
  });
  const res = await worker.fetch(req);
  const json = await res.json();
  assert.deepStrictEqual(json, { decision: "block", reason: "UNSAFE_OUTPUT" });
});

test("render_html - bad event handler", async () => {
  const req = makeRequest({
    provenance: "trusted",
    humanApproved: false,
    action: {
      tool: "render_html",
      args: { html: "<img src='x' onerror=alert(1)>" }
    }
  });
  const res = await worker.fetch(req);
  const json = await res.json();
  assert.deepStrictEqual(json, { decision: "block", reason: "UNSAFE_OUTPUT" });
});

test("render_html - bad javascript url", async () => {
  const req = makeRequest({
    provenance: "trusted",
    humanApproved: false,
    action: {
      tool: "render_html",
      args: { html: "<a href='javascript:alert(1)'>click</a>" }
    }
  });
  const res = await worker.fetch(req);
  const json = await res.json();
  assert.deepStrictEqual(json, { decision: "block", reason: "UNSAFE_OUTPUT" });
});

test("render_html - safe html", async () => {
  const req = makeRequest({
    provenance: "trusted",
    humanApproved: false,
    action: {
      tool: "render_html",
      args: { html: "<b>Hello</b> world!" }
    }
  });
  const res = await worker.fetch(req);
  const json = await res.json();
  assert.deepStrictEqual(json, { decision: "allow", reason: "ALLOW" });
});

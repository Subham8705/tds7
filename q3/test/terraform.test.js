import test from "node:test";
import assert from "node:assert";
import worker from "../src/index.js";

function makeRequest(body) {
  return new Request("http://localhost/terraform/plan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

const validPayload = {
  "environment": "prod-wumjdl",
  "state": { "backend": "gcs", "locked": true },
  "providerVersion": "~> 6.0",
  "destroyApproved": false,
  "resource": {
    "address": "google_storage_bucket.data",
    "type": "storage_bucket",
    "action": "create",
    "labels": { "owner": "student-au6iq", "environment": "production", "cost_center": "cc-c486" },
    "secret": null,
    "forceDestroy": false
  }
};

test("Valid payload", async () => {
  const req = makeRequest(validPayload);
  const res = await worker.fetch(req);
  const json = await res.json();
  assert.deepStrictEqual(json, { decision: "approve", reason: "APPROVE" });
});

test("Invalid schema - missing forceDestroy", async () => {
  const payload = JSON.parse(JSON.stringify(validPayload));
  delete payload.resource.forceDestroy;
  const req = makeRequest(payload);
  const res = await worker.fetch(req);
  const json = await res.json();
  assert.deepStrictEqual(json, { decision: "reject", reason: "INVALID_PLAN" });
});

test("Environment mismatch", async () => {
  const payload = JSON.parse(JSON.stringify(validPayload));
  payload.environment = "dev";
  const req = makeRequest(payload);
  const res = await worker.fetch(req);
  const json = await res.json();
  assert.deepStrictEqual(json, { decision: "reject", reason: "ENVIRONMENT_MISMATCH" });
});

test("State unsafe - unlocked", async () => {
  const payload = JSON.parse(JSON.stringify(validPayload));
  payload.state.locked = false;
  const req = makeRequest(payload);
  const res = await worker.fetch(req);
  const json = await res.json();
  assert.deepStrictEqual(json, { decision: "reject", reason: "STATE_UNSAFE" });
});

test("State unsafe - bad backend", async () => {
  const payload = JSON.parse(JSON.stringify(validPayload));
  payload.state.backend = "local";
  const req = makeRequest(payload);
  const res = await worker.fetch(req);
  const json = await res.json();
  assert.deepStrictEqual(json, { decision: "reject", reason: "STATE_UNSAFE" });
});

test("Unpinned provider - latest", async () => {
  const payload = JSON.parse(JSON.stringify(validPayload));
  payload.providerVersion = "latest";
  const req = makeRequest(payload);
  const res = await worker.fetch(req);
  const json = await res.json();
  assert.deepStrictEqual(json, { decision: "reject", reason: "UNPINNED_PROVIDER" });
});

test("Unpinned provider - > 6.0", async () => {
  const payload = JSON.parse(JSON.stringify(validPayload));
  payload.providerVersion = "> 6.0";
  const req = makeRequest(payload);
  const res = await worker.fetch(req);
  const json = await res.json();
  assert.deepStrictEqual(json, { decision: "reject", reason: "UNPINNED_PROVIDER" });
});

test("Missing labels", async () => {
  const payload = JSON.parse(JSON.stringify(validPayload));
  payload.resource.labels.owner = "wrong";
  const req = makeRequest(payload);
  const res = await worker.fetch(req);
  const json = await res.json();
  assert.deepStrictEqual(json, { decision: "reject", reason: "MISSING_LABELS" });
});

test("Plaintext secret", async () => {
  const payload = JSON.parse(JSON.stringify(validPayload));
  payload.resource.secret = "my-super-secret";
  const req = makeRequest(payload);
  const res = await worker.fetch(req);
  const json = await res.json();
  assert.deepStrictEqual(json, { decision: "reject", reason: "PLAINTEXT_SECRET" });
});

test("Valid secret ref", async () => {
  const payload = JSON.parse(JSON.stringify(validPayload));
  payload.resource.secret = "secret://vault/my-secret";
  const req = makeRequest(payload);
  const res = await worker.fetch(req);
  const json = await res.json();
  assert.deepStrictEqual(json, { decision: "approve", reason: "APPROVE" });
});

test("Delete not approved", async () => {
  const payload = JSON.parse(JSON.stringify(validPayload));
  payload.resource.action = "delete";
  payload.resource.type = "sql_database";
  const req = makeRequest(payload);
  const res = await worker.fetch(req);
  const json = await res.json();
  assert.deepStrictEqual(json, { decision: "reject", reason: "DELETE_NOT_APPROVED" });
});

test("Force destroy", async () => {
  const payload = JSON.parse(JSON.stringify(validPayload));
  payload.resource.type = "storage_bucket";
  payload.resource.forceDestroy = true;
  const req = makeRequest(payload);
  const res = await worker.fetch(req);
  const json = await res.json();
  assert.deepStrictEqual(json, { decision: "reject", reason: "FORCE_DESTROY" });
});

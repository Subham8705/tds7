import test from "node:test";
import assert from "node:assert";
import worker from "../src/index.js";

function makeRequest(body) {
  return new Request("http://localhost/corroborate", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

const basePayload = {
  "claim": { "subject": "a.com", "predicate": "resolves_to", "value": "1.2.3.4" },
  "asOf": "2026-08-01T00:00:00Z",
  "stalenessDays": 365,
  "sources": []
};

test("invalid - missing claim value", async () => {
  const payload = JSON.parse(JSON.stringify(basePayload));
  delete payload.claim.value;
  const res = await worker.fetch(makeRequest(payload));
  const json = await res.json();
  assert.deepStrictEqual(json, { verdict: "invalid", confidence: "low", corroboratingSources: [] });
});

test("contradicted - one fresh authoritative different value", async () => {
  const payload = JSON.parse(JSON.stringify(basePayload));
  payload.sources = [
    { id: "s1", type: "dns", origin: "o1", observedAt: "2026-07-30T00:00:00Z", value: "8.8.8.8", authoritative: true },
    { id: "s2", type: "dns", origin: "o2", observedAt: "2026-07-30T00:00:00Z", value: "1.2.3.4", authoritative: false }
  ];
  const res = await worker.fetch(makeRequest(payload));
  const json = await res.json();
  assert.deepStrictEqual(json, { verdict: "contradicted", confidence: "low", corroboratingSources: ["s1"] });
});

test("supported - two fresh matching origins, different types = high", async () => {
  const payload = JSON.parse(JSON.stringify(basePayload));
  payload.sources = [
    { id: "s1", type: "dns", origin: "o1", observedAt: "2026-07-30T00:00:00Z", value: "1.2.3.4" },
    { id: "s2", type: "scan", origin: "o2", observedAt: "2026-07-30T00:00:00Z", value: "1.2.3.4" }
  ];
  const res = await worker.fetch(makeRequest(payload));
  const json = await res.json();
  assert.deepStrictEqual(json, { verdict: "supported", confidence: "high", corroboratingSources: ["s1", "s2"] });
});

test("supported - two fresh matching origins, same types = medium", async () => {
  const payload = JSON.parse(JSON.stringify(basePayload));
  payload.sources = [
    { id: "s1", type: "dns", origin: "o1", observedAt: "2026-07-30T00:00:00Z", value: "1.2.3.4" },
    { id: "s2", type: "dns", origin: "o2", observedAt: "2026-07-30T00:00:00Z", value: "1.2.3.4" }
  ];
  const res = await worker.fetch(makeRequest(payload));
  const json = await res.json();
  assert.deepStrictEqual(json, { verdict: "supported", confidence: "medium", corroboratingSources: ["s1", "s2"] });
});

test("unverified - single independent source", async () => {
  const payload = JSON.parse(JSON.stringify(basePayload));
  payload.sources = [
    { id: "s1", type: "dns", origin: "o1", observedAt: "2026-07-30T00:00:00Z", value: "1.2.3.4" }
  ];
  const res = await worker.fetch(makeRequest(payload));
  const json = await res.json();
  assert.deepStrictEqual(json, { verdict: "unverified", confidence: "low", corroboratingSources: [] });
});

test("unverified - only mirrors", async () => {
  const payload = JSON.parse(JSON.stringify(basePayload));
  payload.sources = [
    { id: "s1", type: "dns", origin: "o1", observedAt: "2026-07-30T00:00:00Z", value: "1.2.3.4" },
    { id: "s2", type: "dns", origin: "o1", observedAt: "2026-07-30T00:00:00Z", value: "1.2.3.4" }
  ];
  const res = await worker.fetch(makeRequest(payload));
  const json = await res.json();
  assert.deepStrictEqual(json, { verdict: "unverified", confidence: "low", corroboratingSources: [] });
});

test("supported - lexicographically smallest id used for mirrors", async () => {
  const payload = JSON.parse(JSON.stringify(basePayload));
  payload.sources = [
    { id: "z2", type: "dns", origin: "o1", observedAt: "2026-07-30T00:00:00Z", value: "1.2.3.4" },
    { id: "a1", type: "dns", origin: "o1", observedAt: "2026-07-30T00:00:00Z", value: "1.2.3.4" },
    { id: "s3", type: "scan", origin: "o2", observedAt: "2026-07-30T00:00:00Z", value: "1.2.3.4" }
  ];
  const res = await worker.fetch(makeRequest(payload));
  const json = await res.json();
  assert.deepStrictEqual(json, { verdict: "supported", confidence: "high", corroboratingSources: ["a1", "s3"] });
});

test("unverified - agreement entirely stale", async () => {
  const payload = JSON.parse(JSON.stringify(basePayload));
  payload.sources = [
    { id: "s1", type: "dns", origin: "o1", observedAt: "2025-01-01T00:00:00Z", value: "1.2.3.4" },
    { id: "s2", type: "scan", origin: "o2", observedAt: "2025-01-01T00:00:00Z", value: "1.2.3.4" }
  ];
  const res = await worker.fetch(makeRequest(payload));
  const json = await res.json();
  assert.deepStrictEqual(json, { verdict: "unverified", confidence: "low", corroboratingSources: [] });
});

test("unverified - stale authoritative disagreement doesn't contradict", async () => {
  const payload = JSON.parse(JSON.stringify(basePayload));
  payload.sources = [
    { id: "s1", type: "dns", origin: "o1", observedAt: "2026-07-30T00:00:00Z", value: "1.2.3.4" },
    { id: "s2", type: "scan", origin: "o2", observedAt: "2026-07-30T00:00:00Z", value: "1.2.3.4" },
    // stale authoritative disagreement
    { id: "s3", type: "dns", origin: "o3", observedAt: "2025-01-01T00:00:00Z", value: "8.8.8.8", authoritative: true }
  ];
  const res = await worker.fetch(makeRequest(payload));
  const json = await res.json();
  assert.deepStrictEqual(json, { verdict: "supported", confidence: "high", corroboratingSources: ["s1", "s2"] });
});

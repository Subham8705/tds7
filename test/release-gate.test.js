import test from "node:test";
import assert from "node:assert/strict";
import { evaluate } from "../src/index.js";

const safeWorkflow = {
  trigger: "pull_request",
  permissions: {
    contents: "read",
    packages: "write",
    "id-token": "none",
  },
  testsPassed: true,
  matrixComplete: true,
  failFast: false,
  actions: [
    { owner: "actions", name: "checkout", ref: "v4" },
    { owner: "thirdparty", name: "example", ref: "0123456789abcdef0123456789abcdef01234567" }
  ],
};

const safeImage = {
  multiStage: true,
  runsAsRoot: false,
  secretMode: "none",
  criticalVulnerabilities: 0,
  digestPinned: true,
};

test("safe preview PR is promoted", () => {
  const result = evaluate({
    target: "preview",
    event: "pull_request",
    ref: "refs/pull/1/merge",
    workflow: safeWorkflow,
    image: safeImage,
  });
  assert.deepEqual(result, { decision: "promote", violations: [] });
});

test("production requires push to main and approval", () => {
  const workflow = { ...safeWorkflow, trigger: "push", environmentApproval: true };
  const result = evaluate({
    target: "production",
    event: "push",
    ref: "refs/heads/main",
    workflow,
    image: safeImage,
  });
  assert.deepEqual(result, { decision: "promote", violations: [] });
});

test("unsafe PR target is blocked", () => {
  const result = evaluate({
    target: "preview",
    event: "pull_request_target",
    ref: "refs/pull/2/merge",
    workflow: { ...safeWorkflow, trigger: "pull_request_target" },
    image: safeImage,
  });
  assert.ok(result.violations.includes("UNSAFE_PR_TRIGGER"));
  assert.equal(result.decision, "block");
});

test("extra permissions are blocked", () => {
  const result = evaluate({
    target: "preview",
    event: "pull_request",
    ref: "refs/pull/3/merge",
    workflow: {
      ...safeWorkflow,
      permissions: { ...safeWorkflow.permissions, actions: "write" },
    },
    image: safeImage,
  });
  assert.deepEqual(result.violations, ["EXCESS_PERMISSION"]);
});

test("incomplete matrix and fail-fast are blocked", () => {
  const result = evaluate({
    target: "preview",
    event: "pull_request",
    ref: "refs/pull/4/merge",
    workflow: { ...safeWorkflow, testsPassed: false, matrixComplete: false, failFast: true },
    image: safeImage,
  });
  assert.deepEqual(result.violations, ["TESTS_INCOMPLETE"]);
});

test("third-party mutable action is blocked", () => {
  const result = evaluate({
    target: "preview",
    event: "pull_request",
    ref: "refs/pull/5/merge",
    workflow: {
      ...safeWorkflow,
      actions: [{ owner: "thirdparty", name: "example", ref: "v1" }],
    },
    image: safeImage,
  });
  assert.deepEqual(result.violations, ["MUTABLE_ACTION"]);
});

test("image hardening violations are all returned", () => {
  const result = evaluate({
    target: "preview",
    event: "pull_request",
    ref: "refs/pull/6/merge",
    workflow: safeWorkflow,
    image: {
      multiStage: false,
      runsAsRoot: true,
      secretMode: "arg",
      criticalVulnerabilities: 2,
      digestPinned: false,
    },
  });
  assert.deepEqual(result.violations, [
    "SINGLE_STAGE_IMAGE",
    "ROOT_RUNTIME",
    "SECRET_IN_LAYER",
    "CRITICAL_CVE",
    "UNPINNED_IMAGE",
  ]);
});

test("image with buildkit secret mode is allowed", () => {
  const result = evaluate({
    target: "preview",
    event: "pull_request",
    ref: "refs/pull/8/merge",
    workflow: safeWorkflow,
    image: { ...safeImage, secretMode: "buildkit" },
  });
  assert.deepEqual(result, { decision: "promote", violations: [] });
});

test("empty payload produces all necessary violations", () => {
  const result = evaluate({});
  assert.equal(result.decision, "block");
  assert.ok(result.violations.includes("EXCESS_PERMISSION"));
  assert.ok(result.violations.includes("TESTS_INCOMPLETE"));
  assert.ok(result.violations.includes("SINGLE_STAGE_IMAGE"));
  assert.ok(result.violations.includes("ROOT_RUNTIME"));
  assert.ok(result.violations.includes("SECRET_IN_LAYER"));
  assert.ok(result.violations.includes("CRITICAL_CVE"));
  assert.ok(result.violations.includes("UNPINNED_IMAGE"));
});

test("production without main push and approval returns both violations", () => {
  const result = evaluate({
    target: "production",
    event: "pull_request",
    ref: "refs/pull/7/merge",
    workflow: { ...safeWorkflow, environmentApproval: false },
    image: safeImage,
  });
  assert.deepEqual(result.violations, [
    "INVALID_PRODUCTION_REF",
    "APPROVAL_REQUIRED",
  ]);
});

test("worker fetch handles GET / and POST /release-gate and 404", async () => {
  const worker = (await import("../src/index.js")).default;
  const getRes = await worker.fetch(new Request("http://localhost/"));
  assert.equal(getRes.status, 200);

  const postRes = await worker.fetch(
    new Request("http://localhost/release-gate", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        target: "preview",
        event: "pull_request",
        ref: "refs/pull/1/merge",
        workflow: safeWorkflow,
        image: safeImage,
      }),
    })
  );
  assert.equal(postRes.status, 200);
  const data = await postRes.json();
  assert.deepEqual(data, { decision: "promote", violations: [] });

  const invalidJsonRes = await worker.fetch(
    new Request("http://localhost/release-gate", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{invalid json",
    })
  );
  assert.equal(invalidJsonRes.status, 400);

  const notFoundRes = await worker.fetch(
    new Request("http://localhost/other", { method: "GET" })
  );
  assert.equal(notFoundRes.status, 404);
});


const ALLOWED_PERMISSIONS = {
  contents: "read",
  packages: "write",
  "id-token": "none",
};

const SHA40 = /^[0-9a-f]{40}$/;

function addViolation(violations, code) {
  if (!violations.includes(code)) violations.push(code);
}

function validatePermissions(permissions) {
  const violations = [];
  if (!permissions || typeof permissions !== "object") {
    addViolation(violations, "EXCESS_PERMISSION");
    return violations;
  }

  const keys = Object.keys(permissions);
  const expected = Object.keys(ALLOWED_PERMISSIONS);

  const exact =
    keys.length === expected.length &&
    expected.every((key) => Object.prototype.hasOwnProperty.call(permissions, key)) &&
    expected.every((key) => permissions[key] === ALLOWED_PERMISSIONS[key]);

  if (!exact) addViolation(violations, "EXCESS_PERMISSION");
  return violations;
}

function validateActions(actions) {
  const violations = [];
  if (!Array.isArray(actions)) return violations;

  for (const action of actions) {
    if (!action || typeof action !== "object") continue;

    const owner = String(action.owner ?? "");
    const ref = String(action.ref ?? "");

    if (owner !== "actions" && !SHA40.test(ref)) {
      addViolation(violations, "MUTABLE_ACTION");
    }
  }
  return violations;
}

function evaluate(payload) {
  const violations = [];
  const target = payload?.target;
  const event = payload?.event;
  const ref = payload?.ref;
  const workflow = payload?.workflow ?? {};
  const image = payload?.image ?? {};

  // Release permissions must be exactly the stated least-privilege set.
  for (const code of validatePermissions(workflow.permissions)) {
    addViolation(violations, code);
  }

  // Pull requests must use the safe pull_request trigger.
  if (event === "pull_request" && workflow.trigger !== "pull_request") {
    addViolation(violations, "UNSAFE_PR_TRIGGER");
  }
  if (event === "pull_request_target" || workflow.trigger === "pull_request_target") {
    addViolation(violations, "UNSAFE_PR_TRIGGER");
  }

  // Tests must pass, the complete matrix must finish, and fail-fast must be disabled.
  if (workflow.testsPassed !== true) addViolation(violations, "TESTS_INCOMPLETE");
  if (workflow.matrixComplete !== true) addViolation(violations, "TESTS_INCOMPLETE");
  if (workflow.failFast !== false) addViolation(violations, "TESTS_INCOMPLETE");

  // actions/* may use a version tag; all third-party actions need a full SHA.
  for (const code of validateActions(workflow.actions)) {
    addViolation(violations, code);
  }

  // Image hardening requirements.
  if (image.multiStage !== true) addViolation(violations, "SINGLE_STAGE_IMAGE");
  if (image.runsAsRoot !== false) addViolation(violations, "ROOT_RUNTIME");
  if (!["none", "buildkit"].includes(image.secretMode)) {
    addViolation(violations, "SECRET_IN_LAYER");
  }
  if (image.criticalVulnerabilities !== 0) {
    addViolation(violations, "CRITICAL_CVE");
  }
  if (image.digestPinned !== true) addViolation(violations, "UNPINNED_IMAGE");

  // Production has two additional gates.
  if (target === "production") {
    if (event !== "push" || ref !== "refs/heads/main") {
      addViolation(violations, "INVALID_PRODUCTION_REF");
    }
    if (workflow.environmentApproval !== true) {
      addViolation(violations, "APPROVAL_REQUIRED");
    }
  }

  return {
    decision: violations.length === 0 ? "promote" : "block",
    violations,
  };
}

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

export default {
  async fetch(request) {
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: CORS_HEADERS,
      });
    }

    const url = new URL(request.url);

    if (request.method === "GET" && url.pathname === "/") {
      return new Response(
        JSON.stringify({
          service: "TDS GA7 Release Gate",
          endpoint: "POST /release-gate",
          status: "ok",
        }),
        {
          headers: {
            "content-type": "application/json",
            ...CORS_HEADERS,
          },
        }
      );
    }

    if (request.method !== "POST" || url.pathname !== "/release-gate") {
      return new Response(JSON.stringify({ error: "Not found" }), {
        status: 404,
        headers: {
          "content-type": "application/json",
          ...CORS_HEADERS,
        },
      });
    }

    try {
      const payload = await request.json();
      const result = evaluate(payload);
      return new Response(JSON.stringify(result), {
        status: 200,
        headers: {
          "content-type": "application/json",
          "cache-control": "no-store",
          ...CORS_HEADERS,
        },
      });
    } catch {
      return new Response(JSON.stringify({ error: "Invalid JSON" }), {
        status: 400,
        headers: {
          "content-type": "application/json",
          ...CORS_HEADERS,
        },
      });
    }
  },
};

export { evaluate };

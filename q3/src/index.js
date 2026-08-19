const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

export default {
  async fetch(request, env, ctx) {
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: CORS_HEADERS, status: 204 });
    }

    if (request.method === "GET") {
      return Response.json(
        { service: "TDS GA7 Terraform Plan", status: "ok" },
        { headers: CORS_HEADERS }
      );
    }

    if (request.method === "POST" && new URL(request.url).pathname === "/terraform/plan") {
      try {
        const body = await request.json();

        // 1. Schema check
        if (
          typeof body !== "object" ||
          body === null ||
          typeof body.environment !== "string" ||
          typeof body.state !== "object" ||
          body.state === null ||
          typeof body.state.backend !== "string" ||
          typeof body.state.locked !== "boolean" ||
          typeof body.providerVersion !== "string" ||
          typeof body.destroyApproved !== "boolean" ||
          typeof body.resource !== "object" ||
          body.resource === null ||
          typeof body.resource.address !== "string" ||
          typeof body.resource.type !== "string" ||
          !["create", "update", "delete"].includes(body.resource.action) ||
          typeof body.resource.labels !== "object" ||
          body.resource.labels === null ||
          (body.resource.secret !== null && typeof body.resource.secret !== "string") ||
          typeof body.resource.forceDestroy !== "boolean"
        ) {
          return Response.json({ decision: "reject", reason: "INVALID_PLAN" }, { headers: CORS_HEADERS });
        }

        // 2. Environment check
        if (body.environment !== "prod-wumjdl") {
          return Response.json({ decision: "reject", reason: "ENVIRONMENT_MISMATCH" }, { headers: CORS_HEADERS });
        }

        // 3. State check
        const validBackends = ["gcs", "s3", "azurerm", "remote"];
        if (!validBackends.includes(body.state.backend) || body.state.locked !== true) {
          return Response.json({ decision: "reject", reason: "STATE_UNSAFE" }, { headers: CORS_HEADERS });
        }

        // 4. Provider Version check
        const providerRegex = /^(?:=?\s*\d+\.\d+(?:\.\d+)?|~>\s*\d+\.\d+(?:\.\d+)?)$/;
        if (!providerRegex.test(body.providerVersion)) {
          return Response.json({ decision: "reject", reason: "UNPINNED_PROVIDER" }, { headers: CORS_HEADERS });
        }

        // 5. Missing Labels check
        const labels = body.resource.labels;
        if (
          labels.owner !== "student-au6iq" ||
          labels.environment !== "production" ||
          labels.cost_center !== "cc-c486"
        ) {
          return Response.json({ decision: "reject", reason: "MISSING_LABELS" }, { headers: CORS_HEADERS });
        }

        // 6. Plaintext Secret check
        if (body.resource.secret !== null) {
          if (!body.resource.secret.startsWith("secret://") || body.resource.secret.length <= "secret://".length) {
            return Response.json({ decision: "reject", reason: "PLAINTEXT_SECRET" }, { headers: CORS_HEADERS });
          }
        }

        // 7. Delete Not Approved check
        const protectedTypes = ["storage_bucket", "sql_database", "persistent_disk"];
        if (
          body.resource.action === "delete" &&
          protectedTypes.includes(body.resource.type) &&
          body.destroyApproved !== true
        ) {
          return Response.json({ decision: "reject", reason: "DELETE_NOT_APPROVED" }, { headers: CORS_HEADERS });
        }

        // 8. Force Destroy check
        if (body.resource.type === "storage_bucket" && body.resource.forceDestroy === true) {
          return Response.json({ decision: "reject", reason: "FORCE_DESTROY" }, { headers: CORS_HEADERS });
        }

        return Response.json({ decision: "approve", reason: "APPROVE" }, { headers: CORS_HEADERS });

      } catch (err) {
        return Response.json({ decision: "reject", reason: "INVALID_PLAN" }, { headers: CORS_HEADERS, status: 400 });
      }
    }

    return new Response("Not Found", { status: 404, headers: CORS_HEADERS });
  },
};

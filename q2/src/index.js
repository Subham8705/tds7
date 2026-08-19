const ALLOWED_TOOLS = ["search", "lookup_record", "send_email", "render_html"];
const TENANT_ID = "tenant-b6hhujd";
const EMAIL_DOMAIN = "notify-4rcutch.example";

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
        { service: "TDS GA7 Action Firewall", status: "ok" },
        { headers: CORS_HEADERS }
      );
    }

    if (request.method === "POST" && new URL(request.url).pathname === "/action-firewall") {
      try {
        const body = await request.json();

        // 1. Check top-level schema
        if (
          typeof body !== "object" ||
          body === null ||
          !["trusted", "untrusted"].includes(body.provenance) ||
          typeof body.humanApproved !== "boolean" ||
          (body.untrustedContent !== undefined && typeof body.untrustedContent !== "string") ||
          typeof body.action !== "object" ||
          body.action === null ||
          typeof body.action.tool !== "string" ||
          typeof body.action.args !== "object" ||
          body.action.args === null
        ) {
          return Response.json({ decision: "block", reason: "INVALID_SCHEMA" }, { headers: CORS_HEADERS });
        }

        const tool = body.action.tool;
        const args = body.action.args;

        // 2. Tool allowlist
        if (!ALLOWED_TOOLS.includes(tool)) {
          return Response.json({ decision: "block", reason: "TOOL_NOT_ALLOWED" }, { headers: CORS_HEADERS });
        }

        // 3. Selected tool's argument schema
        if (tool === "search") {
          if (
            Object.keys(args).length !== 1 ||
            typeof args.query !== "string" ||
            args.query.length < 1 ||
            args.query.length > 200
          ) {
            return Response.json({ decision: "block", reason: "INVALID_SCHEMA" }, { headers: CORS_HEADERS });
          }
        } else if (tool === "lookup_record") {
          if (
            Object.keys(args).length !== 2 ||
            typeof args.tenantId !== "string" ||
            typeof args.recordId !== "string" ||
            args.recordId.trim() === ""
          ) {
            return Response.json({ decision: "block", reason: "INVALID_SCHEMA" }, { headers: CORS_HEADERS });
          }
        } else if (tool === "send_email") {
          if (
            Object.keys(args).length !== 3 ||
            typeof args.to !== "string" ||
            typeof args.subject !== "string" ||
            typeof args.body !== "string"
          ) {
            return Response.json({ decision: "block", reason: "INVALID_SCHEMA" }, { headers: CORS_HEADERS });
          }
        } else if (tool === "render_html") {
          if (
            Object.keys(args).length !== 1 ||
            typeof args.html !== "string"
          ) {
            return Response.json({ decision: "block", reason: "INVALID_SCHEMA" }, { headers: CORS_HEADERS });
          }
        }

        // 4. Tenant scope (for lookup_record)
        if (tool === "lookup_record") {
          if (args.tenantId !== TENANT_ID) {
            return Response.json({ decision: "block", reason: "TENANT_SCOPE" }, { headers: CORS_HEADERS });
          }
        }

        // 5. Exact email domain & human approval (for send_email)
        if (tool === "send_email") {
          const emailParts = args.to.split("@");
          if (emailParts.length !== 2 || emailParts[1] !== EMAIL_DOMAIN) {
            return Response.json({ decision: "block", reason: "EGRESS_DENIED" }, { headers: CORS_HEADERS });
          }
          if (body.humanApproved !== true) {
            return Response.json({ decision: "block", reason: "APPROVAL_REQUIRED" }, { headers: CORS_HEADERS });
          }
        }

        // 6. HTML safety (for render_html)
        if (tool === "render_html") {
          // block scripts, iframes, inline event handlers, and javascript: URLs.
          const scriptRegex = /<\s*script/i;
          const iframeRegex = /<\s*iframe/i;
          const inlineEventRegex = /\bon[a-z]+\s*=/i;
          const jsUrlRegex = /javascript\s*:/i;

          if (
            scriptRegex.test(args.html) ||
            iframeRegex.test(args.html) ||
            inlineEventRegex.test(args.html) ||
            jsUrlRegex.test(args.html)
          ) {
            return Response.json({ decision: "block", reason: "UNSAFE_OUTPUT" }, { headers: CORS_HEADERS });
          }
        }

        return Response.json({ decision: "allow", reason: "ALLOW" }, { headers: CORS_HEADERS });
      } catch (err) {
        return Response.json({ decision: "block", reason: "INVALID_SCHEMA" }, { headers: CORS_HEADERS, status: 400 });
      }
    }

    return new Response("Not Found", { status: 404, headers: CORS_HEADERS });
  },
};

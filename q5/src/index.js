const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

const VALID_TYPES = ["dns", "ct_log", "registry", "archive", "scan"];

export default {
  async fetch(request, env, ctx) {
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: CORS_HEADERS, status: 204 });
    }

    if (request.method === "GET") {
      return Response.json(
        { service: "TDS GA7 Corroborate", status: "ok" },
        { headers: CORS_HEADERS }
      );
    }

    if (request.method === "POST" && new URL(request.url).pathname === "/corroborate") {
      try {
        const body = await request.json();

        // Rule 1: invalid
        if (
          typeof body !== 'object' || body === null ||
          typeof body.claim?.value !== 'string' ||
          typeof body.asOf !== 'string' || isNaN(Date.parse(body.asOf)) ||
          typeof body.stalenessDays !== 'number' ||
          !Array.isArray(body.sources)
        ) {
          return Response.json({ verdict: "invalid", confidence: "low", corroboratingSources: [] }, { headers: CORS_HEADERS });
        }

        const asOfMs = Date.parse(body.asOf);
        const maxDiffMs = body.stalenessDays * 86400000;
        const claimValue = body.claim.value;

        // Filter and tag valid/fresh sources
        const validSources = [];
        for (const s of body.sources) {
          if (
            typeof s.id === 'string' &&
            typeof s.origin === 'string' &&
            typeof s.value === 'string' &&
            typeof s.observedAt === 'string' &&
            VALID_TYPES.includes(s.type)
          ) {
            const obsMs = Date.parse(s.observedAt);
            const isFresh = !isNaN(obsMs) && (asOfMs - obsMs) <= maxDiffMs;
            validSources.push({ ...s, isFresh });
          }
        }

        // Rule 2: contradicted
        const contradictingSources = validSources.filter(s => 
          s.isFresh && s.authoritative === true && s.value !== claimValue
        );

        if (contradictingSources.length > 0) {
          const ids = contradictingSources.map(s => s.id).sort();
          return Response.json({ verdict: "contradicted", confidence: "low", corroboratingSources: ids }, { headers: CORS_HEADERS });
        }

        // Rule 3: supported
        const supportingFresh = validSources.filter(s => s.isFresh && s.value === claimValue);

        // Group by origin to find representatives
        const representativesByOrigin = {};
        for (const s of supportingFresh) {
          if (!representativesByOrigin[s.origin]) {
            representativesByOrigin[s.origin] = s;
          } else {
            // "lexicographically smallest id"
            if (s.id < representativesByOrigin[s.origin].id) {
              representativesByOrigin[s.origin] = s;
            }
          }
        }

        const representatives = Object.values(representativesByOrigin);

        if (representatives.length >= 2) {
          const types = new Set(representatives.map(s => s.type));
          const confidence = types.size >= 2 ? "high" : "medium";
          const ids = representatives.map(s => s.id).sort();
          
          return Response.json({ verdict: "supported", confidence: confidence, corroboratingSources: ids }, { headers: CORS_HEADERS });
        }

        // Rule 4: unverified
        return Response.json({ verdict: "unverified", confidence: "low", corroboratingSources: [] }, { headers: CORS_HEADERS });

      } catch (err) {
        return Response.json({ verdict: "invalid", confidence: "low", corroboratingSources: [] }, { headers: CORS_HEADERS, status: 400 });
      }
    }

    return new Response("Not Found", { status: 404, headers: CORS_HEADERS });
  },
};

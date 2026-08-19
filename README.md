# TDS GA7 Release Gate

Deterministic Cloudflare Worker implementing `POST /release-gate`.

## Local

```bash
npm install
npm test
npx wrangler dev
```

The local endpoint is `http://localhost:8787/release-gate`.

## Deploy

```bash
npx wrangler login
npx wrangler deploy
```

Wrangler will print the public `workers.dev` URL. Submit:

```json
{
  "serviceUrl": "https://YOUR-WORKER.YOUR-SUBDOMAIN.workers.dev",
  "workflowUrl": "https://github.com/YOUR-USER/YOUR-REPO/actions/workflows/TDS%20GA7%20Release%20Gate.yml"
}
```

The GitHub workflow must be named exactly `TDS GA7 Release Gate`, and the repository must be public.

## Important

The policy evaluator intentionally uses only the fields described in the assignment and returns only the defined violation codes.

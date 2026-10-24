# Sentinel MCP integration

## Design and scope

Sentinel exposes nine read-only tools using the existing Rust/Axum process and database handlers. No extra server, duplicated intelligence store, model provider or paid service is required. The endpoint is `POST /api/mcp` on the API, Vite dev proxy and deployed frontend. Existing nginx and HTTPS proxy configuration already forwards `/api/`.

Supported protocol revisions: **2025-03-26, 2025-06-18 and 2025-11-25**. The server negotiates during `initialize`, responds with JSON, and is stateless: no session IDs, unsolicited messages, SSE stream, sampling, prompts or resources. GET and DELETE return 405. A notification receives 202 with an empty body. HTTP requests must accept both `application/json` and `text/event-stream`. Unsupported protocol headers receive 400. Newer protocol clients must support handshake-era fallback; the 2026 protocol revision is not implemented.

This follows the [MCP transport specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports) and [tool specification](https://modelcontextprotocol.io/specification/2025-11-25/server/tools).

## Connect over HTTP

Start Sentinel normally with `npm run dev`, or use Docker Compose. For a client on this machine:

```json
{
  "mcpServers": {
    "sentinel": {
      "type": "http",
      "url": "http://127.0.0.1:8080/api/mcp",
      "headers": {
        "Authorization": "Bearer <SCOPED_CLIENT_TOKEN>"
      }
    }
  }
}
```

Replace the placeholder privately with the token from your deployment environment. This is a generic configuration example; client-specific keys vary. If your client uses `serverUrl` instead of `url`, put the same endpoint in `serverUrl` and retain the authorization header. The app’s **API & integrations** page supplies a copyable configuration using the direct API address in local development and the current app origin in deployed builds. A remote AI client needs your deployed, reachable `https://your-host/api/mcp` URL. Localhost refers to the client’s own machine.

Use an expiring client credential with the `read` scope. Create and revoke keys with `scripts/client-token.mjs`; see [client setup](OPERATIONS.md#security-upgrade-and-scoped-clients). The hash-only registry is reloaded on every client-authenticated request, so removal revokes subsequent requests without an API restart. Client keys cannot create browser operator sessions. The existing operator token still grants all REST actions and should remain with administrators. Origin checks apply to all MCP methods; the allowed origin is `VI_PUBLIC_ORIGIN` with the existing local development exception. Existing shared rate limits also apply. MCP request bodies are limited to 64 KiB. Tools cannot enqueue jobs, write VEX, execute detection rules or change policy.

There is no OAuth discovery or authorization service. Clients requiring OAuth or prohibiting bearer headers cannot connect directly; they require a suitable authentication gateway. Browser clients from other origins require a same-origin proxy; this endpoint does not offer arbitrary CORS access. No universal compatibility with every AI product is implied.

## Connection troubleshooting

If initialization fails with `connect: connection refused`, the client could not reach a listening server. This happens before bearer-token authentication.

1. From the project directory, run `npm run dev` and keep it running. PostgreSQL and Valkey containers alone do not start the API or frontend. For a full Docker deployment, start the app services with `docker compose up -d --build` after setup.
2. For a client on the same machine, set its endpoint to `http://127.0.0.1:8080/api/mcp`. Port 8080 serves the API directly. Port 5173 is the development frontend proxy and is available only while Vite is running. Using `127.0.0.1` avoids clients resolving `localhost` to IPv6 `::1` when the server listens only on IPv4.
3. Reconnect or reload the MCP client after the API starts. Keep the existing `Authorization: Bearer <SCOPED_CLIENT_TOKEN>` header.

To check API reachability, run `curl --fail http://127.0.0.1:8080/health`. A successful health check confirms HTTP reachability; MCP initialization also requires the bearer token. Opening `/api/mcp` in a browser sends GET, which returns 405 by design.

## Connect over stdio

For clients that launch a local process, Node.js 22.12+ is sufficient. The adapter forwards JSON-RPC to the running Sentinel API; it does not start the app. Use an absolute script path:

```json
{
  "mcpServers": {
    "sentinel": {
      "command": "node",
      "args": ["/absolute/path/to/threat-intel/scripts/mcp-stdio.mjs"],
      "env": {
        "VI_MCP_URL": "http://127.0.0.1:8080/api/mcp",
        "VI_API_TOKEN": "<SCOPED_CLIENT_TOKEN>"
      }
    }
  }
}
```

The bridge reads credentials only from its environment, does not load `.env`, rejects plaintext remote URLs and redirects, sends diagnostics to stderr, and writes only JSON-RPC to stdout. The default URL is `http://127.0.0.1:8080/api/mcp`. Public connections use HTTPS.

## Tool catalog

| Tool | Inputs | Behavior |
|---|---|---|
| `search_vulnerabilities` | `text_search`, `conditions`, `operator`, `sort_by`, `sort_order`, `cursor`, `limit` | Typed API filters, facets and cursor pagination; default 20, maximum 100 records |
| `get_vulnerability` | required `id` | CVE details, scores and source evidence |
| `get_detection_rules` | required `id` | Source-backed detection artifacts for a CVE |
| `get_relationships` | required `id` | Relationships for a CVE or entity reference |
| `search_threat_actors` | `name`, `cve`, `skip`, `limit` | Actor and ransomware profiles; default 20, maximum 100 |
| `search_products` | `name`, `ecosystem`, `skip`, `limit` | Source-backed package/CPE/PURL lookup; maximum 100 |
| `lookup_patch` | required `kb`, optional `product` | Source-supplied KB supersedence chain |
| `get_statistics` | none | Current committed counts and source status |
| `get_sources` | none | Ingestion checkpoints, freshness and failures |

Filter conditions use the same fields/operators/types as `/api/v2/vulnerabilities/filter`. For example:

```json
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"search_vulnerabilities","arguments":{"conditions":[{"field":"seen_wild","operator":"eq","value":true}],"limit":10}}}
```

Tool results provide `structuredContent` and a JSON text content block. Protocol errors use JSON-RPC errors; database errors, unknown CVEs and handler validation failures return tool results with `isError: true`. Tool inputs are validated before dispatch. Feed content is untrusted data, not instructions, and source URLs should be cited by the consuming assistant. Missing records or unknown scores are not evidence that a product is safe.

## Verification and next phases

Run `npm test`, `cargo build --manifest-path backend/Cargo.toml --locked`, `node scripts/test-production.mjs`, and `npm run build`. The production integration test uses a disposable database, exercises all nine tools, authentication, origins, version negotiation, errors and pagination, and runs a stdio initialize/notification/tool-call exchange.

Implementation plan:

1. **Implemented:** native HTTP endpoint, nine read-only tools, existing security controls, stdio bridge, in-app configuration and integration checks.
2. **Implemented:** expiring/revocable scoped client keys, shared query limits and credential identity on VEX/ingestion writes. **Next:** OAuth authorization/discovery and per-client usage reporting.
3. **Later:** newer protocol revision support, broader SDK/client compatibility matrix, explicitly authorized write tools with separate permissions.

The latter phases are planned, not provided by this implementation. Public deployment uses the existing HTTPS deployment process; adding this code does not publish a new internet endpoint by itself.

### Weakness and remediation context

`get_vulnerability` includes NVD-backed `weaknesses`, `weakness_evidence`, and `patch_links` after that CVE is reimported. Follow `get_relationships` from the CVE to a CWE, then from the CWE to an OWASP category. For CWE and OWASP identifiers, the relationship response includes a `knowledge` entry with source provenance. MITRE mitigations describe a weakness class; they are not a product-specific fix or applicability determination. No additional MCP tools or write permissions are introduced.

Vendor source imports also expose `remediation_evidence` through `get_vulnerability`, retaining product/branch context, published release status and original affected ranges. `patch_available` is an aggregate signal; consult the scoped evidence before choosing a product version or patch. Apache HTTP Server, Apache Tomcat, OpenSSL and curl appear in `get_sources` after restart.

Browser OIDC SSO and local human-user roles do not add an OAuth authorization server for MCP connectors. Use scoped bearer keys for integrations; see [identity and audit operations](OPERATIONS.md#database-tls-oidc-sign-in-and-audit-management).

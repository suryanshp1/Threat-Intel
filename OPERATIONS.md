# Operations

## Storage and upgrades

PostgreSQL is the source of truth. API/worker startup applies idempotent migrations under a database advisory lock. Import pages and checkpoints commit together. Before an upgrade, back up the database and retain the previous image. Test upgrades against a restored copy first; schema changes are not automatically reversible. The old demonstration snapshot is deliberately not imported into the intelligence tables. Existing local VEX documents are preserved.

```sh
node scripts/backup.mjs
```

Backups are custom-format PostgreSQL dumps written under ignored `backups/` with restrictive permissions. Copy them to your encrypted backup storage with a retention policy. They include local VEX and audit data; feed caches are disposable. Back up `.env` separately in a secrets manager.

Restore to a **new empty database** first, using the correct admin role for your deployment:

```sh
docker compose exec -T postgres createdb -U sentinel -O sentinel_app sentinel_restore
docker compose exec -T postgres pg_restore -U sentinel -d sentinel_restore --no-owner --role=sentinel_app < backups/YOUR_BACKUP.dump
```

Inspect the restored database and verify record counts before changing a deployment's DATABASE_URL. Never restore over an active database. `docker compose down` retains named volumes; `down --volumes` destroys them and is only appropriate for disposable test stacks.

## Credentials and access

`VI_API_TOKEN` is a single operator secret (minimum 32 characters in production). Rotation requires replacing it in the secret environment and restarting the API; sessions are namespaced by its hash and old sessions cease to authenticate. Valkey stores session handles, not the raw operator token. Sessions expire after eight hours. Logout durably revokes the current session in the database before reporting success, even if Valkey cleanup fails. A failed durable write or unavailable session store returns 503 and the UI offers retry. Production requires HTTPS for Secure cookies.

`POSTGRES_PASSWORD` is the database admin credential; `VI_DB_PASSWORD` belongs to `sentinel_app`, which owns application schema objects but has no superuser/create-database/create-role privileges. Changing an environment variable alone does not rotate an existing PostgreSQL role password; rotate the role inside PostgreSQL in a controlled session and update app secrets together. Do not expose PostgreSQL or Valkey to public networks. Base Compose uses plaintext database transport on its private Docker network; remote deployments must enable the verified TLS connector described in the database TLS section below.

`VI_PUBLIC_ORIGIN` must match the browser's origin exactly. Public HTTPS overlay derives it from `VI_PUBLIC_HOST`. Cross-origin mutations are rejected. REST and GraphQL require authentication; distributed Valkey quotas fail closed when unavailable. Login attempts have a deployment-wide rate limit. There are no tenant boundaries or individual user roles in this release.

## Source operations

Data sources shows the last success, last-run count, status, and upstream error. Sync now creates a durable job; duplicate queued/running jobs for the same source are deduplicated. It does not bypass an upstream backoff. The worker polls every ten seconds and caps concurrent source runs at four.

HTTP 429/503 and provider outages are normal observable failures: wait for the persisted retry time, configure an optional free provider key, or investigate the upstream service. Do not replace missing results with fixtures. NVD backfill is gradual; EPSS and detection mappings cover the ingested subset, not every published CVE. MSRC begins with recent update documents, not a complete KB history. Ransomware names do not imply verified CVE attribution.

Graceful SIGTERM aborts active worker tasks and releases that worker's leases. After a hard kill, source leases expire after 15 minutes and abandoned queued jobs are recovered after their timeout. Checkpoints preserve already committed pages. Feed HTTP response bodies and expanded rule archives are bounded; rules are stored as references and never executed.

Vendor CSAF/OpenVEX imports require files under `VI_VEX_IMPORT_DIR`. Supply that directory from a publisher verification process. The current importer does not establish signatures or publisher identity. Leave `VI_TRUST_LOCAL_VEX=false` unless your operator process explicitly accepts locally authored statements. Do not present this option as signature validation.

### CWE, OWASP, and patch evidence

`MITRE CWE` and `OWASP Top 10` refresh weekly through the existing worker, source status, leases, cache, and backoff. CWE uses the official `/api/v1/cwe/weakness/all` JSON endpoint. OWASP discovers exactly ten 2025 English category Markdown documents from its official GitHub directory, then parses only the explicit mapped-CWE sections. Missing/malformed documents fail the refresh and retain the last complete snapshot. No new credentials or configuration are required; GitHub's unauthenticated quota still applies to the directory request.

```sh
node scripts/run-worker.mjs --once --source 'MITRE CWE'
node scripts/run-worker.mjs --once --source 'OWASP Top 10'
# Optional read-only upstream parser smoke test; does not import a database:
cargo test --manifest-path backend/Cargo.toml --locked -p vi-ingest official_knowledge_sources_smoke -- --ignored
# Independently verify OWASP if the CWE endpoint is unavailable:
cargo test --manifest-path backend/Cargo.toml --locked -p vi-ingest official_owasp_sources_smoke -- --ignored
```

New NVD imports preserve explicit CWE assertions, their asserting source/type, and safe HTTP(S) references tagged `Patch`. Existing CVEs acquire these fields when NVD returns them again; the modified-window checkpoint is not reset and this upgrade does not trigger a full historical backfill. CVE evidence merges additively, so earlier source assertions remain historical evidence. Taxonomy snapshots replace only that source's taxonomy entities and mappings after the full download parses successfully. Source record counts include relationship entities.

Migration `0003_knowledge_sources.sql` expands the entity-kind constraint without deleting existing intelligence. Root and backend migration copies are kept identical for host and container builds. Existing CVE JSON remains readable; absent new fields default to empty arrays. Restart the API and worker after upgrading to apply the migration and register the new source checkpoints. `/api/knowledge/{id}` uses the existing API authentication. Relationship responses include `knowledge` when querying a CWE or OWASP category, including through MCP `get_relationships`.

### Vendor advisory web scrapers

Four additional sources run daily without credentials: `Apache HTTP Server` (2.4), `Apache Tomcat` (9.x, 10.x, 11.x), `OpenSSL`, and `curl`. Apache and OpenSSL use HTML parsing without a browser or JavaScript execution; curl uses its publisher-provided OSV-style JSON. The approved pages are listed in [SOURCES.md](SOURCES.md). This is a fixed-scope collector, not a general link crawler.

```sh
node scripts/run-worker.mjs --once --source 'Apache HTTP Server'
node scripts/run-worker.mjs --once --source 'Apache Tomcat'
node scripts/run-worker.mjs --once --source 'OpenSSL'
node scripts/run-worker.mjs --once --source 'curl'
# Read-only live parser verification; no database imports:
cargo test --manifest-path backend/Cargo.toml --locked -p vi-ingest official_vendor_sources_smoke -- --ignored --nocapture
```

Each source downloads one document, except Tomcat which reads three branch pages with a one-second pause between requests. Downloads and cached bodies are limited to 8 MiB, each request has a 45-second timeout, and redirects are restricted to the original HTTPS host (at most two redirects). Each run accepts at most 5,000 CVE assertions and commits only after every page parses. Conditional HTTP caching, worker leases and persisted backoff still apply. Empty or structurally changed pages fail visibly and do not erase existing intelligence. No arbitrary reference or fix URL is fetched.

CVE `remediation_evidence` preserves source title/description, product, branch where applicable, original affected ranges, source severity, fixed versions and release status with provenance. Released fixes may set the existing aggregate patch-availability signal, but never populate a global `fixed_version` or infer a PURL. Apache development/unreleased fixes remain planned evidence. Tomcat's minor branch is taken from each release heading (including historical 10.0 entries on the 10.x page); its non-vulnerability appendix is excluded. HTML severity labels are not converted to CVSS. Earlier assertions remain in the existing additive evidence history; this is not an authoritative deletion/retraction sync or a complete vendor/product catalog.

No additional schema migration is required: `remediation_evidence` is an additive field in existing CVE JSON, defaulting to an empty array for older records. Restart the API and worker to register the four new sources and expose the field through REST, MCP and exports. The existing UI's Data sources list uses the source registry automatically; no frontend layout changed.

### Direct CVE records, distribution fixes, and PoC references

Four sources require no new credentials. Restart the API and worker to register them; no schema migration, NVD checkpoint reset or bulk import is required. Older CVE JSON defaults `source_assertions` and `poc_references` to empty arrays. REST, MCP and JSON exports include these fields. The detail drawer's **Evidence** tab separates publisher dates from collection events, shows scoped remediation, and labels community links as unverified. Data sources displays each collector's coverage limits.

| Source | Schedule and coverage | Bounds |
|---|---|---|
| `CVE List V5` | Every five minutes, 50 records per run; starts with changes in the latest 24 hours of the official rolling delta log | 32 MiB index, 1 MiB per CVE, 20,000 pending IDs |
| `Debian Security Tracker` | Daily full publisher JSON; preserve source package/release status and literal fixed-version markers | 128 MiB document, 500,000 release assertions |
| `Ubuntu USN` | Hourly refresh of the newest 20 notices plus one historical 20-notice page; rolls over after the historical scan completes | Two 16 MiB pages, 50,000 package/CVE assertions per page, offset at most 100,000 |
| `Trickest PoC references` | Every ten minutes, next 50 catalog CVEs in ID order; repeats after the scan completes | 1 MiB per CVE index, 500 GitHub references per CVE |

All four reuse conditional caching, HTTPS with no redirects, worker leases, durable jobs and persisted backoff. Each run has a five-minute overall deadline. CVE and PoC records and Debian 250-CVE pages commit individually with their checkpoints; Ubuntu pages and its historical cursor commit together. A failure retains completed pages and never advances past an uncommitted record. Long historical scans are gradual; a successful run is not a completeness guarantee. In particular, a large catalog can take weeks to scan for PoC references.

Direct CVE records preserve the CNA and ADP containers, metadata, status and document provenance independently. CNA descriptions/scores fill missing aggregate fields without replacing already populated display fields; source assertions remain available in exported JSON. Rejected records retain their source status and do not delete other evidence or automatically alter priority. The rolling delta history is not a full historical corpus: a checkpoint older than retained history fails visibly. Backfill/restore the missing interval before an operator deliberately resets that checkpoint; the collector does not silently skip gaps. Each pending window is frozen in the database so restarts can resume it.

Debian fixed-version `0` is retained as the publisher's marker, not a patch version. No dpkg version strings are normalized or compared as semantic versions. Ubuntu's notice lists packages and CVEs at advisory scope; the collector preserves that scope instead of claiming that every package fixes every listed CVE. It does not set global patch availability from these associations. Neither collector creates guessed PURLs or a universal `fixed_version`. An exact asset applicability engine is follow-on work.

Trickest's GitHub section includes research and detection projects as well as potential PoCs. Links never set `exploit_available`, `weaponized`, `seen_wild` or `is_zeroday`. Only fixed repository paths are downloaded; reference targets and code are never fetched or executed. Missing index pages are checkpointed as absent; earlier links remain historical evidence rather than being silently removed. Repeated unchanged assertions are deduplicated even when their containing page or retrieval timestamp changes; record-level provenance retains document observations.

```sh
node scripts/run-worker.mjs --once --source 'CVE List V5'
node scripts/run-worker.mjs --once --source 'Debian Security Tracker'
node scripts/run-worker.mjs --once --source 'Ubuntu USN'
node scripts/run-worker.mjs --once --source 'Trickest PoC references'
# Optional read-only parser verification; no database imports:
cargo test --manifest-path backend/Cargo.toml --locked -p vi-ingest official_expansion_sources_smoke -- --ignored --nocapture
```

See the [implementation plan](docs/intelligence-expansion-plan.md) for the first release and follow-on proposals. Public availability does not relicense publisher data or linked repositories; retain [upstream attribution](SOURCES.md).

## Security upgrade and scoped clients

Restart/rebuild the API and worker after upgrading. Migration `0004_security_controls.sql` adds session revocation tombstones, VEX revision history and query indexes; it preserves existing intelligence, VEX documents and credentials. It is additive/idempotent and applied under the existing startup migration lock. VEX revisions store sensitive before/after documents with the credential identity; include them in normal protected backups. API writes remain attributed to `operator` for the existing operator session/token, or to the configured client ID. Ingestion enqueue events are also audited.

### Create and revoke an integration key

Use `npm run setup` to create the private `backend/data/auth` directory before starting the API container. Alternatively create that directory yourself with owner-only permissions. The Compose API mounts it read-only and reads `clients.json`. Host development needs `VI_CLIENT_TOKENS_FILE=backend/data/auth/clients.json` in `.env` before launching the API. Do not mount client secret output files into the server container.

```sh
node scripts/client-token.mjs --id analyst-reader --scopes read \
  --expires 2027-01-01T00:00:00Z \
  --config backend/data/auth/clients.json \
  --token-file backend/data/analyst-reader.token
```

Choose your own future expiry. The token file is created exclusively with mode 0600; its contents are never printed by the utility. The registry contains only SHA-256 fingerprints, client IDs, scopes and expiry timestamps. Configure the private token value in your MCP client's Authorization header; for the stdio bridge, put that value in the client-side `VI_API_TOKEN` environment variable. Keep the server's existing operator token unchanged.

Supported scopes:

| Scope | Access |
|---|---|
| `read` | Read/search REST, GraphQL, exports and all nine read-only MCP tools, including stored VEX evidence |
| `analyze` | SBOM analysis; sends package identifiers to public OSV |
| `vex:write` | Create/update VEX documents; does not grant read or ingestion access |
| `ingest` | Enqueue source refreshes and read ingestion jobs |

Combine scopes explicitly, such as `read,analyze`. Keys expire at the configured timestamp and cannot be used for browser login. At most 100 clients are supported. The registry must be a valid array under 64 KiB; malformed configuration fails client authentication closed while the operator credential remains usable.

```sh
node scripts/client-token.mjs --revoke --id analyst-reader \
  --config backend/data/auth/clients.json
```

Registry removal takes effect on the next request on every API replica reading that registry; already-running requests may complete. Distribute the updated registry to every host in a multi-host deployment. The operator secret still rotates through the existing environment/restart procedure. Shared principal limits follow the client ID rather than the session cookie.

### Login, revocation and proxy configuration

Rejected browser Origins are checked before login accounting. Invalid credentials have a 20/minute per-client-IP failure budget. Correct credentials do not share that anonymous failure budget; successful operator session creation has its own 20/minute deployment allowance. Session fingerprints are revoked for eight hours in PostgreSQL; expired tombstones are cleaned during subsequent logouts. Valkey failures cannot silently restore a successfully revoked session after restart. Private API/session responses carry `Cache-Control: no-store`.

`VI_TRUSTED_PROXIES` optionally lists exact, comma-separated proxy IPs. Without it, forwarded client addresses are ignored; failed logins behind one proxy share that proxy's failure budget, while valid credentials still work. Configure only the actual trusted proxy hops and preserve the forwarded chain; never trust a user-supplied header based on a broad Internet address range. Nginx appends its observed hop, and the API walks the chain from the trusted peer backwards. Tokenless mode requires `VI_ALLOW_UNAUTHENTICATED=true` and a loopback `BIND_ADDR`; production always requires the operator token and Valkey.

### Request and output budgets

REST and MCP enforce at most 30 filter conditions, 100 entries in an `in` filter, 512-byte search/filter strings, 4096-byte cursors and 100 results per page. Actor/product lookups use SQL pagination (`limit` up to 100, `skip` up to 10000); the actor UI follows bounded pages. VEX listing also supports `limit`/`skip` and reports `truncated`. Rules/relationship responses return up to 100 links with a `truncated` flag. KB traversal is capped at 100 nodes/results. VEX writes are limited to 128 KiB, 100 statements and 100 products per statement.

Each API process admits up to 16 concurrent requests, with at most two analyses and two bulk exports. Permits remain held until response consumption/drop. A request, including streaming output, has a 60-second deadline; ordinary responses have a 16 MiB body budget and bulk NDJSON exports 128 MiB. Exceeding a streaming budget terminates the response with an error, not a successful complete export. Use paginated catalog queries for larger/resumable exports. Per-principal quotas are 1000 units/minute: ordinary calls cost 1, analysis/ingestion cost 100, and bulk export costs 50. Deployment resource limits are 1 CPU/1 GiB for the API and 2 CPU/2 GiB for the worker; tune through an explicit Compose override after measuring your catalog.

OSV analysis has a 45-second overall deadline, at most 500 findings, five continuation tokens per package and 50 continuation pages overall. Repeated tokens fail the analysis. Detail documents and query-batch responses are limited to 1 MiB each, with 8 MiB total distinct details and 8 MiB normalized upstream output. The API returns an explicit failure when a budget is exceeded; split large manifests. In-flight requests to OSV are cancelled when their deadline expires. No successful partial clean result is inferred. Applicability lookup reads only relevant VEX candidates, with an explicit 1000-document cap.

### Browser, feeds and dependency checks

The legacy `/scalar` URL now serves a local searchable API reference. Its script is served by the API; the Nginx CSP permits only same-origin scripts. No CDN JavaScript is loaded. The shared feed/API fetcher refuses redirects, preventing credential forwarding or HTTPS downgrade. Update an upstream URL explicitly when a publisher moves it; source failure/backoff remains visible. The separately scoped vendor scrapers retain their two-hop same-host HTTPS redirect policy.

The API no longer depends on the unused Tantivy search crate. The standalone search crate is upgraded to Tantivy 0.27 / patched lru; HTML parsing uses scraper 0.27 and YAML detection parsing uses maintained serde-saphyr with explicit node/depth/alias/scalar budgets and no include/network features. CI runs npm audit and `node scripts/audit-dependencies.mjs` against OSV. Advisory service failures fail that check visibly; lockfiles and a zero-match scan are not guarantees against unknown vulnerabilities. Container-layer scanning and production load/TLS checks remain separate operator responsibilities.

The optional monitoring overlay requires `GRAFANA_ADMIN_PASSWORD`; setup generates it without printing it. No default monitoring password remains.

## Logging & Monitoring

### Structured Logging & Tracing

Sentinel API (`vi-server`) and ingestion worker (`vi-worker`) emit structured telemetry using `tracing` and `tracing-subscriber`:

- **Log Level**: Controlled via standard `RUST_LOG` environment variable (e.g., `RUST_LOG=info`, `RUST_LOG=debug,tower_http=trace`). Defaults to `info`.
- **Output Formats**:
  - `VI_ENV=production` or `LOG_FORMAT=json`: Emits structured JSON events to `stdout`/`stderr` with timestamps, spans, target, status codes, and error traces. Suitable for ingestion into Loki, Vector, Fluentbit, or Datadog.
  - Development mode (`VI_ENV=development`): Emits compact, human-readable terminal output.
- **Request Tracing**: Inbound HTTP requests extract or assign a unique `X-Request-ID` UUID header, log request completion duration in milliseconds, and echo `x-request-id` in response headers for end-to-end audit tracing.

### Health & Metrics Endpoints

- `/health`: Fast unauthenticated process liveness probe (`{"status":"ok","version":"0.1.0"}`).
- `/readyz`: Infrastructure readiness probe validating active PostgreSQL and Valkey connectivity; returns `503 Service Unavailable` if backing stores are offline.
- `/api/metrics`: Authenticated Prometheus exposition format 0.0.4 endpoint exposing:
  - **RED Metrics**: `sentinel_http_requests_total{method, path, status}` with parameterized path masking (e.g. `/api/vulnerabilities/:id`) to prevent Prometheus label cardinality explosion.
  - **Latency Histograms**: `sentinel_http_request_duration_seconds_bucket{le=...}`, `_sum`, `_count`.
  - **In-flight Requests**: `sentinel_http_requests_in_flight` gauge.
  - **Component State**: `sentinel_service_ready`, `sentinel_db_ready`, and `sentinel_security_ready` gauges.
  - **Catalog & Feed Metrics**: `sentinel_vulnerabilities`, `sentinel_cisa_kev_total`, `sentinel_source_healthy{source=...}`, and `sentinel_source_records{source=...}`.

### Turnkey Prometheus & Grafana Monitoring

To launch the integrated local monitoring stack:

```sh
docker compose -f compose.yaml -f compose.monitoring.yaml up -d
```

- **Prometheus**: Runs at `http://localhost:9090`, scraping `/api/metrics` every 15s using `VI_API_TOKEN`. Includes rules in `deploy/monitoring/alert_rules.yml` for API outages, DB disconnections, 5xx error spikes (>5%), P99 latency spikes (>2s), and degraded feed sources.
- **Grafana**: Runs at `http://localhost:3001` (administrator credentials from your environment), pre-provisioned with the "Sentinel Threat Intelligence Overview" dashboard (`deploy/monitoring/grafana/dashboards/sentinel-overview.json`).


## Database TLS, OIDC sign-in and audit management

Migration `0005_identity_audit.sql` adds local identity users and fingerprint-only SSO sessions, plus audit indexes. It is additive/idempotent; existing operator sessions, client registries, intelligence and VEX history are retained. User role changes use an optimistic version check. Take a protected backup before upgrading; new tables contain provider subjects and display labels and belong in the same protected backup policy.

### Verified PostgreSQL TLS

For a remote database, set `VI_DB_TLS_MODE=verify-full` on **both the API and worker** and use a DNS hostname matching the server certificate in `DATABASE_URL`. The connector requires TLS, validates the certificate chain and hostname, and never falls back to plaintext. It trusts system CA roots by default. Set `VI_DB_TLS_CA_FILE` to a readable PEM CA bundle for a private CA; that bundle replaces system roots. Missing/empty/invalid bundles fail startup. There is no insecure-certificate option, `verify-ca` mode or TLS client-certificate authentication in this implementation.

The supplied local Compose database does not enable server TLS. Base Compose explicitly uses `disable` inside that private network. Setting only `.env` does not replace its hardcoded private database URL or TLS mode: use an override for a remote database, for example:

```yaml
services:
  vi-api:
    environment:
      DATABASE_URL: ${DATABASE_URL:?Set the remote restricted-role URL}
      VI_DB_TLS_MODE: verify-full
      VI_DB_TLS_CA_FILE: /etc/sentinel/db/ca.pem
    volumes:
      - ./deploy/local-db-ca.pem:/etc/sentinel/db/ca.pem:ro
  vi-worker:
    environment:
      DATABASE_URL: ${DATABASE_URL:?Set the remote restricted-role URL}
      VI_DB_TLS_MODE: verify-full
      VI_DB_TLS_CA_FILE: /etc/sentinel/db/ca.pem
    volumes:
      - ./deploy/local-db-ca.pem:/etc/sentinel/db/ca.pem:ro
```

Keep private certificates/keys outside version control and never commit a real connection URL. Omit the CA environment/mount for public system roots. Retain the restricted application role and provision its schema ownership on the remote database. URL `sslmode=require` without `VI_DB_TLS_MODE=verify-full` is rejected rather than silently disabling encryption. The environment setting controls transport; libpq `verify-full` URL options are not supported by this driver.

Run `node scripts/test-database-tls.mjs` for a disposable TLS-enabled PostgreSQL container with generated test certificates. It verifies encryption, successful trusted-host connections, wrong-hostname rejection and untrusted-CA rejection. It requires Docker and OpenSSL and removes only its own container and temporary files.

### Register a browser SSO client

Configure an OIDC confidential web application at your identity provider. Enable authorization code flow, S256 PKCE, `client_secret_basic`, and `openid profile` scopes. Register exactly:

```text
https://YOUR_HOST/api/auth/oidc/callback
```

Set these server-side settings and rebuild/restart the API:

```text
VI_PUBLIC_ORIGIN=https://YOUR_HOST
VI_OIDC_ISSUER=https://YOUR_PROVIDER/EXACT_ISSUER_PATH
VI_OIDC_CLIENT_ID=YOUR_REGISTERED_CLIENT_ID
VI_OIDC_CLIENT_SECRET=YOUR_PRIVATE_CLIENT_SECRET
```

Issuer must exactly match discovery and signed ID tokens. Production requires HTTPS for issuer, authorization, token, JWKS and callback URLs. The provider must publish RS256, PS256 or ES256 signing keys; encrypted/HMAC ID tokens and unsupported critical JWT headers are rejected. No UserInfo request or refresh token storage is used. OIDC browser sign-in does **not** turn Sentinel into an OAuth authorization server for MCP clients; use existing scoped integration keys for those clients.

Sign-in start is limited to 20 requests per observed client IP per minute and 100 across the deployment; configure trusted proxies for shared gateways. These SSO-start budgets do not block operator recovery login. Sign-in uses a five-minute, single-use, browser-bound state entry in Valkey plus S256 PKCE and nonce verification. Signature, issuer, audience/authorized party, expiry/not-before/issued-at and access-token hash (when present) are verified. Provider requests reject redirects, have ten-second deadlines and a 1 MiB response limit. Discovery/JWKS are retrieved for each login so rotated keys are refreshed without a server restart. Local sessions expire at the earlier of the ID token expiry or eight hours; expiration requires sign-in again. Temporary callback cookies use SameSite=Lax; application session cookies retain SameSite=Strict. Browser sign-in does not save provider access/refresh/ID tokens or the client secret in the browser or database.

For local HTTP testing only, use loopback provider and public-origin URLs with `VI_ENV=development` and `VI_OIDC_ALLOW_HTTP_LOOPBACK=true`. Production ignores that opt-in. The dev launcher sets the callback origin to `http://localhost:5173`, which must also be registered if you use it. Use one hostname consistently during a browser flow. Use provider/system CA trust for OIDC HTTPS; the database CA setting applies only to PostgreSQL.

The API requires PostgreSQL, Valkey and the existing operator recovery token when SSO is configured. An unavailable provider does not prevent operator login. Keep the recovery token private; do not give it to regular users.

### Approve users and assign roles

After a first verified SSO sign-in, a user is stored as **pending** and receives no session. Sign in as the operator and open **Audit & access → Users & sessions**. Confirm the displayed issuer and immutable provider subject with your identity-provider administrator before approving the user; display names are informational, not authorization evidence. Sentinel IDs are stable hashes of issuer and subject, so email/name changes do not transfer access. Role assignments are local and are never inferred from provider groups, email domains or self-asserted roles.

| Role | Permissions |
|---|---|
| pending | No application access |
| reader | Read/search intelligence, VEX evidence and exports |
| analyst | Reader plus OSV analysis and VEX writes |
| auditor | Reader plus audit events and VEX before/after history |
| admin | All of the above plus ingestion, user roles and session revocation |
| operator | Recovery/bootstrap administrator through the existing server token |

The API resolves current access on every session request. Ordinary role changes apply on the next request. Disabling a user or returning them to pending also revokes existing sessions; enabling them again requires a new sign-in. Administrators cannot change their own role/disabled status: another administrator or the operator must do that. The operator remains available even if every SSO administrator is disabled. Role updates use `version`; a stale update returns 409 and requires refreshing the user list. In-flight authorized requests may finish.

Identity-provider disabling alone is not immediate local logout: disable the local user/revoke sessions for immediate offboarding, or wait for the bounded local session expiry. Removing/changing the configured issuer rejects sessions belonging to the old issuer. Signing out revokes the local session; it does not terminate the provider's browser session or other applications. Provider-wide logout, SCIM, IdP group mapping, SAML and tenant isolation are not implemented. This is one shared intelligence workspace; reader access includes stored private VEX evidence and exports.

### Review activity and revoke sessions

**Audit & access** provides exact action/identity filters, cursor-paginated events, before/after VEX revisions and administrator-only user/session controls. Auditors cannot change users or revoke sessions. Revoking a session persists a tombstone before success; cache cleanup is not required for enforcement. Session IDs shown to administrators are fingerprints, never usable cookies. The UI manages SSO sessions; operator token rotation and integration-key revocation still use the deployment procedures above.

Protected endpoints:

- `GET /api/auth/me`: current identity, role and capabilities.
- `GET /api/audit/events?limit=50&before=ID&action=ACTION&subject=IDENTITY`: auditor/admin event pages, maximum 100.
- `GET /api/audit/vex-revisions?document_id=ID&limit=5&before=REVISION`: auditor/admin history, maximum 10.
- `GET /api/admin/users?limit=50&after=IDENTITY`: administrator user pages, maximum 100.
- `PUT /api/admin/users/{id}` with `{role,disabled,version}`: administrator access update.
- `GET /api/admin/users/{id}/sessions` and `DELETE /api/admin/sessions/{fingerprint}`: administrator session listing/revocation.

Successful operator/SSO session creation, verified SSO identities, local logout, role changes, administrative revocations, VEX writes and ingestion enqueue actions are recorded. Rejected SSO callbacks produce a sanitized reason in structured operational logs, without codes or tokens. Nginx access logs omit query strings and callback-specific proxy error logging is disabled to protect callback codes; API rejection categories and path/status access logs remain available; configure any additional gateway/observability layer the same way. Do not enable request-body/token logging.

Audit APIs offer no edit/delete operation. The application database owner can still alter records; this is application history, not a tamper-proof compliance ledger. There is no automatic audit retention/deletion or external log export policy. Apply protected backups, restricted database access and an external immutable audit sink if required. A durable logout still revokes access if its later audit append fails; that append failure is logged. File-mode development does not persist identity users or audit events; use PostgreSQL for this feature.

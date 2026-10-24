# Sentinel application security audit — 19 October 2026

## Scope and limits

White-box review of the current working tree, including uncommitted source additions. Reviewed API authentication/session handling, REST/GraphQL/MCP authorization and validation, database access, ingestion/download controls, frontend rendering and deployment/CI configuration.

Runtime probes used a temporary loopback API with a temporary file store and a disposable Valkey container. The API ran in development mode with a fresh random operator token and Valkey enabled. The login counter and Redis session-revocation paths under test are shared with production; this was not a test of the full production proxy/TLS deployment. No real credentials, application database, source imports or user inventories were used. Temporary services and test data were removed. Application code was not changed by this audit.

Dependency checks queried npm audit for the frontend lockfile and OSV for all 402 registry package/version entries in Cargo.lock. Lockfile matches are not proof of exploitability. No production load test, browser exploit, deployed-host scan, container image scan or complete fuzzing campaign was performed. The earlier implementation test runs are not presented as new penetration-test coverage.

## Priority summary

| ID | Priority | Evidence | Improvement |
|---|---|---|---|
| SA-01 | Medium | Runtime reproduced | Prevent anonymous requests from globally exhausting login allowance |
| SA-02 | Medium | Runtime reproduced under a Valkey command failure | Make logout accurately report and reliably complete session revocation |
| SA-03 | High for exposure to untrusted authenticated clients | Code review; validation discrepancy reproduced | Bound request cost, database materialization and upstream SBOM work |
| SA-04 | Medium, conditional on third-party script compromise | Source and HTTP response verified | Remove floating same-origin CDN script trust |
| SA-05 | Medium dependency hygiene; remote exploitability unproven | Live advisory matches and dependency graph | Remove unused vulnerable dependency paths and replace unmaintained parsers |
| SA-06 | Medium, conditional on upstream redirects | Source/library review | Apply destination and credential rules to every feed client |

Priorities reflect this app's deployment and trust boundaries, not computed CVSS scores. SA-03 through SA-06 include risks with explicitly stated preconditions; they are not four demonstrated remote compromises.

## SA-01 — Anonymous requests can block all new logins

Evidence: `backend/crates/vi-api/src/security.rs:190-203`.

The login handler describes its throttle as per-IP, but its Redis key contains only a fingerprint of the operator token. Every client shares one counter. The increment also happens before Origin validation. With Valkey configured, anonymous requests rejected with HTTP 403 still consume the global limit of 20 attempts per 60-second counter window.

Reproduction: in the isolated instance, obtain one valid test login, then submit 21 invalid-token login requests with a rejected Origin. Responses transition from 403 to 429. A subsequent correct-token login from the approved Origin returns 429. No valid token was needed for the requests that consumed the budget. Existing authenticated sessions continue to work; the demonstrated impact is denial of new logins, not account takeover.

Fix: validate Origin before counting browser requests; use per-client limits with a deliberate, bounded deployment-wide backstop. Behind Caddy/Nginx, accept client-IP information only from explicitly trusted proxies, rather than trusting arbitrary forwarded headers. Add regression coverage proving one client's rejected requests do not block another client's valid login.

## SA-02 — Logout succeeds even when session deletion fails

Evidence: `backend/crates/vi-api/src/security.rs:246-276`.

Redis connection and DEL errors are ignored. The handler clears the browser cookie and returns HTTP 200 with `authenticated:false`, although the server-side session may remain valid until its eight-hour expiry.

Reproduction: create a test session, deny only the DEL command in the disposable Valkey's ACL, and log out. Logout returns 200; replaying the original cookie against `/api/stats/` also returns 200. Re-enable DEL and repeat logout: replay returns 401. A stolen cookie is not created by this bug; the risk is that a previously copied cookie remains usable after a logout that appeared successful.

Fix: distinguish cookie removal from confirmed server-side revocation. Return an error when revocation cannot be confirmed, and provide a reliable revocation/retry mechanism or a fail-closed session epoch strategy for datastore outages. Never log the raw session. Test command-denied, connection-failed and recovery cases.

## SA-03 — Authenticated request cost is insufficiently bounded

Evidence:

- `backend/crates/vi-api/src/main.rs:65-159`: REST validates types/operators, but imposes no application-level count cap on filter conditions or `in` array entries and no text length cap.
- `backend/crates/vi-api/src/mcp.rs:16-20`: MCP advertises a 30-condition maximum. Runtime: REST accepts 31 conditions with HTTP 200 while the equivalent MCP call returns error -32602. The 31-condition request itself is small; it demonstrates unequal enforcement, not a measured outage.
- `backend/crates/vi-db/src/lib.rs:390-417`: entity/VEX readers materialize all rows before handlers filter them.
- `backend/crates/vi-api/src/main.rs:484-508`: rules and relationships fetch entire entity kinds for a single identifier. Actor/product/KB handlers also load complete entity sets before slicing responses.
- `backend/crates/vi-ingest/src/lib.rs:254-299`: the 1,000-PURL SBOM input limit does not cap total advisory detail fetches, output size or pagination. Pagination has no maximum page count or repeated-token check. Each individual request has a timeout, but the complete analysis has no overall deadline.
- Router assembly has a body-size limit but no endpoint concurrency semaphore or total handler deadline. The deployment applies no CPU/memory resource limits to the main API/worker services.

Impact: an authenticated client can invoke expensive queries or long-running analysis repeatedly, consuming memory, database capacity and upstream quotas. Giving an external MCP client the operator credential also gives it access to these REST routes. A complete denial of service was not attempted against a populated catalog.

Fix: enforce one shared validation policy in the handlers, including maximum conditions, array sizes, text/cursor lengths and output sizes. Push filtering/pagination into indexed SQL queries instead of fetching every entity. Add route-specific concurrency limits and request budgets, plus per-client/per-principal weighted quotas for analysis, exports and syncs. Bound OSV pages, advisory counts, repeated page tokens and total elapsed time; move large analysis into bounded jobs. Keep existing SQL statement timeouts and add container limits. Validate these controls with small fixtures before capacity testing.

## SA-04 — Floating CDN JavaScript runs on the authenticated app origin

Evidence: `backend/crates/vi-api/src/main.rs:641-644` and `frontend/nginx.conf:11`.

The unauthenticated `/scalar` page loads `https://cdn.jsdelivr.net/npm/@scalar/api-reference` without a pinned version or integrity attribute. The Nginx CSP allows JavaScript from that CDN across the application origin. HTTP verification confirmed the floating script URL and missing integrity attribute.

If that dependency/CDN-delivered script were compromised, its code would execute on Sentinel's origin. HttpOnly prevents JavaScript from reading the session cookie, but does not stop same-origin JavaScript from using that cookie for authenticated API calls. This is a conditional supply-chain risk; no malicious script or XSS payload was introduced.

Fix: bundle/self-host a reviewed, pinned Scalar build and restrict the main app's script policy to self. Alternatively isolate API documentation on an origin without operator cookies. Where remote scripts are unavoidable, pin versions and integrity hashes and scope the policy narrowly. Reference: [OWASP third-party JavaScript guidance](https://cheatsheetseries.owasp.org/cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.html).

## SA-05 — Rust dependency matches need remediation and reachability review

Live results:

| Locked package | Dependency path | Result and interpretation |
|---|---|---|
| `lru 0.12.5` | `vi-api → vi-search → tantivy 0.25.0 → lru` | Matches RUSTSEC-2026-0002 / GHSA-rhfx-m35p-ff5j (same issue), and RUSTSEC-2026-0253. Both are reported soundness/memory-safety issues. |
| `fxhash 0.2.1` | `vi-ingest → scraper 0.24.0 → selectors → fxhash` | RUSTSEC-2025-0057: unmaintained. This dependency arrived with the new HTML scrapers; not evidence of an app exploit. |
| `unsafe-libyaml 0.2.11` | `vi-ingest → serde_yaml 0.9.34+deprecated → unsafe-libyaml` | RUSTSEC-2024-0449: unmaintained. Relevant because downloaded detection content is parsed as YAML. |

The active catalog routes use PostgreSQL; source search found no `vi_search` call site in the API. Therefore the lru lockfile matches are not established as reachable from a remote request. The second lru issue requires particular panic/drop/unwinding behavior, which was not demonstrated here. Do not describe these matches as confirmed remote code execution.

Fix: remove the unused `vi-search` dependency from the API if it is unnecessary, or upgrade the search dependency chain to one resolving the lru advisories. Replace deprecated YAML parsing with a maintained implementation suitable for untrusted input. Update/review the scraper dependency tree to eliminate unmaintained components. Gate CI on reviewed RustSec/OSV and npm results, with explicit, expiring exceptions when reachability justifies them. Include image scanning and pinned build inputs.

Primary records: [lru iterator issue](https://rustsec.org/advisories/RUSTSEC-2026-0002.html), [lru panic-safety issue](https://api.osv.dev/v1/vulns/RUSTSEC-2026-0253), [fxhash maintenance notice](https://rustsec.org/advisories/RUSTSEC-2025-0057.html), [unsafe-libyaml maintenance notice](https://api.osv.dev/v1/vulns/RUSTSEC-2024-0449).

The npm audit returned zero known advisories for the frontend lockfile at review time. This does not cover container packages or prove absence of unknown issues.

## SA-06 — Legacy feed client redirect policy is weaker than the new scrapers

Evidence: `backend/crates/vi-ingest/src/lib.rs:32-58`, `backend/crates/vi-ingest/src/adapters.rs:203-214`, and the locked reqwest 0.12.28 redirect implementation.

The shared Fetcher only checks the initial URL for HTTPS and allows four redirects without a destination-host restriction. NVD supplies an `apiKey` custom header. Reqwest strips its standard sensitive headers on cross-host redirects, but that custom header is not among the stripped headers. A redirect controlled by an upstream service could therefore move a fetch outside the intended origin and potentially disclose that provider key. This is not a demonstrated user-controlled SSRF endpoint: callers normally use fixed URLs and this attack needs control of an upstream redirect or equivalent infrastructure.

The new vendor scraper client already restricts redirects to the original HTTPS host. Extend that protection to legacy feed paths, allowing only specific documented redirect destinations when needed. Bind provider credentials to their exact origin, revalidate each redirect, and apply egress restrictions to internal/metadata destinations. Test with fake provider keys and controlled local test servers; no real provider key was used during this audit. Reference: [OWASP SSRF prevention guidance](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html).

## Additional design and deployment improvements

These are contextual hardening items rather than newly demonstrated auth bypasses.

1. **Scoped, revocable client credentials before wider MCP use.** The single operator token deliberately authorizes all REST operations, including VEX writes and ingestion. MCP's read-only tool catalog does not restrict the credential itself. Add distinct read-only, analysis, VEX-write and ingest/admin scopes, expiration and individual revocation. Retain the current documented single-operator limitation until implemented.
2. **Better audit identity and history.** VEX writes are recorded as `authenticated-analyst`; existing VEX data can be replaced by document ID. Record credential/principal IDs, before/after hashes and document versions, plus login/revocation/admin events. Do not log secrets, session cookies or private inventories.
3. **Require an explicit Grafana secret.** `compose.monitoring.yaml:36-37` falls back to `admin` / `sentinel`. The service is loopback-bound, so this is not proof of Internet exposure. Remove the password fallback and prevent proxying it publicly without authentication/TLS review. Pin/review the monitoring image versions and scan them; this audit did not scan their layers.
4. **Keep database transport assumptions explicit.** `vi-db` uses PostgreSQL `NoTls`. The private local Compose network is the documented trust boundary. Require certificate-verified TLS before supporting a remote database; separate migration/schema-owner privileges from routine runtime access where practical.
5. **Disclose SBOM egress at submission.** Analysis sends package identifiers/versions to public OSV. Documented functionality, but a relevant privacy choice for private inventories. Provide a clear submission notice and an option for an approved proxy/offline workflow when required.
6. **Fail closed outside explicit local development.** Tokenless mode is allowed whenever the environment is not exactly `production`. The default API binds to loopback, and Compose sets production correctly. Require an explicit opt-in for unauthenticated mode and reject non-loopback binds without authentication.
7. **Protect sensitive response caching.** Add deliberate no-store policy for session/private inventory/VEX responses, plus session-activity visibility and targeted revocation.
8. **Maintain source trust separation.** Keep imported advisory/rule text inert and explicitly untrusted in MCP responses. Preserve source ownership and correction/retraction history so a later feed cannot silently change the apparent meaning of an earlier source assertion. Continue excluding unsigned VEX from suppression by default.

## Controls observed working

- Unauthenticated protected API request returned 401.
- Authenticated mutation with a rejected Origin returned 403.
- Unsupported SQL filter field returned 400; SQL values are parameterized and selectable fields/operators are allowlisted.
- Successful session deletion invalidated the original cookie (subsequent API request returned 401).
- Session tokens are random and stored by fingerprint; production cookies include HttpOnly, SameSite=Strict and Secure.
- GraphQL has depth/complexity limits; MCP has input schemas and a smaller body limit.
- Unsigned VEX suppression is disabled in the supplied Compose configuration.
- The main app containers use non-root users/read-only filesystems/capability drops; public database/cache ports are loopback-only in the development overlay.
- New vendor collectors have explicit URL sets, byte limits and same-host HTTPS redirects.

These observations are limited to the inspected code/configuration and the stated probes. No authentication bypass, SQL injection or remote code execution was demonstrated.

## Recommended order

1. Fix SA-01 and SA-02 with failure-path regression tests.
2. Add scoped credentials and the shared request-cost/concurrency controls in SA-03 before connecting less-trusted clients or exposing larger catalogs.
3. Self-host Scalar and resolve dependency warnings, starting with removal of unused dependency paths and deprecated YAML parsing.
4. Unify feed egress/credential handling, remove default monitoring secrets and add automated dependency/image checks.
5. Test the actual HTTPS proxy deployment, then perform bounded capacity testing and targeted parser fuzzing against deterministic fixtures.

## Remediation follow-up

The findings above describe the audited snapshot. Subsequent fixes and verification are recorded in the [security remediation plan](security-remediation-plan.md), with deployment instructions in [OPERATIONS.md](../OPERATIONS.md#security-upgrade-and-scoped-clients). All six findings have corresponding code/configuration remediations in the working tree; deployment-specific verification and the remaining design improvements are listed separately in that plan.

# Security remediation plan

This implements the 19 October 2026 audit against the current working tree, preserving the source expansions.

1. **Authentication/session reliability:** validate Origin before login accounting; isolate failed-client throttles without letting bad credentials block a valid login; persist session revocations before logout succeeds; regression-test Valkey failure and restart behavior.
2. **Client boundaries:** keep the operator credential compatible; add hash-only, expiring scoped client credentials with individual revocation and no privilege escalation through browser login; attribute sensitive writes to the credential identity.
3. **Resource budgets:** enforce shared filter/lookup limits, bounded SQL entity queries, bounded VEX candidates, endpoint concurrency/deadline limits, and finite OSV pagination/detail/result budgets. Keep failures explicit instead of returning a misleading partial clean result.
4. **Browser and outbound trust:** host API-reference scripts locally, tighten CSP, add no-store responses for sensitive endpoints, constrain feed redirects and provider credentials to their origins, and require an explicit monitoring password.
5. **Dependency and verification work:** remove unused API search dependencies; replace deprecated YAML parsing and upgrade the HTML parser tree; add advisory checks to CI; run deterministic and isolated production regression tests, builds, browser checks for visible changes, and read-only upstream smoke checks where download behavior changes.

The operator token remains an administrator credential. Existing unsigned VEX policy, upstream attribution, source hashes and additive evidence history remain in force. Deployment-dependent items (remote PostgreSQL TLS, production capacity testing, container-layer scanning and a full identity provider/RBAC system) will be reported separately rather than described as implemented.

## Implementation status — 19 October 2026

All five steps above are implemented in the working tree. See [OPERATIONS.md](../OPERATIONS.md#security-upgrade-and-scoped-clients) for migration, scoped credential creation/revocation, proxy configuration, request budgets and upgrade instructions.

- SA-01: rejected Origins do not consume login counters; invalid credentials cannot exhaust the valid-credential allowance.
- SA-02: logout persists a durable revocation before success; failed persistence returns an error and the UI keeps the session visible. Revocation survives cache deletion failure and API restart.
- SA-03: shared query limits, bounded SQL pagination, weighted principal quotas, streaming concurrency/deadlines/byte limits and finite OSV work budgets are enforced.
- SA-04: `/scalar` serves a local searchable reference with no CDN scripts; CSP restricts scripts to the same origin.
- SA-05: unused API search dependencies were removed; the standalone search and HTML parser dependencies were upgraded; YAML parsing was replaced and explicitly bounded. Advisory checks run in CI.
- SA-06: the shared fetcher rejects redirects; the vendor scraper retains bounded same-host HTTPS redirects.

Additional implemented controls include expiring hash-only scoped integration keys, client identity on VEX/ingestion audit records, VEX before/after revision history, explicit tokenless loopback mode, mandatory monitoring passwords, no-store API responses and the SBOM egress disclosure. Migration 0004 is additive and preserves existing documents; historical revisions start with writes after this upgrade.

## Verification

- Rust workspace tests: 35 passed, three optional live tests ignored; locked build and formatting passed.
- Frontend: 11 tests and production build passed.
- Disposable PostgreSQL/Valkey suite: 147 checks passed, including scope/expiry/revocation, login denial-of-service regression, durable logout failure paths and restart, pagination, VEX attribution and MCP access.
- Official vendor smoke check: all six documents parsed successfully without importing a database.
- Dependency checks: 406 Rust registry versions checked against OSV with zero matches; npm audit reported zero vulnerabilities.
- Credential utility smoke check: exclusive private token creation, 0600 file permissions, hash-only registry and revocation passed.
- Browser: local API reference search/expansion and SBOM privacy disclosure verified against an empty isolated instance; no browser console errors observed.

These checks do not replace a deployed HTTPS penetration test. Remaining deployment work includes verified remote database TLS, image scanning/pinning, capacity testing, parser fuzzing and identity-provider integration. Login/session activity history and a user-facing audit/revocation console remain future improvements; this change records VEX and ingestion write identity/history only. No production deployment or real catalog import was performed.

## Identity/TLS follow-up

Database TLS, OIDC SSO/local RBAC and audit management were subsequently implemented in the [identity and audit plan](identity-and-audit-plan.md). The remaining-work statements above describe the earlier remediation snapshot.

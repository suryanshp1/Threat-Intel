# Database TLS, SSO/RBAC and audit management

Implementation sequence:

1. Add PostgreSQL `verify-full` transport with system/custom CA roots, no insecure certificate bypass and configuration validation. Preserve explicit private-network plaintext mode for the existing Compose installation.
2. Add optional OIDC authorization-code SSO with PKCE, nonce, browser-bound single-use state, verified identity tokens and bounded HTTPS provider requests. Keep operator access for bootstrap/recovery.
3. Add persisted local role assignments: pending (no access), reader, analyst, auditor and admin. Resolve roles on every request; record identity on writes. New provider identities require approval. Scope integration keys independently.
4. Add additive identity/session schema and protected, paginated APIs for audit events, VEX revisions, user role changes and individual session revocation. Record administrative changes and session activity without tokens or inventory contents in logs.
5. Add SSO sign-in, current identity/capability-aware controls and an audit/access management screen using existing UI patterns. Verify regression tests, PostgreSQL/Valkey integration, TLS failure paths and browser workflows. Document provider registration, CA mounting, role policy and operational limitations.

Provider credentials and production certificates must be supplied by the operator. Implementation and fixture verification do not configure a real identity provider or deploy the application. Tenant isolation, SAML, provider-wide logout and an external immutable audit sink are outside this change.

## Completed — 20 October 2026

All five stages are implemented in the working tree. [OPERATIONS.md](../OPERATIONS.md#database-tls-oidc-sign-in-and-audit-management) covers provider registration, pending-user approval, roles, API endpoints, CA mounting and upgrade compatibility. OpenAPI includes identity/audit/administration endpoints. Migration 0005 preserves existing intelligence and credentials.

Verification:

- 225 disposable PostgreSQL/Valkey API checks passed. They exercise a local RSA-signed OIDC provider, PKCE, browser binding/replay rejection, invalid issuer/audience/nonce/expiry/not-before/issued-at/hash/signature/key/algorithm/critical headers, pending approval, role boundaries, version conflicts, disable/re-enable behavior, session revocation across restart, issuer removal, audit pagination and VEX identity/history.
- Session-store and audit-persistence failures return no cookie; failed creation does not record a successful login. Logout after account disabling retains the correct user attribution.
- Rust workspace: 38 passed, three optional upstream checks ignored. Locked build and formatting passed. Frontend: 11 tests and production build passed.
- A separate TLS-enabled PostgreSQL container proved encrypted connections with a trusted certificate and rejected wrong hostnames and untrusted CAs.
- OSV checked 437 Rust registry versions with no advisory matches. Candidate dependency paths with advisories were replaced; no advisory exceptions were added.
- Compose configuration and Nginx syntax passed. Callback query strings are excluded from access/error logs; API logs record safe rejection categories.
- Browser checks against a separate disposable database verified pending-user approval, saved roles, before/after VEX history, the complete SSO redirect flow, local sign-out, capability-aware navigation and the audit UI at desktop and 390 px mobile widths.

The integration harness also fixes a restart timer that could kill a newly started test process; its timeout now refers only to the original child and is cleared on exit.

No real catalog was imported or altered. Production deployment, registration with your actual IdP and installation-specific certificate configuration remain operator steps. Release container images were not built or scanned in this verification; the backend builder now explicitly installs CMake for the JWT cryptographic backend. Tenant isolation, SCIM/group mapping, SAML, provider-wide logout and an external immutable audit sink remain outside this implementation.

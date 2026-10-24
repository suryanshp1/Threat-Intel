# Security policy

## Scope and support

This policy covers vulnerabilities in Sentinel’s code, authentication, API, MCP interface, deployment configuration, and ingestion handling. The project is under active development and has no formal support SLA or long-term-support release policy. Fixes target the current default branch; backports are not guaranteed.

A CVE displayed by Sentinel is intelligence about an upstream product, not necessarily a vulnerability in Sentinel. Follow the original vendor’s disclosure process for flaws in those products.

## Report a vulnerability privately

Do not disclose exploit details, credentials, private SBOMs, database dumps, or sensitive logs in a public issue or pull request.

Use the repository’s **Security → Advisories → Report a vulnerability** option when private vulnerability reporting is enabled. If that option is unavailable, ask a maintainer for a private reporting channel without posting technical details. No dedicated security mailbox is configured in this source tree; repository operators should enable private reporting before publication.

A useful private report includes:

- The affected commit or version and deployment mode.
- A description of the issue and realistic impact.
- Minimal reproduction steps using non-sensitive test data.
- Relevant request/response examples with secrets removed.
- Any proposed mitigation and your preferred contact method.

Maintainers can coordinate reproduction, mitigation, and disclosure through that private channel. Do not assume a guaranteed response time, bounty, or embargo agreement.

## Deployment trust boundaries

Sentinel supports optional OIDC SSO with locally assigned human-user roles, an operator recovery credential and expiring scoped client keys. New SSO users require administrator approval; provider groups and email addresses do not grant access. This is one shared workspace without tenant isolation. The operator bearer token authorizes all REST actions, even when configured in a read-only MCP client. Use a separate `read` client credential for integrations and grant analysis/write/ingestion scopes only when required. Client keys cannot be exchanged for operator browser sessions.

Use the HTTPS deployment overlay for public access, keep PostgreSQL and Valkey private, protect `.env` and backups, and review [OPERATIONS.md](OPERATIONS.md) before operating an instance. Use certificate/hostname-verified PostgreSQL TLS for remote database connections as described there. Local development defaults are not a substitute for a deployment review.

Downloaded intelligence, advisory text, and detection references are untrusted content. They are not executable code or AI instructions. Unsigned local VEX does not suppress findings by default, and enabling local trust does not establish publisher identity or signatures.

## Dependency and release hygiene

Commit lockfiles, review automated dependency updates, run the verification suite, and back up data before upgrades. Do not attach environment files, credentials, private inventories, or database backups to bug reports or releases. The repository provides automated checks; it does not claim a formal security certification.

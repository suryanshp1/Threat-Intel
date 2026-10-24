# Roadmap

This roadmap describes opportunities, not delivery commitments. Discuss substantial work in an issue before starting. See [IMPLEMENTATION.md](IMPLEMENTATION.md) for the detailed scope matrix and [MCP.md](MCP.md) for the MCP design.

## Available today

- Continuous public-source ingestion with provenance, checkpoints, retries, and visible failures.
- PostgreSQL catalog search, typed filters, facets, and keyset pagination.
- CVE investigation, actor and ransomware profiles, affected package and KB lookup.
- Versioned-PURL SBOM analysis with live OSV matching and persisted OpenVEX statements.
- REST, GraphQL, OpenAPI, exports, and nine read-only MCP tools over HTTP or the stdio bridge.
- Expiring scoped client credentials, durable logout revocation, bounded request/analysis budgets, and VEX revision history.
- Verified PostgreSQL TLS, optional OIDC SSO with local RBAC, and an audit/user/session management screen.
- A responsive React workspace, local preferences, Docker Compose, and an HTTPS deployment overlay.

## Reliability and evidence quality

- Expand deterministic adapter fixtures and failure/recovery coverage.
- Improve historical backfill visibility and source coverage reporting.
- Benchmark bounded entity queries against a larger catalog.
- Exercise backup/restore, upgrades, and failure recovery on a repeatable schedule.
- Expand accessibility and browser regression coverage.

## Integrations and AI clients

- Per-client usage reporting and richer credential-management UI.
- OAuth discovery and authorization for hosted AI connectors.
- Newer MCP protocol revisions and a tested client compatibility matrix.
- Bounded SBOM tools with explicit outbound network controls.
- Generated API clients and fuller TAXII interoperability.

## Broader intelligence and trust

- Publisher identity and signature verification for vendor VEX/CSAF.
- More complete SSVC decision support and CVSS v4 computation.
- Broader historical KB/advisory coverage and verified actor attribution.
- Additional connectors where upstream access and licensing support them.

## Deployment evolution

- Tenant isolation, IdP group/SCIM integration, and provider-wide logout.
- External immutable audit export and retention management.
- High availability, monitoring integrations, and capacity testing.
- Release artifacts, supply-chain review, and a versioned support policy.

These items are not implemented unless explicitly marked as available. Proposals should preserve provenance, unknown-value semantics, bounded resource use, and the existing conservative VEX policy.

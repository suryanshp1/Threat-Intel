# Implementation and verification record

Updated 16 October 2026 against PRD.md and design.md.

The app now uses actual upstream intelligence and normalized PostgreSQL persistence. Production starts empty, and no sample intelligence is injected. The React dashboard retains the design reference's dark surfaces, locally hosted typography, restrained accents, and responsive tables. The requested frontend taste skill excludes dashboards; Tailwind 4 tokens and the existing application design system govern these screens.

## PRD scope matrix

| Area | Delivered | Remaining |
|---|---|---|
| Runtime | Five Rust crates; independent API and continuous worker; React 19 | Capacity and release supply-chain audits |
| Persistence | PostgreSQL domain tables, JSONB evidence, indexes, pooled connections, transactional checkpoints, advisory locking, leases, durable jobs | Multi-tenant isolation, large-corpus entity-query optimization |
| Search | SQL full-text GIN, typed filters, facets, deterministic keyset pagination, aliases and CVE/PURL search | Production Tantivy index (crate retained but DB is authoritative), million-record benchmarking |
| Scoring | PRD additive score, explicit unknown inputs, source CVSS/EPSS evidence | Full CVSS v4 computation and mission-specific SSVC decision trees |
| CVE UI | Live catalog, detail evidence, filters, browser preferences, real relationships, streaming NDJSON | Full legacy Strobes AST compatibility |
| Actors/ransomware | Official ATT&CK groups/techniques and RansomLook group names with provenance | Verified CVE attribution where upstream does not provide it |
| Packages/KB | Source CPE/PURL coordinates, GHSA affected/fixed ranges, recent MSRC KB/product mappings and bounded source supersedence traversal | Comprehensive historical KB and dual-coordinate resolver coverage |
| SBOM | CycloneDX/SPDX JSON, exact versioned PURLs, live OSV ecosystem-aware matching and advisory evidence | Reachability analysis and offline complete OSV mirror |
| OpenVEX | Validation, persistence, audit records, no default unsigned suppression | Publisher signature validation and full CSAF semantics |
| Sources | Twelve connector slots, eleven automatic public feed/repository adapters; explicit configuration requirement for vendor imports; retries, cache, bounds, checkpoints | ENISA/VulnCheck/deps.dev integrations, full historical backfill |
| Detection | Real Nuclei, Sigma, Suricata CVE mappings, upstream rule links | YARA and rule execution/validation engines |
| API | REST, GraphQL query, generated OpenAPI, Scalar, NDJSON stream, paginated STIX objects, nine read-only MCP tools with HTTP and stdio bridge | Full TAXII 2.1 conformance, generated client, scoped MCP credentials and OAuth |
| Security | OIDC SSO/local RBAC, recovery operator/scoped clients, durable sessions, audit/user/session UI, request budgets, restricted DB role | Tenant isolation, provider-wide logout/SCIM, immutable audit export, formal security assessment |
| Deployment | Non-root containers, read-only app filesystems, PostgreSQL/Valkey volumes, Caddy TLS overlay, verified PostgreSQL TLS, backup helper, CI | HA, automated restore drills and monitoring integration |

## Verification

The records below describe individual verification runs, not permanent test or corpus counts. The MCP addition subsequently passed 74 isolated production API checks, including discovery, all nine tools, authentication, origins, errors, pagination, and a stdio handshake/tool exchange. `npm test` now includes both Rust workspace and frontend unit tests.

- Rust workspace: 11 unit tests pass, covering score arithmetic, empty installation, source parsing, evidence merging, and scoped package identifiers.
- Frontend TypeScript/Vite production build passes.
- Production PostgreSQL/Valkey API suite: 40 checks pass in a disposable database, including auth/session/origin rejection, SQL filter validation, cursor paging, job deduplication, OpenVEX persistence, exports, GraphQL and process restart persistence.
- Live API/OSV check: 35,795 CVEs and 812 source-backed profiles at the recorded run; two actual findings for a vulnerable versioned package; no demonstration source labels.
- Upstream responses were exercised for CISA, NVD, EPSS, ATT&CK, RansomLook, GHSA, MSRC and rule repositories. NVD has intermittent upstream failures; checkpoints and visible error state retain partial progress.

- Browser checks: actual MITRE actor search resolves 93 APT28 technique links; live OSV SBOM analysis renders two findings. Overview, actor, sources and SBOM routes have no page overflow at 390px. A real MSRC KB lookup renders four product-specific update records. Ransomware search finds four LockBit-related groups from the complete paginated profile catalog. Screenshots are saved under `output/playwright/live-*`.
- Container checks: final API/worker/frontend images build. Fresh PostgreSQL creates the restricted application role and initializes an empty intelligence schema; Nginx API authentication and SPA routes pass. The hardened worker imports 1,746 real CISA records into the disposable stack; those records persist across replacement with the final images, which also create Secure sessions. The disposable containers and volumes were removed.
- Backup check: custom-format database backup restores into an isolated database with 26,746 CVEs; the temporary restore database was removed.

 The final MSRC reconciliation completes successfully with aggregated CVE lists per KB/product (up to 680 observed associations). Counts are snapshots, not corpus completeness claims. Deployment infrastructure and tested workflows do not imply that every enterprise PRD requirement or security certification is complete.

# Intelligence expansion implementation plan

The first release adds direct publisher records, distribution-scoped fixes, public PoC references, and an evidence timeline. Existing local work, authentication, VEX policies and source attribution remain in force. Follow-on items are proposals, not implemented capabilities.

## First release, in order

1. **CVE List V5:** scheduled, bounded collection of official CNA records with resumable checkpoints. Retain source assertions independently of aggregate display fields. Surface rejected records as source status without silently deleting other publishers' evidence. Expose coverage limits and fail visibly when the incremental history is insufficient.
2. **Debian and Ubuntu remediation:** consume publisher JSON rather than scrape rendered pages. Preserve distribution/release/package scope, original version strings and explicit fixes. Never compare Debian package versions with generic semantic-version logic or advertise one package's fix as a universal fix.
3. **Public PoC references:** use the Trickest CVE index for the ingested catalog, preserve reference provenance and explicitly label links as unverified. Never execute downloaded content or infer exploitation in the wild from a PoC link.
4. **Evidence timeline:** show dated publisher assertions, KEV additions and collection events separately, with links to the source. Include scoped remediation and PoC references in the existing detail drawer. Missing dates remain unknown.
5. **Verification:** deterministic parser/merge/UI-helper regressions, Rust and frontend checks/builds, disposable-database integration checks when services are available, and browser inspection at desktop and mobile sizes. Live parser checks are read-only and opt-in; no bulk import into the user's database is needed for verification.

## Follow-on releases

- Advisory-native identities and OpenSSF malicious-package reports, with alias resolution and withdrawal semantics across catalog, SBOM, REST, MCP and exports.
- Scheduled Red Hat/CISA CSAF collection, using fixed trusted publishers and explicit product status; publisher signature verification remains a separate trust feature.
- Metasploit module metadata, with independent exploit-module and confirmed-exploitation signals.
- Persistent watchlists and delivery subscriptions, including user ownership, retry/deduplication and configurable change thresholds.
- Inventory applicability using ecosystem-specific version semantics and explicit OS/distribution identity.
- Source disagreement/freshness views, historical EPSS observations, and evidence-linked summaries.

## First-release verification record

Steps 1–4 are implemented. All four public sources passed the opt-in read-only live parser check on 21 October 2026. The first live check exposed Ubuntu's maximum page size of 20; the collector now validates that page size and refreshes the newest page while advancing through historical notices.

Verification passed 45 deterministic Rust tests, 16 frontend tests, Rust formatting, the locked Rust build, the frontend production build, and 227 PostgreSQL/Valkey production API checks in a disposable database. Added coverage verifies source assertions, product-scoped version preservation, unverified PoC semantics, checkpoint persistence and failed-batch rollback, bounded keyset scans, old-record compatibility, HTTP evidence round-trips and restart persistence. Other pre-existing optional network suites were not run.

The Evidence tab was inspected at desktop and 390-pixel mobile sizes with an isolated synthetic fixture, with screenshots under the ignored `output/playwright/` directory. No bulk feed import or synthetic intelligence was added to the application's database. Existing local work remains uncommitted.

## Compatibility

New evidence fields live in existing CVE JSON and default to empty arrays on old records. No schema reset, NVD checkpoint reset or historical backfill is implied. New sources reuse the worker's leases, conditional cache, durable jobs and persisted backoff. Public data retains its publisher's terms; linked PoCs retain their own licenses. Incremental coverage and catalog-scoped PoC collection are not completeness guarantees.

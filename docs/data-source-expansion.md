# Data-source expansion plan

## Implemented steps

- [x] Audit existing feeds: NIST NVD, MSRC, OSV/GHSA, KEV and Vulnrichment already supply vulnerability and remediation intelligence.
- [x] Preserve NVD CWE assertions and explicit Patch-tagged HTTP(S) links, including source document hashes and retrieval timestamps. Emit CVE-to-CWE relationships without guessing from prose.
- [x] Add the official MITRE CWE weakness catalog as a weekly, bounded JSON import. Store complete upstream definition metadata, including source-provided mitigation content.
- [x] Add OWASP Top 10:2025 categories using the official Markdown documents. Parse mappings only from the explicit mapped-CWE section, validate all ten documents, and commit one atomic snapshot.
- [x] Add authenticated knowledge lookup and reuse REST/MCP relationships for CVE → CWE → OWASP navigation. Keep taxonomy content separate from vulnerability severity and product applicability.
- [x] Add an additive schema upgrade, deterministic parser/storage regression tests, an optional read-only live parser check, and operations/attribution documentation.

## Source selection

| Input | Retrieval | Evidence policy |
|---|---|---|
| NIST NVD | Existing CVE 2.0 API and incremental checkpoint | Keep source/type of CWE assertions and explicitly tagged patch references |
| MITRE CWE | Official REST `/cwe/weakness/all` | Store source definitions verbatim as untrusted data; do not execute examples |
| OWASP Top 10:2025 | GitHub directory plus ten official Markdown documents | Version mappings by edition; never classify CVEs by keyword similarity |
| Patch targets | Reference extraction only | Do not follow arbitrary URLs, infer fixed versions, or claim verified fixes |

Official machine-readable endpoints and source Markdown are preferred to scraping rendered HTML. All requests reuse bounded downloads, conditional caching, timeouts, and persisted worker retry behavior. OWASP request URLs are constructed under a fixed repository/directory; directory metadata cannot select an arbitrary download host. Full taxonomy snapshots remove withdrawn mappings only after a successful replacement. NVD CVE evidence follows the existing additive merge policy.

## Later source candidates

These are follow-on proposals, not enabled connectors. Each needs deterministic fixtures, terms review, bounded request policy and exact product/CVE mapping before activation:

1. Vendor advisory APIs/CSAF feeds for Red Hat: preserve affected/fixed package semantics and publisher attribution; do not treat generic release notes as patches. Debian tracker JSON and Ubuntu USN JSON are now implemented in the [intelligence expansion](intelligence-expansion-plan.md); scheduled vendor CSAF remains follow-on work.
2. NIST CPE match criteria: expand exact source-supplied configuration evidence without inventing package matches or duplicating NVD CVEs.
3. CAPEC: connect source-backed weakness and attack-pattern identifiers; keep class relationships separate from observed exploitation.
4. Allowlisted vendor HTML adapters only where a structured feed is unavailable: inspect terms/robots policy, enforce domain and redirect restrictions, conditional requests, per-host pacing, extraction bounds and schema-drift fixtures. Never build an unrestricted crawler from advisory links.

## Compatibility and coverage

No full feed import or historical NVD checkpoint reset occurs during the upgrade. The next NVD import enriches only returned CVEs; older records can remain without CWE/patch arrays. Existing authentication and VEX trust policies remain in force. Taxonomy mappings describe weakness classes; they do not establish that a deployment is vulnerable or that a patch is suitable. See [operations](../OPERATIONS.md) for manual source runs and the live parser check.

## Verification record

- Backend deterministic tests, frontend tests, Rust formatting, Rust build and frontend production build passed.
- The PostgreSQL/Valkey production suite passed 94 checks, including knowledge authentication, new entity kinds, restart persistence and migration reapplication, in a disposable database.
- The live OWASP parser check passed against all ten official category documents.
- The live full-CWE check failed on an incomplete upstream response; an independent download also timed out. A single CWE response was retrieved successfully and its schema verified. Full catalog availability remains an upstream operational limitation; no partial taxonomy snapshot is committed on a failed download.

## Implemented vendor web collectors

The next expansion adds four daily sources using six fixed publisher documents:

| Source | Input and coverage | Normalized evidence |
|---|---|---|
| Apache HTTP Server | Official HTML, 2.4 | Primary CVE heading, description, affected text, explicitly released fix version |
| Apache Tomcat | Official HTML, pages for 9.x, 10.x, 11.x | Primary CVE title, scoped paragraphs, branch-specific release/fix context and commit references |
| OpenSSL | Official HTML vulnerability catalog | Source severity, publication date, affected version ranges, fix bounds and commit references |
| curl/libcurl | Official `vuln.json` | OSV-style affected/fixed events, release versions separated from Git commit hashes |

All preserve source URLs, hashes and retrieval times. HTML is parsed without executing scripts. The collectors never expand the crawl from reference links, never match packages by name, and never translate severity words into numeric CVSS. Released remediation remains scoped under `remediation_evidence`; unreleased Apache fixes do not imply patch availability. Unsupported/nonissue appendices are excluded. All pages in a source run must parse before its data and checkpoint commit.

Limits: daily cadence; 8 MiB per document including cached responses; 45 seconds per HTTP request; two same-host HTTPS redirects; 5,000 CVE assertions per source run; one-second spacing for Tomcat branch pages. A parser/schema failure leaves existing data intact and surfaces through normal source status/backoff. These are additional source assertions, not a completeness guarantee or automatic proof of product applicability.

The live read-only parser check successfully parsed 180 HTTP Server assertions, 350 Tomcat assertions across three branches, 297 OpenSSL assertions, and 239 curl assertions on 19 October 2026. These are parser-validation counts (including cross-branch duplicates), not records imported into the application database.

Vendor-expansion verification also passed the backend and frontend unit suites, Rust formatting, both builds, documentation link checks, and all 94 PostgreSQL/Valkey production integration checks. The integration suite verifies all 18 registered sources and backward-compatible empty remediation evidence on older stored CVEs.

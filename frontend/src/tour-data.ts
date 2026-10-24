export const TOUR_STORAGE_KEY = "sentinel-tour-v1";

export const tourSteps = [
  {
    path: "/vi", label: "Overview", title: "Start with the intelligence overview",
    description: "Get a snapshot of the ingested catalog and exploitation signals. Use it to decide where to investigate next.",
    tip: "A new installation starts empty. Counts reflect this instance’s imported data, not complete coverage.",
  },
  {
    path: "/vi/explore", label: "Vulnerabilities", title: "Investigate a vulnerability",
    description: "Search for a CVE or package, then narrow results with filters. Open a finding to inspect its evidence, affected packages and remediation references.",
    tip: "Missing scores and fixes stay unknown. Add findings to your watchlist from their details; the watchlist is saved in this browser.",
  },
  {
    path: "/vi/threat-actors", label: "Threat actors", title: "Explore the adversary context",
    description: "Find threat actor profiles and inspect source-backed techniques and relationships. The Ransomware screen provides a separate group catalog.",
    tip: "An actor profile provides research context. It does not establish attribution for a particular incident.",
  },
  {
    path: "/vi/supply-chain", label: "Supply chain", title: "Research package advisories",
    description: "Explore package advisories and source-supplied affected ranges and fixed versions to support dependency research.",
    tip: "Use exact package coordinates and versions when assessing your own inventory.",
  },
  {
    path: "/vi/tools/kb-lookup", label: "KB lookup", title: "Trace Microsoft update evidence",
    description: "Look up a Microsoft KB to inspect product mappings and source-supplied supersedence relationships.",
    tip: "Check the product scope of an update before treating it as remediation for your system.",
  },
  {
    path: "/vi/tools/sbom-vex", label: "SBOM & VEX", title: "Analyze your software inventory",
    description: "Use CycloneDX or SPDX JSON for SBOM analysis, or record applicability with OpenVEX. Analysis uses exact versioned PURLs and live OSV matching.",
    tip: "Unversioned components can produce warnings. Unsigned VEX statements do not suppress findings under the default trust policy.",
  },
  {
    path: "/vi/sources", label: "Data sources", title: "Check where the evidence comes from",
    description: "Review source freshness, import progress and failures. Use this screen when the catalog looks empty or a source appears out of date.",
    tip: "Ingestion runs asynchronously. A successful import does not guarantee complete historical coverage.",
  },
  {
    path: "/vi/developers", label: "API & integrations", title: "Bring intelligence into your tools",
    description: "Find REST, GraphQL and MCP integration guidance. Use an expiring, scoped read credential when connecting an AI client.",
    tip: "You’re ready to explore. Replay this guide anytime using User tour in the header.",
  },
] as const;

// Browser preferences must never prevent the app or guide from opening.
export function hasSeenTour(storage: Pick<Storage, "getItem">): boolean {
  try { return storage.getItem(TOUR_STORAGE_KEY) === "seen"; } catch { return false; }
}
export function rememberTour(storage: Pick<Storage, "setItem">): void {
  try { storage.setItem(TOUR_STORAGE_KEY, "seen"); } catch { /* Storage may be blocked. */ }
}

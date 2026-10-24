import type { Vulnerability } from "./types";
import { evidenceTimeline, evidenceUrl, remediationScope } from "./evidence";

export function EvidencePanel({ vulnerability: v }: { vulnerability: Vulnerability }) {
  const timeline = evidenceTimeline(v);
  const remediation = v.remediation_evidence ?? [];
  const references = [...new Map((v.poc_references ?? []).map(reference => [reference.url, reference])).values()];
  const latest = v.source_assertions?.at(-1);
  return <section className="evidence-panel" aria-label="Source evidence">
    {latest?.status === "REJECTED" && <p className="note" role="status">The latest collected CNA record is rejected. Earlier evidence from other sources remains available; review the publisher record.</p>}
    <h3>Evidence timeline</h3>
    <p className="muted small">Publisher dates and Sentinel collection times are separate events. Dates are shown as supplied; collection time does not establish when exploitation began.</p>
    {!timeline.length ? <p className="muted">No dated source evidence collected.</p> : <>
      {timeline.length > 100 && <p className="muted small">Showing the latest 100 of {timeline.length} events. Export the record for all retained evidence.</p>}
      <ol className="evidence-timeline">{timeline.slice(0, 100).map((entry, i) => <li key={i}>
        <time dateTime={entry.date}>{entry.date}</time>
        <strong>{entry.label}</strong>
        <span className="muted small">{entry.kind === "collection" ? "Collection" : "Publisher"} · {entry.source}</span>
        {entry.url && <a className="text-link" href={entry.url} target="_blank" rel="noreferrer">View source</a>}
        {entry.sha256 && <details><summary>Document hash</summary><code>{entry.sha256}</code></details>}
      </li>)}</ol>
    </>}
    <h3>Scoped remediation</h3>
    <p className="muted small">Versions apply to the named product and release. Ubuntu notice mappings associate packages and CVEs at advisory scope; confirm the exact package in the notice. These records do not establish inventory applicability.</p>
    {!remediation.length ? <p className="muted">No scoped remediation collected.</p> : <ul className="evidence-records">{remediation.slice(-100).reverse().map((evidence, i) => {
      const url = evidenceUrl(evidence.advisory_url || evidence.provenance?.url);
      const fixed = evidence.fixed_versions ?? [];
      return <li key={i}>
        <strong>{remediationScope(evidence)}</strong>
        <span>{fixed.length ? `Listed fix versions: ${fixed.join(", ")}` : evidence.fixed_version_raw === "0" ? "Publisher fixed-version marker: 0 (no fix version listed)" : "No fix version reported"}</span>
        <span className="muted small">{evidence.source}{evidence.status ? ` · ${evidence.status}` : ""}{evidence.mapping_scope === "notice" ? " · notice-level association" : ""}{evidence.release_status ? ` · ${evidence.release_status.replaceAll("_", " ")}` : ""}</span>
        {url && <a className="text-link" href={url} target="_blank" rel="noreferrer">{evidence.notice_id || "View advisory"}</a>}
      </li>;
    })}</ul>}
    {remediation.length > 100 && <p className="muted small">Showing the latest 100 of {remediation.length} assertions. Export for the complete retained history.</p>}
    <h3>Public PoC references</h3>
    <p className="muted small">Unverified community links may describe research or detection rather than a working exploit. Their presence does not establish exploitation in the wild.</p>
    {!references.length ? <p className="muted">No community references collected. This does not establish that no PoC exists.</p> : <ul className="evidence-records">{references.slice(0, 100).map((reference, i) => {
      const url = evidenceUrl(reference.url);
      return <li key={i}>{url && <a className="text-link" href={url} target="_blank" rel="noreferrer">{url.replace("https://github.com/", "")}</a>}<span className="muted small">Unverified · {reference.source}</span></li>;
    })}</ul>}
    {references.length > 100 && <p className="muted small">Showing 100 of {references.length} references. Export for all retained links.</p>}
  </section>;
}

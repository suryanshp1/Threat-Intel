import type { Vulnerability, RemediationEvidence } from "./types";

export interface TimelineEntry {
  date: string;
  label: string;
  source: string;
  kind: "publisher" | "collection";
  url?: string;
  sha256?: string;
}
export function evidenceUrl(raw?: string): string | undefined {
  if (!raw) return undefined;
  try {
    const url = new URL(raw);
    if (!["https:", "http:"].includes(url.protocol) || url.username || url.password) return undefined;
    return url.href;
  } catch { return undefined; }
}

function validDate(date?: string | null): date is string {
  return !!date && /^\d{4}-\d{2}-\d{2}(T.*)?$/.test(date) && Number.isFinite(Date.parse(date));
}

export function evidenceTimeline(v: Vulnerability): TimelineEntry[] {
  const entries: TimelineEntry[] = [];
  for (const assertion of v.source_assertions ?? []) {
    const source = assertion.metadata?.assignerShortName || assertion.source;
    const origin = assertion.provenance;
    if (validDate(assertion.metadata?.datePublished)) entries.push({
      date: assertion.metadata.datePublished, label: "CNA published record", source, kind: "publisher", url: evidenceUrl(origin?.url),
    });
    if (validDate(assertion.metadata?.dateUpdated)) entries.push({
      date: assertion.metadata.dateUpdated, label: assertion.status === "REJECTED" ? "CNA record rejected" : "CNA record updated",
      source, kind: "publisher", url: evidenceUrl(origin?.url),
    });
  }
  if (validDate(v.cisa_date_added)) entries.push({
    date: v.cisa_date_added, label: "Added to known exploited catalog", source: "CISA KEV", kind: "publisher",
    url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
  });
  for (const evidence of v.remediation_evidence ?? []) {
    if (validDate(evidence.published_at)) entries.push({
      date: evidence.published_at, label: evidence.notice_id ? `${evidence.notice_id} published` : "Remediation advisory published",
      source: evidence.source, kind: "publisher", url: evidenceUrl(evidence.advisory_url),
    });
  }
  // Repeated conditional fetches have new retrieval times. Show the earliest
  // retained observation of each document hash, rather than implying new evidence.
  const observations = new Map<string, TimelineEntry>();
  for (const origin of v.provenance ?? []) {
    if (!validDate(origin.retrieved_at)) continue;
    const key = JSON.stringify([origin.source, origin.url, origin.sha256]);
    const entry: TimelineEntry = {date: origin.retrieved_at, label: "Document collected", source: origin.source,
      kind: "collection", url: evidenceUrl(origin.url), sha256: origin.sha256};
    const old = observations.get(key);
    if (!old || old.date > entry.date) observations.set(key, entry);
  }
  entries.push(...observations.values());
  const unique = new Map(entries.map(entry => [JSON.stringify([entry.kind, entry.date, entry.source, entry.label, entry.url]), entry]));
  // Dates remain displayed exactly as supplied. Date-only publisher records have
  // day precision; they do not imply an exact time of discovery or exploitation.
  return [...unique.values()].sort((a, b) => b.date.localeCompare(a.date) || a.label.localeCompare(b.label));
}

export function remediationScope(evidence: RemediationEvidence): string {
  return [evidence.distribution, evidence.release || evidence.branch, evidence.product].filter(Boolean).join(" · ") || "See publisher scope";
}

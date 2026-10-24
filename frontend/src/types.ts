export interface Vulnerability {
  id: string;
  cvss_known: boolean;
  epss_known: boolean;
  patch_status: string;
  remediation?: string;
  provenance: {source:string;url:string;retrieved_at:string;sha256:string}[];
  source_assertions?: SourceAssertion[];
  poc_references?: PocReference[];
  remediation_evidence?: RemediationEvidence[];
  cisa_date_added?: string | null;
  
  title: string;
  description: string;
  vendor: string;
  product: string;
  ecosystem: string;
  purl: string;
  affected_version: string;
  fixed_version: string;
  cvss: number;
  epss_score: number;
  seen_wild: boolean;
  exploit_available: boolean;
  patch_available: boolean;
  is_zeroday: boolean;
  known_ransomware_use: boolean;
  automatable: boolean;
  total_impact: boolean;
  priority_score: number;
  ssvc_decision: string;
  published: string;
  actors: string[];
  tags: string[];
  sources: string[];
  score_breakdown: Record<string, number | string>;
}
export interface EvidenceOrigin {
  source: string;
  url: string;
  retrieved_at: string;
  sha256: string;
}
export interface SourceAssertion {
  source: string;
  status: string;
  metadata: { datePublished?: string; dateUpdated?: string; assignerShortName?: string };
  cna: { title?: string; descriptions?: {lang: string; value: string}[]; metrics?: Record<string, unknown>[] };
  provenance: EvidenceOrigin;
}
export interface PocReference {
  source: string;
  url: string;
  verification: string;
  provenance: EvidenceOrigin;
}
export interface RemediationEvidence {
  source: string;
  product?: string;
  distribution?: string;
  release?: string;
  branch?: string;
  status?: string;
  fixed_version_raw?: string;
  fixed_versions?: string[];
  release_status?: string;
  mapping_scope?: string;
  notice_id?: string;
  published_at?: string;
  advisory_url?: string;
  provenance: EvidenceOrigin;
}
export interface Actor {
  id: string;
  country: string;
  code: string;
  description: string;
  aliases: string[];
  cves_exploited: string[];
  target_category: string[];
  techniques: string[];
  type: string;
  first_seen: string;
  victim_count: number;
  source?: string;
  provenance?:{url:string;retrieved_at:string};
}
export interface Source {
  source_name: string;
  status: string;
  last_success_at: string | null;
  consecutive_failures: number;
  records?:number;
  last_error?:string;
  configuration_required?:string;
  coverage?:string;
}
export interface Stats {
  total: number;
  kev: number;
  zerodays: number;
  exploits: number;
  high_priority: number;
  decisions: Record<string, number>;
  mode: string;
  snapshot: string|null;
  activity: {month:string;total:number;kev:number}[];
  sources: Source[];
}
export interface FilterResult {
  results: Vulnerability[];
  total: number;
  next_cursor: string | null;
  facets: Record<string, number>;
}
export async function api<T>(path: string, body?: unknown, signal?: AbortSignal): Promise<T> {
  const r = await fetch(path, {
    method: body === undefined ? "GET" : "POST",
    headers: { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
    signal,
  });
  if (!r.ok) {
    const data = await r.json().catch(() => ({ detail: r.statusText }));
    if(r.status===401)window.dispatchEvent(new Event("sentinel-auth-required"));
    throw new Error(data.detail || "Request failed");
  }
  return r.json();
}
export function download(
  data: unknown,
  name: string,
  type = "application/json",
) {
  const blob = new Blob(
    [typeof data === "string" ? data : JSON.stringify(data, null, 2)],
    { type },
  );
  downloadBlob(blob, name);
}
export function downloadBlob(blob: Blob, name: string) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

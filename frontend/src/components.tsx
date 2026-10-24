import { useEffect, useState, useRef, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  useReactTable,
  getCoreRowModel,
  type ColumnDef,
} from "@tanstack/react-table";
import {
  ArrowUpRight,
  X,
  Check,
  Copy,
  Bookmark,
  Download,
  ExternalLink,
  ShieldCheck,
    Radar,
} from "lucide-react";
import {
  ReactFlow,
  Background,
  Controls,
  useNodesState,
  useEdgesState,
  type ReactFlowInstance,
  type Node,
  type Edge,
} from "@xyflow/react";
import { api, download, downloadBlob, type Vulnerability } from "./types";
import { sourceDescription, vulnerabilityExport, type ExportProgress } from "./ui-data";
import { useTheme } from "./theme";
import { EvidencePanel } from "./evidence-panel";

export function ExportButton({ filter = {}, name, label = "Export", primary = false }: {
  filter?: Record<string, unknown>; name: string; label?: string; primary?: boolean;
}) {
  const controller = useRef<AbortController | null>(null);
  const [progress, setProgress] = useState<ExportProgress | null>(null);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  useEffect(() => () => controller.current?.abort(), []);
  async function run() {
    if (controller.current) return;
    const active = new AbortController();
    controller.current = active;
    setProgress({ count: 0, total: 0 });
    setError("");
    setMessage("");
    try {
      const result = await vulnerabilityExport(filter, active.signal, setProgress);
      downloadBlob(result.blob, name);
      setMessage(`Exported ${result.count.toLocaleString()} records.`);
    } catch (e) {
      if (active.signal.aborted) setMessage("Export canceled.");
      else setError((e as Error).message || "Export failed. Please retry.");
    } finally {
      controller.current = null;
      setProgress(null);
    }
  }
  return <div className="export-control">
    <div className="export-actions">
      <button className={`button ${primary ? "primary" : "secondary"}`} disabled={!!progress} onClick={run} title="Export every matching record, ordered by CVE ID">
        <Download size={15} />{progress ? "Exporting…" : label}
      </button>
      {progress && <button className="button secondary" onClick={() => controller.current?.abort()}>Cancel export</button>}
    </div>
    <span className="export-status" role="status">{progress
      ? `${progress.count.toLocaleString()}${progress.total ? ` of ${progress.total.toLocaleString()}` : ""} records fetched`
      : message}</span>
    {error && <span className="form-error" role="alert">{error}</span>}
  </div>;
}

export function SourceDescription({ text }: { text: string }) {
  const { body, citations } = sourceDescription(text);
  const parts = body.split(/(\[[^\]]+\]\(https?:\/\/[^\s)]+\))/g);
  return <div className="actor-description">
    <p>{parts.map((part, index) => {
      const link = /^\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)$/.exec(part);
      return link ? <a className="source-text-link" key={index} href={link[2]} target="_blank" rel="noreferrer">{link[1]}</a> : part;
    })}</p>
    {citations.length > 0 && <details className="source-citations"><summary>Source citations ({citations.length})</summary><p>{citations.join(" · ")}</p></details>}
  </div>;
}
export function Badge({
  children,
  tone = "neutral",
}: {
  children: React.ReactNode;
  tone?: string;
}) {
  return <span className={`badge ${tone}`}>{children}</span>;
}
export function Decision({ value }: { value: string }) {
  return (
    <Badge
      tone={
        value === "Act"
          ? "danger"
          : value === "Attend"
            ? "warning"
            : value === "Track*"
              ? "blue"
              : "neutral"
      }
    >
      <span className="status-dot" />
      {value}
    </Badge>
  );
}
export function Empty({
  title,
  description,
}: {
  title: string;
  description: string;
}) {
  return (
    <div className="empty">
      <Radar size={30} />
      <h3>{title}</h3>
      <p>{description}</p>
    </div>
  );
}
export function ErrorBox({
  error,
  retry,
}: {
  error: Error | null;
  retry?: () => void;
}) {
  return (
    <div className="error-box" role="alert">
      <strong>Unable to load intelligence</strong>
      <p>
        {error?.message ||
          "The API is unavailable. Start the Rust API and retry."}
      </p>
      {retry && (
        <button className="button secondary" onClick={retry}>
          Try again
        </button>
      )}
    </div>
  );
}
export function Loading() {
  return (
    <div className="loading" role="status">
      <span />
      Loading intelligence…
    </div>
  );
}
export function Graph({ nodes, edges }: { nodes: Node[]; edges: Edge[] }) {
 const { theme } = useTheme();
 const [graphNodes,setNodes,onNodesChange]=useNodesState(nodes);
 const [graphEdges,setEdges,onEdgesChange]=useEdgesState(edges);
 const instance=useRef<ReactFlowInstance|null>(null);
 const container=useRef<HTMLDivElement>(null);
 useEffect(()=>{setNodes(nodes);setEdges(edges);const frame=requestAnimationFrame(()=>instance.current?.fitView({padding:0.15,maxZoom:1.1}));return()=>cancelAnimationFrame(frame)},[nodes,edges,setNodes,setEdges]);
 useEffect(()=>{const element=container.current;if(!element)return;let frame=0;const observer=new ResizeObserver(()=>{cancelAnimationFrame(frame);frame=requestAnimationFrame(()=>instance.current?.fitView({padding:0.15,maxZoom:1.1}))});observer.observe(element);return()=>{observer.disconnect();cancelAnimationFrame(frame)}},[]);
 return <div ref={container} className="graph" aria-label="Interactive intelligence relationship graph"><ReactFlow nodes={graphNodes} edges={graphEdges} onNodesChange={onNodesChange} onEdgesChange={onEdgesChange} onInit={flow=>{instance.current=flow}} fitView fitViewOptions={{padding:0.15,maxZoom:1.1}} minZoom={0.3} maxZoom={1.5} colorMode={theme} nodesDraggable nodesConnectable={false}><Background color="var(--graph-grid, #303030)" gap={24}/><Controls showInteractive={false}/></ReactFlow></div>;
}
export function useStored<T>(key: string, initial: T) {
  const [value, setValue] = useState<T>(() => {
    try {
      return JSON.parse(localStorage.getItem(key) || "null") ?? initial;
    } catch {
      return initial;
    }
  });
  useEffect(() => {
    const listener = (event: Event) => {
      const detail = (event as CustomEvent).detail;
      if (detail.key === key) setValue(detail.value);
    };
    window.addEventListener("sentinel-storage", listener);
    return () => window.removeEventListener("sentinel-storage", listener);
  }, [key]);
  const update: React.Dispatch<React.SetStateAction<T>> = (action) => {
    const next =
      typeof action === "function" ? (action as (v: T) => T)(value) : action;
    setValue(next);
    try {
      localStorage.setItem(key, JSON.stringify(next));
    } catch {}
    window.dispatchEvent(
      new CustomEvent("sentinel-storage", { detail: { key, value: next } }),
    );
  };
  return [value, update] as const;
}
export function ProbabilityMeter({ value }: { value: number }) {
  return (
    <span className="probability-meter" aria-hidden="true">
      <i style={{ width: `${value * 100}%` }} />
    </span>
  );
}
export function CveRows({
  records,
  onSelect,
  compact = false,
  sortBy = "priority_score",
}: {
  records: Vulnerability[];
  onSelect: (id: string) => void;
  compact?: boolean;
  sortBy?: string;
}) {
  const columns = useMemo<ColumnDef<Vulnerability>[]>(
    () => [
      { accessorKey: "id" },
      { accessorKey: "priority_score" },
      { accessorKey: "cvss" },
      { accessorKey: "epss_score" },
      { accessorKey: "ssvc_decision" },
    ],
    [],
  );
  const table = useReactTable({
    data: records,
    columns,
    getCoreRowModel: getCoreRowModel(),
    getRowId: (r) => r.id,
  });
  return (
    <div className="table-scroll">
      <table className={`intel-table ${compact ? "compact" : ""}`}>
        <thead>
          <tr>
            <th aria-sort={sortBy === "published" ? "descending" : undefined}>Vulnerability{sortBy === "published" && <span className="sort-caption">Published ↓</span>}</th>
            <th aria-sort={sortBy === "priority_score" ? "descending" : undefined}>
              Priority {sortBy === "priority_score" && <span>↓</span>}
            </th>
            <th aria-sort={sortBy === "cvss" ? "descending" : undefined}>CVSS {sortBy === "cvss" && <span>↓</span>}</th>
            <th aria-sort={sortBy === "epss_score" ? "descending" : undefined}>EPSS {sortBy === "epss_score" && <span>↓</span>}</th>
            <th>Decision</th>
            {!compact && <th>Intelligence</th>}
            <th aria-label="View details" />
          </tr>
        </thead>
        <tbody>
          {table.getRowModel().rows.map(({ original: v }) => (
            <tr key={v.id} onClick={() => onSelect(v.id)}>
              <td>
                <button
                  className="cve-link"
                  onClick={(e) => {
                    e.stopPropagation();
                    onSelect(v.id);
                  }}
                >
                  {v.id}
                </button>
                <span className="table-description" title={v.title}>{v.title}</span>
                {sortBy === "published" && <span className="table-description">Published {v.published || "Not reported"}</span>}
              </td>
              <td>
                <div className="score-cell">
                  <strong
                    className={v.priority_score >= 700 ? "score-high" : ""}
                  >
                    {v.priority_score}
                  </strong>
                  <span className="score-track">
                    <i style={{ width: `${v.priority_score / 10}%` }} />
                  </span>
                </div>
              </td>
              <td>
                <span
                  className={`severity ${v.cvss >= 9 ? "critical" : v.cvss >= 7 ? "high" : "medium"}`}
                >
                  {v.cvss_known?v.cvss.toFixed(1):"Unknown"}
                </span>
              </td>
              <td>
                <div className="epss-cell">
                  {v.epss_known?`${(v.epss_score * 100).toFixed(1)}%`:"Unknown"}{" "}
                  {v.epss_known&&<ProbabilityMeter value={v.epss_score} />}
                </div>
              </td>
              <td>
                <Decision value={v.ssvc_decision} />
              </td>
              {!compact && (
                <td>
                  <div className="flex gap-2">
                    {v.seen_wild && <Badge tone="neutral">KEV</Badge>}
                    {v.exploit_available && (
                      <Badge tone="neutral">Exploit</Badge>
                    )}
                  </div>
                </td>
              )}
              <td>
                <button
                  className="icon-button"
                  aria-label={`View ${v.id}`}
                  onClick={(e) => {
                    e.stopPropagation();
                    onSelect(v.id);
                  }}
                >
                  <ArrowUpRight size={16} />
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
export function DetailDrawer({
  id,
  onClose,
}: {
  id: string;
  onClose: () => void;
}) {
  const drawerRef = useRef<HTMLElement>(null);
  const {
    data: v,
    error,
    isPending,
  } = useQuery({
    queryKey: ["vulnerability", id],
    queryFn: () => api<Vulnerability>(`/api/vulnerabilities/${id}`),
  });
  const [tab, setTab] = useState("Overview");
  const [watch, setWatch] = useStored<string[]>("sentinel-watchlist", []);
  const [copied, setCopied] = useState(false);
  const { data: rules, error: rulesError, isPending: rulesPending, refetch: refetchRules } = useQuery({
    queryKey: ["rules", id],
    queryFn: () =>
      api<{
        results: { rule_id: string; rule_type:string; title: string; source_url: string; raw_content:string }[];
        note: string;
      }>(`/api/v2/vulnerabilities/${id}/rules`),
    enabled: tab === "Detection",
  });
  useEffect(() => {
    const previous = document.activeElement as HTMLElement;
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
      if (e.key === "Tab") {
        const controls = drawerRef.current?.querySelectorAll<HTMLElement>(
          "button:not(:disabled),a[href],input,select,textarea",
        );
        if (controls?.length) {
          const first = controls[0],
            last = controls[controls.length - 1];
          if (e.shiftKey && document.activeElement === first) {
            e.preventDefault();
            last.focus();
          } else if (!e.shiftKey && document.activeElement === last) {
            e.preventDefault();
            first.focus();
          }
        }
      }
    };
    document.addEventListener("keydown", handler);
    const old = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", handler);
      document.body.style.overflow = old;
      previous?.focus();
    };
  }, [onClose]);
  return (
    <div className="drawer-backdrop" onClick={onClose}>
      <section
        ref={drawerRef}
        className="drawer"
        role="dialog"
        aria-modal="true"
        aria-label={`${id} intelligence`}
        onClick={(e) => e.stopPropagation()}
      >
        <header>
          <span className="flex items-center gap-2">
            <ShieldCheck size={17} /> Vulnerability intelligence
          </span>
          <button
            autoFocus
            className="icon-button"
            onClick={onClose}
            aria-label="Close details"
          >
            <X />
          </button>
        </header>
        {isPending ? (
          <Loading />
        ) : error ? (
          <ErrorBox error={error} />
        ) : (
          v && (
            <>
              <div className="drawer-intro">
                <div className="flex justify-between items-center">
                  <span className="muted">Source-backed record</span>
                  <Decision value={v.ssvc_decision} />
                </div>
                <h2>{v.id}</h2>
                <p className="drawer-title">{v.title}</p>
                <div className="flex gap-2 flex-wrap">
                  <button
                    className="button primary"
                    onClick={() =>
                      setWatch(
                        watch.includes(id)
                          ? watch.filter((x) => x !== id)
                          : [...watch, id],
                      )
                    }
                  >
                    <Bookmark
                      size={15}
                      fill={watch.includes(id) ? "currentColor" : "none"}
                    />
                    {watch.includes(id) ? "Watching" : "Add to watchlist"}
                  </button>
                  <button
                    className="button secondary"
                    onClick={() => download(v, `${id}.json`)}
                  >
                    <Download size={15} />
                    Export
                  </button>
                  <button
                    className="icon-button"
                    aria-label="Copy CVE ID"
                    onClick={() => {
                      navigator.clipboard
                        .writeText(id)
                        .then(() => {
                          setCopied(true);
                          setTimeout(() => setCopied(false), 2000);
                        })
                        .catch(() => {});
                    }}
                  >
                    {copied ? <Check size={17} /> : <Copy size={17} />}
                  </button>
                </div>
              </div>
              <nav className="tabs">
                {["Overview", "Evidence", "Relationships", "Detection"].map((t) => (
                  <button
                    key={t}
                    className={tab === t ? "active" : ""}
                    onClick={() => setTab(t)}
                  >
                    {t}
                  </button>
                ))}
              </nav>
              <div className="drawer-content">
                {tab === "Overview" ? (
                  <>
                    <div className="detail-metrics">
                      <div>
                        <span>Priority score</span>
                        <strong>
                          {v.priority_score}
                          <small>/1000</small>
                        </strong>
                      </div>
                      <div>
                        <span>CVSS severity</span>
                        <strong>{v.cvss_known?v.cvss.toFixed(1):"Unknown"}</strong>
                      </div>
                      <div>
                        <span>EPSS probability</span>
                        <strong>
                          {v.epss_known?(v.epss_score * 100).toFixed(1):"Unknown"}
                          {v.epss_known && <small>%</small>}
                        </strong>
                      </div>
                    </div>
                    <h3>Evidence sources</h3><div className="provenance-list">{v.provenance?.map((source,i)=><a key={i} href={source.url} target="_blank" rel="noreferrer"><strong>{source.source}</strong><span>Retrieved {new Date(source.retrieved_at).toLocaleString()}</span><ExternalLink size={13}/></a>)}</div>
                    <h3>What you need to know</h3>
                    <p>{v.description}</p>
                    <div className="signal-list">
                      <span>
                        Active exploitation{" "}
                        <Badge tone={v.seen_wild ? "danger" : "neutral"}>
                          {v.seen_wild ? "Confirmed by source" : "Not reported"}
                        </Badge>
                      </span>
                      <span>
                        Vendor patch{" "}
                        <Badge tone={v.patch_available ? "success" : "neutral"}>
                          {v.patch_available ? "Available" : "Not reported"}
                        </Badge>
                      </span>
                      <span>
                        Published <b>{v.published||"Not reported"}</b>
                      </span>
                    </div>
                    <h3>Why this score?</h3>
                    <p className="muted small">
                      Transparent contributions from the PRD formula. Unknown evidence contributes no points. SSVC decisions require a complete assessment.
                    </p>
                    {[
                      ["exploitation", "Exploitation evidence", 350],
                      ["epss", "Exploitation probability", 250],
                      ["severity", "Technical severity", 200],
                      ["threat", "Threat context", 150],
                      ["supply_chain", "Supply-chain exposure", 50],
                    ].map(([key, label, max]) => (
                      <div className="breakdown" key={key}>
                        <span>{label}</span>
                        <div>
                          <i
                            style={{
                              width: `${(Number(v.score_breakdown[key]) / Number(max)) * 100}%`,
                            }}
                          />
                        </div>
                        <b>{Math.round(Number(v.score_breakdown[key]))}</b>
                      </div>
                    ))}
                    <h3>Remediation</h3>
                    <div className="remediation">
                      <ShieldCheck size={20} />
                      <div>
                        <strong>
                          {v.fixed_version?`Upgrade ${v.product} to ${v.fixed_version}`:v.remediation||"Consult the source advisory for remediation"}
                        </strong>
                        <p>Affected range: {v.affected_version||"See source advisory"}</p>
                      </div>
                    </div>
                    <a
                      className="text-link"
                      target="_blank"
                      rel="noreferrer"
                      href={`https://nvd.nist.gov/vuln/detail/${id}`}
                    >
                      Verify the NVD advisory <ExternalLink size={14} />
                    </a>
                  </>
                ) : tab === "Evidence" ? <EvidencePanel vulnerability={v} /> : tab === "Relationships" ? (
                  <>
                    <h3>From adversary to affected package</h3>
                    <p className="muted small">
                      Only ingested source relationships are shown. Drag nodes or zoom to explore.
                    </p>
                    <Graph nodes={[{id:'cve',position:{x:0,y:40},data:{label:v.id}},...(v.product?[{id:'product',position:{x:250,y:40},data:{label:v.product}}]:[]),...(v.fixed_version?[{id:'fix',position:{x:500,y:40},data:{label:`Fix ${v.fixed_version}`}}]:[])]} edges={[...(v.product?[{id:'affected',source:'cve',target:'product',label:'affects · source reported'}]:[]),...(v.product&&v.fixed_version?[{id:'remediate',source:'product',target:'fix',label:'fixed version'}]:[])]}/>
                    <div className="note">Unknown actor attribution is not inferred from exploitation status.</div>
                  </>
                ) : (
                  <>
                    <h3>Defensive coverage</h3>
                    {rulesError ? <ErrorBox error={rulesError} retry={() => { void refetchRules(); }} />
                      : rulesPending ? <Loading />
                      : <><p className="muted">{rules?.note}</p>{!rules?.results.length && <Empty title="No detection rules reported" description="No ingested rules reference this vulnerability." />}</>}
                    {rules?.results.map((rule) => (
                      <a
                        className="rule-link"
                        key={rule.rule_id}
                        href={rule.source_url}
                        target="_blank"
                        rel="noreferrer"
                      >
                        <div>
                          <Badge tone="blue">{rule.rule_type}</Badge>
                          <h4>{rule.title}</h4>
                          <p>View upstream rule</p>
                        </div>
                        <ArrowUpRight size={20} />
                      </a>
                    ))}
                  </>
                )}
              </div>
            </>
          )
        )}
      </section>
    </div>
  );
}

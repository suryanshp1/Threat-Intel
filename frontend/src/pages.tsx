import {useIdentity,permits} from "./identity";
import { useEffect, useRef, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router-dom";
import {
  ArrowDownToLine,
  ArrowRight,
  ArrowUpRight,
  Bookmark,
  Check,
  ChevronLeft,
  ChevronRight,
  Code2,
  Copy,
  Database,
  ExternalLink,
  FileJson,
  Fingerprint,
  GitBranch,
  Globe2,
  Info,
  Layers,
  Package,
  Plus,
  Radio,
  Search,
  Shield,
  ShieldCheck,
  SlidersHorizontal,
  Upload,
  X,
} from "lucide-react";
import {
  api,
  download,
  type Vulnerability,
  type FilterResult,
  type Stats,
  type Actor,
} from "./types";
import {
  Badge,
  CveRows,
  Decision,
  Empty,
  ErrorBox,
  Graph,
  Loading,
  useStored,
  ExportButton,
  SourceDescription,
} from "./components";
import { activitySeries } from "./ui-data";

type SelectProps = { onSelect: (id: string) => void };
function useAll() {
  return useQuery({
    queryKey: ["all-vulnerabilities"],
    queryFn: () =>
      api<FilterResult>("/api/v2/vulnerabilities/filter", { limit: 100 }),
  });
}
function PageHeading({
  title,
  description,
  children,
}: {
  title: string;
  description: string;
  children?: React.ReactNode;
}) {
  return (
    <div className="page-heading">
      <div>
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      <div className="heading-actions">{children}</div>
    </div>
  );
}

export function Overview({ onSelect }: SelectProps) {
  const {
    data: stats,
    error,
    refetch,
  } = useQuery({
    queryKey: ["stats"],
    queryFn: () => api<Stats>("/api/stats/"),
  });
  const { data, error: recordsError, refetch: refetchRecords } = useAll();
  const [period, setPeriod] = useState("All history");
  const [hover, setHover] = useState<number | null>(null);
  if (error || recordsError) return <ErrorBox error={error || recordsError} retry={() => { void refetch(); void refetchRecords(); }} />;
  if (!stats || !data) return <Loading />;
  const rows = data.results;
  const activity = activitySeries(stats.activity || [], period);
  const groups = activity.map(point=>point.month);
  const counts = activity.map(point=>point.total);
  const kev = activity.map(point=>point.kev);
  const max = Math.max(...counts, 1) + 2;
  const pointX = (i: number) => counts.length < 2 ? 395 : 55 + i * 680 / (counts.length - 1);
  const tickStep = Math.max(1, Math.ceil((counts.length - 1) / 5));
  const points = (values: number[]) =>
    values
      .map(
        (n, i) =>
          `${pointX(i)},${190 - (n / max) * 155}`,
      )
      .join(" ");
  const active =
    hover === null ? counts.reduce((a, b) => a + b, 0) : counts[hover];
  const decisions = stats.decisions;
  const act = decisions.Act || 0;
  const attend = decisions.Attend || 0;
  const pct = (act / Math.max(stats.total,1)) * 100;
  return (
    <>
      <PageHeading
        title="Intelligence overview"
        description="The signals that matter. The context to act."
      >
        <span className="snapshot-label">
          <span className="status-light" /> Source-backed workspace
        </span>
        <ExportButton name="sentinel-intelligence.json" label="Export report" />
      </PageHeading>
      <div className="overview-notice">
        <div>
          <span className="notice-icon">
            <Radio size={16} />
          </span>
          <span>
            <b>Your threat landscape, in focus.</b> Explore connected
            vulnerabilities, adversaries, and the path to remediation.
          </span>
        </div>
        <Link to="/vi/explore">
          Explore intelligence <ArrowRight size={16} />
        </Link>
      </div>
      <section className="metrics-grid" aria-label="Dataset overview">
        {[
          {
            label: "Tracked vulnerabilities",
            n: stats.total,
            sub: "Ingested from public sources",
            icon: Shield,
            link: "/vi/explore",
            tone: "",
          },
          {
            label: "Known exploited",
            n: stats.kev,
            sub: "Confirmed by CISA KEV",
            icon: Radio,
            link: "/vi/explore?kev=true",
            tone: "danger",
          },
          {
            label: "Zero-day vulnerabilities",
            n: stats.zerodays,
            sub: "Exploited before a patch",
            icon: Fingerprint,
            link: "/vi/explore?zero=true",
            tone: "warning",
          },
          {
            label: "High-priority findings",
            n: stats.high_priority,
            sub: "Priority score of 700 or above",
            icon: Layers,
            link: "/vi/explore?priority=true",
            tone: "blue",
          },
        ].map((m) => (
          <Link to={m.link} className="metric" key={m.label}>
            <div className="metric-label">
              {m.label}
              <m.icon size={17} />
            </div>
            <div className="metric-number">
              {String(m.n).padStart(2, "0")}
              <ArrowUpRight size={20} />
            </div>
            <div className="metric-caption">
              <span className={`status-dot ${m.tone}`} />
              {m.sub}
            </div>
          </Link>
        ))}
      </section>
      <div className="charts-grid">
        <section className="panel activity-panel">
          <div className="panel-header">
            <div>
              <h2>Vulnerability activity</h2>
              <p>Publication counts from ingested records</p>
            </div>
            <select
              aria-label="Chart period"
              value={period}
              onChange={(e) => {
                setPeriod(e.target.value);
                setHover(null);
              }}
            >
              <option>All history</option>
              <option>Last 12 months</option>
            </select>
          </div>
          <div className="chart-summary">
            <strong>{String(active).padStart(2, "0")}</strong>
            <span>
              {hover === null
                ? "vulnerabilities in this view"
                : `published in ${groups[hover]}`}
              <small>
                <span className="blue-dot" />
                All vulnerabilities <span className="grey-dot" />
                Known exploited
              </small>
            </span>
          </div>
          {!activity.length ? <Empty title="No publication history yet" description="Activity will appear when sources report publication dates." /> : <><div className="activity-chart">
            <svg
              viewBox="0 0 770 235"
              role="img"
              aria-label={`Publication counts by ${period === "Last 12 months" ? "month" : "year"}`}
              onMouseLeave={() => setHover(null)}
            >
              {[0, 1, 2, 3].map((n) => (
                <g key={n}>
                  <line
                    x1="55"
                    x2="735"
                    y1={35 + n * 52}
                    y2={35 + n * 52}
                    stroke="var(--theme-border, #252525)"
                    strokeDasharray="3 5"
                  />
                  <text x="46" textAnchor="end" y={39 + n * 52} fill="var(--theme-text-secondary, #aaa)" fontSize="12">
                    {Math.round(max - (n * max) / 3)}
                  </text>
                </g>
              ))}
              <polygon
                points={`55,190 ${points(counts)} 735,190`}
                fill="#0099ff"
                opacity=".055"
              />
              <polyline
                points={points(kev)}
                stroke="#646b72"
                fill="none"
                strokeWidth="2"
              />
              <polyline
                points={points(counts)}
                stroke="#339fff"
                fill="none"
                strokeWidth="2.5"
                strokeLinejoin="round"
              />
              {counts.map((n, i) => (
                <g key={i} onMouseEnter={() => setHover(i)}>
                  <title>{`${groups[i]}: ${n.toLocaleString()} vulnerabilities, ${kev[i].toLocaleString()} known exploited`}</title>
                  <rect
                    x={pointX(i) - 10}
                    y="18"
                    width={Math.min(40, 680 / Math.max(counts.length, 1))}
                    height="180"
                    fill="transparent"
                  />
                  <circle
                    cx={pointX(i)}
                    cy={190 - (n / max) * 155}
                    r={hover === i ? 5 : 3}
                    fill="#60b4ff"
                  />
                  {(i % tickStep === 0 || i === counts.length - 1) && <text
                    x={pointX(i)}
                    y="222"
                    textAnchor="middle"
                    fill="var(--theme-text-secondary, #aaa)"
                    fontSize="13"
                  >
                    {period === "Last 12 months"
                      ? new Date(`${groups[i]}-01T00:00:00`).toLocaleDateString(
                          "en",
                          { month: "short" },
                        )
                      : groups[i]}
                  </text>}
                </g>
              ))}
            </svg>
          </div><details className="chart-data"><summary>View chart data</summary><div className="table-scroll"><table className="intel-table"><caption className="sr-only">Publication counts by {period === "Last 12 months" ? "month" : "year"}</caption><thead><tr><th>Period</th><th>Vulnerabilities</th><th>Known exploited</th></tr></thead><tbody>{activity.map(point => <tr key={point.month}><th scope="row">{point.month}</th><td>{point.total.toLocaleString()}</td><td>{point.kev.toLocaleString()}</td></tr>)}</tbody></table></div></details></>}
          <div className="chart-foot">
            <Info size={13} />
            <span>
              Only source-reported publication dates are counted.
            </span>
          </div>
        </section>
        <section className="panel decision-panel">
          <div className="panel-header">
            <div>
              <h2>Know what comes first</h2>
              <p>Source-reported SSVC decisions</p>
            </div>
            <Link to="/vi/explore" aria-label="View triage findings">
              <ArrowUpRight size={18} />
            </Link>
          </div>
          <div className="donut-container">
            <div
              className="donut"
              style={{
                background: `conic-gradient(#e17777 0% ${pct}%,#d5b278 ${pct}% ${((act + attend) / Math.max(stats.total,1)) * 100}%,#629ece ${((act + attend) / Math.max(stats.total,1)) * 100}% ${100 - (((decisions.Track || 0)+(decisions.Unassessed || 0)) / Math.max(stats.total,1)) * 100}%,#3c4146 0)`,
              }}
            >
              <div>
                <strong>{stats.total}</strong>
                <span>findings</span>
              </div>
            </div>
          </div>
          <div className="decision-legend">
            {[
              ["Act", "Immediate attention", "danger"],
              ["Attend", "Elevated attention", "warning"],
              ["Track*", "Monitor closely", "blue"],
              ["Track", "Routine remediation", "neutral"],
              ["Unassessed", "Awaiting assessment", "neutral"],
            ].map(([name, desc, tone]) => (
              <Link
                key={name}
                to={`/vi/explore?decision=${encodeURIComponent(name)}`}
              >
                <span className={`legend-dot ${tone}`} />
                <b>{name}</b>
                <span>{desc}</span>
                <strong>{decisions[name] || 0}</strong>
              </Link>
            ))}
          </div>
        </section>
      </div>
      <section className="panel priority-panel">
        <div className="panel-header">
          <div className="flex items-center gap-3">
            <h2>Prioritize your response</h2>
            <Badge tone="danger">{stats.high_priority} high priority</Badge>
          </div>
          <Link className="text-link" to="/vi/explore">
            View all vulnerabilities <ArrowRight size={15} />
          </Link>
        </div>
        <CveRows records={rows.slice(0, 5)} onSelect={onSelect} />
      </section>
      <div className="bottom-grid">
        <section className="briefing">
          <div className="briefing-icon">
            <GitBranch size={23} />
          </div>
          <div>
            <h2>A CVE is only the beginning.</h2>
            <p>
              Connect the vulnerability to the actor, the affected package, and
              the fix.
            </p>
            <Link to="/vi/threat-actors">
              Follow the intelligence <ArrowUpRight size={16} />
            </Link>
          </div>
          <div className="mini-graph" aria-hidden="true">
            <span>Threat actor</span>
            <i />
            <span>CVE</span>
            <i />
            <span>Package</span>
          </div>
        </section>
        <section className="source-summary">
          <div className="flex items-center justify-between">
            <h2>Behind the intelligence</h2>
            <Database size={17} />
          </div>
          <p>
            Public-source ingestion with persisted checkpoints, provenance, and freshness status.
          </p>
          <Link className="text-link" to="/vi/sources">
            Manage data sources <ArrowRight size={15} />
          </Link>
        </section>
      </div>
    </>
  );
}

export function Explorer({ onSelect }: SelectProps) {
  const [params, setParams] = useSearchParams();
  const q = params.get("q") || "";
  const [input, setInput] = useState(q);
  useEffect(() => setInput(q), [q]);
  const [advanced, setAdvanced] = useState(false);
  const [saved, setSaved] = useStored<{ name: string; query: string }[]>(
    "sentinel-views",
    [],
  );
  const [saveOpen, setSaveOpen] = useState(false);
  const [viewName, setViewName] = useState("");
  const [cursorStack, setCursorStack] = useState<string[]>([]);
  const [watch] = useStored<string[]>("sentinel-watchlist", []);
  const onlyWatch = params.get("watch") === "true";
  const advancedKeys = ["decision", "severity", "ecosystem"];
  const activeAdvanced = advancedKeys.filter(key => params.get(key));
  const allActive = !["kev", "zero", "priority", ...advancedKeys].some(key => params.get(key)) && !onlyWatch;
  function update(key: string, value: string) {
    const p = new URLSearchParams(params);
    if (value) p.set(key, value);
    else p.delete(key);
    p.delete("cursor");
    setCursorStack([]);
    setParams(p);
  }
  const conditions = [
    params.get("kev")
      ? { field: "seen_wild", operator: "eq", value: true }
      : null,
    params.get("zero")
      ? { field: "is_zeroday", operator: "eq", value: true }
      : null,
    params.get("priority")
      ? { field: "priority_score", operator: "gte", value: 700 }
      : null,
    params.get("decision")
      ? {
          field: "ssvc_decision",
          operator: "eq",
          value: params.get("decision"),
        }
      : null,
    params.get("severity")
      ? {
          field: "cvss",
          operator: "gte",
          value: Number(params.get("severity")),
        }
      : null,
    params.get("ecosystem")
      ? { field: "ecosystem", operator: "eq", value: params.get("ecosystem") }
      : null,
    onlyWatch ? { field: "id", operator: "in", value: watch } : null,
  ].filter(Boolean);
  const body = {
    text_search: q,
    conditions,
    sort_by: params.get("sort") || "priority_score",
    sort_order: "desc",
    cursor: params.get("cursor") || undefined,
    limit: 10,
  };
  const { data, isPending, error, refetch } = useQuery({
    queryKey: ["explorer", params.toString(), onlyWatch, watch.join()],
    queryFn: () => api<FilterResult>("/api/v2/vulnerabilities/filter", body),
  });
  return (
    <>
      <PageHeading
        title="Vulnerability explorer"
        description="Find the exposure. Understand the evidence. Decide what’s next."
      >
        <button
          className="button secondary"
          onClick={() => setSaveOpen(!saveOpen)}
        >
          <Bookmark size={15} />
          Save view
        </button>
        <ExportButton key={`${q}:${JSON.stringify(conditions)}`} filter={body} name="sentinel-filtered-intelligence.json" primary />
      </PageHeading>
      {saveOpen && (
        <form
          className="inline-save"
          onSubmit={(e) => {
            e.preventDefault();
            if (viewName.trim()) {
              const savedParams = new URLSearchParams(params);
              savedParams.delete("cursor");
              setSaved([
                ...saved,
                { name: viewName.trim(), query: savedParams.toString() },
              ]);
              setSaveOpen(false);
              setViewName("");
            }
          }}
        >
          <label htmlFor="view-name">View name</label>
          <input
            autoFocus
            id="view-name"
            required
            value={viewName}
            onChange={(e) => setViewName(e.target.value)}
            placeholder="e.g. Internet-facing priorities"
          />
          <button className="button primary">Save view</button>
          <button
            type="button"
            className="icon-button"
            aria-label="Cancel save"
            onClick={() => setSaveOpen(false)}
          >
            <X size={17} />
          </button>
        </form>
      )}
      {saved.length > 0 && (
        <div className="saved-views">
          Saved views{" "}
          {saved.map((v, i) => (
            <span key={i}>
              <button
                onClick={() => {
                  setParams(v.query);
                  setCursorStack([]);
                  setInput(new URLSearchParams(v.query).get("q") || "");
                }}
              >
                {v.name}
              </button>
              <button
                aria-label={`Delete ${v.name}`}
                onClick={() => setSaved(saved.filter((_, n) => n !== i))}
              >
                <X size={12} />
              </button>
            </span>
          ))}
        </div>
      )}
      <section className="panel explorer-panel">
        <div className="explorer-search">
          <form
            onSubmit={(e) => {
              e.preventDefault();
              update("q", input);
            }}
          >
            <Search size={18} />
            <input
              aria-label="Search vulnerabilities"
              placeholder="Search CVE, vendor, product, or package…"
              value={input}
              onChange={(e) => setInput(e.target.value)}
            />
            {input && (
              <button
                type="button"
                className="icon-button"
                aria-label="Clear search"
                onClick={() => {
                  setInput("");
                  update("q", "");
                }}
              >
                <X size={15} />
              </button>
            )}
            <button className="button secondary">Search</button>
          </form>
          <button
            className={`button secondary ${advanced ? "selected" : ""}`}
            aria-expanded={advanced}
            aria-controls="advanced-filters"
            onClick={() => setAdvanced(!advanced)}
          >
            <SlidersHorizontal size={15} />
            Filters{activeAdvanced.length > 0 && ` (${activeAdvanced.length})`}
          </button>
        </div>
        <div className="filter-bar">
          <div className="filter-chips">
            <button
              className={`filter-chip ${allActive ? "active" : ""}`}
              aria-pressed={allActive}
              onClick={() => {
                setParams(q ? { q } : {});
                setCursorStack([]);
              }}
            >
              All vulnerabilities
            </button>
            {[
              ["kev", "Known exploited"],
              ["zero", "Zero-days"],
              ["priority", "High priority"],
            ].map(([key, label]) => (
              <button
                key={key}
                className={`filter-chip ${params.get(key) ? "active" : ""}`}
                aria-pressed={!!params.get(key)}
                onClick={() => update(key, params.get(key) ? "" : "true")}
              >
                {label}
              </button>
            ))}
            <button
              className={`filter-chip ${onlyWatch ? "active" : ""}`}
              aria-pressed={onlyWatch}
              onClick={() => {
                update("watch", onlyWatch ? "" : "true");
              }}
            >
              <Bookmark size={13} />
              Watchlist
            </button>
          </div>
          <select
            aria-label="Sort vulnerabilities"
            value={params.get("sort") || "priority_score"}
            onChange={(e) => update("sort", e.target.value)}
          >
            <option value="priority_score">Priority score ↓</option>
            <option value="cvss">CVSS severity ↓</option>
            <option value="epss_score">EPSS probability ↓</option>
            <option value="published">Published date ↓</option>
          </select>
        </div>
        {activeAdvanced.length > 0 && <div className="active-filters" aria-label="Active filters">
          {activeAdvanced.map(key => <button key={key} className="filter-chip active" aria-label={`Remove ${key} filter: ${params.get(key)}`} onClick={() => update(key, "")}>
            {key === "severity" ? `CVSS ≥ ${params.get(key)}` : `${key === "decision" ? "Decision" : "Ecosystem"}: ${params.get(key)}`}<X size={13} />
          </button>)}
        </div>}
        {advanced && (
          <div className="advanced-filters" id="advanced-filters">
            <label>
              Decision
              <select
                value={params.get("decision") || ""}
                onChange={(e) => update("decision", e.target.value)}
              >
                <option value="">Any decision</option>
                {["Act", "Attend", "Track*", "Track", "Unassessed"].map((d) => (
                  <option key={d}>{d}</option>
                ))}
              </select>
            </label>
            <label>
              Severity
              <select
                value={params.get("severity") || ""}
                onChange={(e) => update("severity", e.target.value)}
              >
                <option value="">Any severity</option>
                <option value="9">Critical · 9.0+</option>
                <option value="7">High · 7.0+</option>
                <option value="4">Medium · 4.0+</option>
              </select>
            </label>
            <label>
              Ecosystem
              <select
                value={params.get("ecosystem") || ""}
                onChange={(e) => update("ecosystem", e.target.value)}
              >
                <option value="">All ecosystems</option>
                {["generic", "maven", "npm", "pypi", "golang"].map((d) => (
                  <option key={d}>{d}</option>
                ))}
              </select>
            </label>
            <button
              className="text-link"
              onClick={() => {
                setParams({});
                setInput("");
                setCursorStack([]);
              }}
            >
              Reset filters
            </button>
          </div>
        )}
        {error ? (
          <ErrorBox error={error} retry={() => refetch()} />
        ) : isPending ? (
          <Loading />
        ) : data?.results.length ? (
          <CveRows records={data.results} onSelect={onSelect} sortBy={body.sort_by} />
        ) : (
          <Empty
            title="No matching vulnerabilities"
            description="Try a broader search or reset your filters."
          />
        )}
        <div className="pagination">
          <span>
            {isPending ? "Loading results…" : error ? "Results unavailable" : `${(data?.total || 0).toLocaleString()} matching records`}{" "}
            <span className="muted">· Source-backed records</span>
          </span>
          <div>
            <button
              className="button secondary"
              disabled={!params.get("cursor")}
              onClick={() => {
                const next = [...cursorStack];
                const prev = next.pop();
                const p = new URLSearchParams(params);
                if (prev) p.set("cursor", prev);
                else p.delete("cursor");
                setCursorStack(next);
                setParams(p);
              }}
            >
              <ChevronLeft size={14} />
              Previous
            </button>
            <button
              className="button secondary"
              disabled={!data?.next_cursor}
              onClick={() => {
                if (data?.next_cursor) {
                  setCursorStack([...cursorStack, params.get("cursor") || ""]);
                  const p = new URLSearchParams(params);
                  p.set("cursor", data.next_cursor);
                  setParams(p);
                }
              }}
            >
              Next
              <ChevronRight size={14} />
            </button>
          </div>
        </div>
      </section>
      <div className="note">
        <Info size={16} />
        Priority scores use observed evidence. Missing SSVC context is shown as Unassessed.
      </div>
    </>
  );
}

export function Actors({
  ransomware = false,
  onSelect,
}: SelectProps & { ransomware?: boolean }) {
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<Actor | null>(null);
  const detailRef = useRef<HTMLElement>(null);
  const { data, error, isPending } = useQuery({
    queryKey: ["actors"],
    queryFn: async () => {
      const first = await api<{results:Actor[];total:number}>("/api/threat-actors",{limit:100});
      const results = [...first.results];
      while(results.length < first.total){
        if(results.length>=10000)throw new Error("Actor catalog exceeds the 10,000-record view budget.");
        const page = await api<{results:Actor[]}>("/api/threat-actors",{limit:100,skip:results.length});
        if(!page.results.length)break;
        results.push(...page.results);
      }
      return {results};
    },
  });
  const actors =
    data?.results.filter(
      (a) =>
        (a.type === "Ransomware") === ransomware &&
        `${a.id} ${a.aliases.join(" ")} ${a.country}`
          .toLowerCase()
          .includes(query.toLowerCase()),
    ) || [];
  const actor =
    (selected && actors.find((a) => a.id === selected.id)) || actors[0];
  return (
    <>
      <PageHeading
        title={
          ransomware ? "Ransomware intelligence" : "Threat actor intelligence"
        }
        description={
          ransomware
            ? "Connect ransomware activity to the exposures behind it."
            : "Understand the adversaries, their methods, and your exposure."
        }
      />
      <div className="note top-note">
        <Info size={16} />
        Profiles and relationships are reported by their named sources. Missing attribution is left unknown.
      </div>
      <div className="actor-layout">
        <section className="panel actor-list" aria-label={ransomware ? "Ransomware profiles" : "Threat actor profiles"}>
          <div className="search-field">
            <Search size={16} />
            <input
              aria-label="Search threat actors"
              placeholder="Search name, alias, country…"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
          </div>
          <div className="actor-results">
          {isPending ? (
            <Loading />
          ) : error ? (
            <ErrorBox error={error} />
          ) : actors.length ? (
            actors.map((a) => (
              <button
                key={a.id}
                className={`actor-list-item ${actor?.id === a.id ? "active" : ""}`}
                aria-pressed={actor?.id === a.id}
                onClick={() => {
                  setSelected(a);
                  if (window.matchMedia("(max-width: 1000px)").matches) {
                    detailRef.current?.focus({ preventScroll: true });
                    detailRef.current?.scrollIntoView({ block: "start", behavior: "instant" });
                  }
                }}
              >
                <span
                  className={`actor-monogram ${ransomware ? "ransom" : ""}`}
                >
                  {a.id
                    .split(" ")
                    .map((w) => w[0])
                    .slice(0, 2)
                    .join("")}
                </span>
                <span>
                  <strong>{a.id}</strong>
                  <small>
                    {a.country} <span>·</span> {a.cves_exploited.length} CVEs
                  </small>
                </span>
                <ChevronRight size={16} />
              </button>
            ))
          ) : (
            <Empty
              title="No profiles found"
              description="Try another actor or country."
            />
          )}
          </div>
        </section>
        {actor && (
          <section className="panel actor-detail" ref={detailRef} tabIndex={-1} aria-label={`${actor.id} profile`}>
            <div className="actor-heading">
              <div className="actor-monogram large">
                {actor.id.slice(0, 2).toUpperCase()}
              </div>
              <div>
                <Badge tone="neutral">{actor.type}</Badge>
                <h2>{actor.id}</h2>
                <p>{actor.aliases.join(" / ")}</p>{actor.provenance&&<a className="text-link" href={actor.provenance.url} target="_blank" rel="noreferrer">Source: {actor.source}<ExternalLink size={12}/></a>}
              </div>
              <Globe2 size={23} />
            </div>
            <SourceDescription text={actor.description || "No description supplied by source."} />
            <div className="actor-facts">
              <div>
                <span>Attribution</span>
                <strong>{actor.country}</strong>
              </div>
              <div>
                <span>{actor.source === "MITRE ATT&CK" ? "Profile created" : "First observed"}</span>
                <strong>{actor.first_seen ? new Date(actor.first_seen).toLocaleDateString() : "Not reported"}</strong>
              </div>
              <div>
                <span>Linked vulnerabilities</span>
                <strong>{actor.cves_exploited.length}</strong>
              </div>
            </div>
            <h3>Connected intelligence</h3>
            {actor.techniques.length ? <Graph nodes={[{id:'actor',position:{x:0,y:90},data:{label:actor.id}},...actor.techniques.slice(0,6).map((t,i)=>({id:t,position:{x:270,y:i*85},data:{label:t}}))]} edges={actor.techniques.slice(0,6).map(t=>({id:t,source:'actor',target:t,label:'uses · MITRE ATT&CK'}))}/> : <p className="evidence-empty">No technique relationships reported by the source.</p>}
            <div className="actor-bottom">
              <div>
                <h3>Target sectors</h3>
                <div className="flex gap-2 flex-wrap">
                  {!actor.target_category.length && <p className="muted">No target sectors reported.</p>}
                  {actor.target_category.map((t) => (
                    <Badge key={t}>{t}</Badge>
                  ))}
                </div>
              </div>
              <div>
                <h3>ATT&CK techniques</h3>
                <div className="flex gap-2 flex-wrap">
                  {!actor.techniques.length && <p className="muted">No techniques reported.</p>}
                  {actor.techniques.map((t) => (
                    <a
                      className="badge blue"
                      key={t}
                      href={`https://attack.mitre.org/techniques/${t}/`}
                      target="_blank"
                      rel="noreferrer"
                    >
                      {t}
                      <ArrowUpRight size={11} />
                    </a>
                  ))}
                </div>
              </div>
            </div>
            <h3>Source-linked vulnerabilities</h3>
            <div className="related-cves">
              {!actor.cves_exploited.length && <p className="muted">No vulnerabilities linked by the source.</p>}
              {actor.cves_exploited.map((c) => (
                <button key={c} onClick={() => onSelect(c)}>
                  {c}
                  <ArrowUpRight size={15} />
                </button>
              ))}
            </div>
          </section>
        )}
      </div>
    </>
  );
}

interface Product {
  name: string;
  vendor: string;
  ecosystem: string;
  purl: string;
  cpe: string;
  affected_version_range: string;
  fixed_version: string;
  cve_id: string;
  priority_score: number;
  is_malicious_package: boolean;
}
export function SupplyChain({ onSelect }: SelectProps) {
  const [q, setQ] = useState("");
  const [ecosystem, setEcosystem] = useState("");
  const { data, error, isPending } = useQuery({
    queryKey: ["products", q, ecosystem],
    queryFn: () =>
      api<{ results: Product[]; total: number }>("/api/affected-product", {
        name: q,
        ecosystem,
      }),
  });
  return (
    <>
      <PageHeading
        title="Supply-chain intelligence"
        description="One view of vulnerable software, from infrastructure to dependencies."
      />
      <div className="supply-intro">
        <Package size={33} />
        <div>
          <h2>Every package. Both coordinates.</h2>
          <p>
            Search PURL and CPE identifiers together. Trace affected versions to
            the fix.
          </p>
        </div>
        <Badge>Source-backed identifiers</Badge>
      </div>
      <section className="panel">
        <div className="explorer-search">
          <div className="search-field">
            <Search size={17} />
            <input
              aria-label="Search packages"
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="Search Apache, axios, pkg:maven…"
            />
          </div>
          <select
            aria-label="Package ecosystem"
            value={ecosystem}
            onChange={(e) => setEcosystem(e.target.value)}
          >
            <option value="">All ecosystems</option>
            {["generic", "maven", "npm", "pypi", "golang"].map((e) => (
              <option key={e}>{e}</option>
            ))}
          </select>
        </div>
        {error ? (
          <ErrorBox error={error} />
        ) : isPending ? (
          <Loading />
        ) : !data?.results.length ? (
          <Empty
            title="No matching packages"
            description="Search a different product or ecosystem."
          />
        ) : (
          <div className="table-scroll">
            <table className="intel-table product-table">
              <thead>
                <tr>
                  <th>Package</th>
                  <th>Coordinates</th>
                  <th>Affected range</th>
                  <th>Fixed version</th>
                  <th>Vulnerability</th>
                </tr>
              </thead>
              <tbody>
                {data.results.map((p) => (
                  <tr key={p.cve_id}>
                    <td>
                      <strong>{p.name}</strong>
                      <span className="table-description">
                        {p.vendor}{" "}
                        <Badge
                          tone={p.is_malicious_package ? "danger" : "neutral"}
                        >
                          {p.is_malicious_package ? "Backdoor" : p.ecosystem}
                        </Badge>
                      </span>
                    </td>
                    <td>
                      <code>{p.purl}</code>
                      <span className="table-description cpe-text">
                        {p.cpe}
                      </span>
                    </td>
                    <td>{p.affected_version_range}</td>
                    <td>
                      <span className="fix-version">
                        <ShieldCheck size={13} />
                        {p.fixed_version}
                      </span>
                    </td>
                    <td>
                      <button
                        className="text-link"
                        onClick={() => onSelect(p.cve_id)}
                      >
                        {p.cve_id}
                        <ArrowUpRight size={14} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <div className="pagination">
          <span>{data?.total || 0} package records</span>
          <Link className="text-link" to="/vi/tools/sbom-vex">
            Analyze your SBOM <ArrowRight size={15} />
          </Link>
        </div>
      </section>
    </>
  );
}

interface Patch {
  id: string;
  product: string;
  build_number: string;
  published: string;
  superseded_by: string[];
}
export function PatchLookup() {
  const [kb, setKb] = useState("");
  const mutation = useMutation({
    mutationFn: () => api<{ results: Patch[] }>("/api/kb-supercedence", { kb }),
  });
  const patches = mutation.data?.results || [];
  return (
    <>
      <PageHeading
        title="KB supersedence lookup"
        description="Follow the patch chain. Find the cumulative update that covers it."
      />
      <section className="panel tool-panel">
        <div className="tool-intro">
          <span className="tool-icon">
            <GitBranch size={25} />
          </span>
          <h2>Trace a Windows update</h2>
          <p>
            Enter a Microsoft KB identifier to visualize its superseding
            patches.
          </p>
        </div>
        <form
          className="kb-form"
          onSubmit={(e) => {
            e.preventDefault();
            mutation.mutate();
          }}
        >
          <label htmlFor="kb">Knowledge Base article</label>
          <div>
            <input
              id="kb"
              value={kb}
              onChange={(e) => setKb(e.target.value)}
              placeholder="Enter a KB identifier"
              required
              pattern="[Kk][Bb][0-9]{7}"
            />
            <button className="button primary" disabled={mutation.isPending}>
              {mutation.isPending ? "Looking up…" : "Trace patch chain"}
              <ArrowRight size={16} />
            </button>
          </div>
          <small>
            Patch relationships are ingested from Microsoft MSRC security updates.
          </small>
        </form>
      </section>
      {mutation.error && <ErrorBox error={mutation.error} />}{" "}
      {patches.length > 0 ? (
        <section className="panel patch-results">
          <div className="panel-header">
            <div>
              <h2>
                Patch relationships for {patches[0].id}
              </h2>
              <p>{patches[0].product} · Microsoft MSRC source data</p>
            </div>
            <button
              className="button secondary"
              onClick={() => download(patches, "kb-patch-chain.json")}
            >
              <ArrowDownToLine size={15} />
              Export
            </button>
          </div>
          <Graph
            nodes={patches.map((p,i) => ({
              id: `${p.id}:${p.product}`,
              position: { x: i * 235, y: 40 },
              data: {
                label: (
                  <div>
                    <strong>{p.id}</strong>
                    <small className="block mt-2">Build {p.build_number}</small>
                  </div>
                ),
              },
              style: i === patches.length - 1 ? { borderColor: "#60b885" } : {},
            }))}
            edges={patches.flatMap(p=>(p.superseded_by||[]).filter(next=>patches.some(row=>row.id===next&&row.product===p.product)).map(next=>({id:`${p.id}:${next}:${p.product}`,source:`${p.id}:${p.product}`,target:`${next}:${p.product}`,label:'superseded by'})))}
          />
          <div className="patch-list">
            {patches.map((p) => (
              <div key={`${p.id}:${p.product}`}>
                <span className="patch-node">
                  <Check size={14} />
                </span>
                <div>
                  <strong>{p.id}</strong>
                  <p>
                    {p.product} · Build {p.build_number}
                  </p>
                </div>
                <span>{p.published}</span>
                {!p.superseded_by?.length && (
                  <Badge tone="success">No ingested successor</Badge>
                )}
                <a
                  aria-label={`Read ${p.id}`}
                  href={`https://support.microsoft.com/help/${p.id.slice(2)}`}
                  target="_blank"
                  rel="noreferrer"
                >
                  <ExternalLink size={15} />
                </a>
              </div>
            ))}
          </div>
        </section>
      ) : (
        !mutation.error && (
          <div className="tool-empty">
            <GitBranch size={45} />
            <h3>A clearer path to patching.</h3>
            <p>The supersedence graph will appear here after lookup.</p>
          </div>
        )
      )}
    </>
  );
}

const manifestTemplate = {
  bomFormat: "CycloneDX",
  specVersion: "1.5",
  version: 1,
  components: [
    {
      type: "library",
      name: "log4j-core",
      version: "2.14.1",
      purl: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
    },
    {
      type: "library",
      name: "axios",
      version: "1.7.2",
      purl: "pkg:npm/axios@1.7.2",
    },
    {
      type: "library",
      name: "requests",
      version: "2.31.0",
      purl: "pkg:pypi/requests@2.31.0",
    },
  ],
};
const justifications = [
  "component_not_present",
  "vulnerable_code_not_present",
  "vulnerable_code_not_in_execute_path",
  "vulnerable_code_cannot_be_controlled_by_adversary",
  "inline_mitigations_already_exist",
];
interface Finding {
  in_catalog: boolean;
  advisory: {id:string};
  provenance: {url:string};
  vulnerability: Vulnerability;
  purl: string;
  suppressed: boolean;
  effective_priority: number;
  statement: unknown;
}
interface Analysis {
  packages: number;
  findings: Finding[];
  suppressed: number;
  unversioned: string[];
  trust: string;
}
export function Workbench({ onSelect }: SelectProps) {
  const {data:identity}=useIdentity();
  const [tab, setTab] = useState("Analyze SBOM");
  const [text, setText] = useState("");
  const [parseError, setParseError] = useState("");
  const input = useRef<HTMLInputElement>(null);
  const [author, setAuthor] = useState("");
  const [cve, setCve] = useState("");
  const [purl, setPurl] = useState("");
  const [status, setStatus] = useState("not_affected");
  const [justification, setJustification] = useState(justifications[2]);
  const [impact, setImpact] = useState("");
  const [savedDoc, setSavedDoc] = useState<unknown>(null);
  const qc = useQueryClient();
  const { data: vex } = useQuery({
    queryKey: ["vex"],
    queryFn: () => api<{ results: unknown[]; truncated?: boolean }>("/api/v2/vex"),
  });
  const analyze = useMutation({
    mutationFn: (doc: unknown) =>
      api<Analysis>("/api/v2/sbom/analyze", { sbom: doc }),
  });
  const save = useMutation({
    mutationFn: (doc: unknown) => api("/api/v2/vex", doc),
    onSuccess: (_, doc) => {
      setSavedDoc(doc);
      qc.invalidateQueries({ queryKey: ["vex"] });
    },
  });
  function run() {
    try {
      const doc = JSON.parse(text);
      setParseError("");
      analyze.mutate(doc);
    } catch {
      setParseError("Invalid JSON. Check the document syntax and try again.");
    }
  }
  function generate() {
    const doc = {
      "@context": "https://openvex.dev/ns/v0.2.0",
      "@id": `urn:uuid:${crypto.randomUUID()}`,
      author,
      timestamp: new Date().toISOString(),
      version: 1,
      statements: [
        {
          vulnerability: { name: cve },
          products: [{ "@id": purl }],
          status,
          ...(status === "not_affected" ? { justification } : {}),
          impact_statement: impact,
        },
      ],
    };
    save.mutate(doc);
  }
  return (
    <>
      <PageHeading
        title="SBOM & VEX workbench"
        description="Turn a dependency list into a focused, auditable response."
      />
      <nav className="tabs page-tabs">
        {["Analyze SBOM", "Create OpenVEX"].map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={tab === t ? "active" : ""}
          >
            {t}
          </button>
        ))}
        <span>{vex?.results.length || 0}{vex?.truncated ? "+" : ""} saved documents</span>
      </nav>
      {tab === "Analyze SBOM" ? (
        <>
          <section className="panel sbom-panel">
            <div className="panel-header">
              <div>
                <h2>What’s in your software?</h2>
                <p>Upload CycloneDX or SPDX JSON, or paste it below. Analysis sends package names and versions to the public OSV service.</p>
              </div>
              <button
                className="button secondary"
                onClick={() => {
                  setText(JSON.stringify(manifestTemplate, null, 2));
                  setParseError("");
                }}
              >
                <FileJson size={15} />
                Manifest template
              </button>
            </div>
            <div className="sbom-grid">
              <button
                className="upload-area"
                onClick={() => input.current?.click()}
                onDragOver={(e) => e.preventDefault()}
                onDrop={async (e) => {
                  e.preventDefault();
                  const file = e.dataTransfer.files[0];
                  if (file) {
                    if (file.size > 10_000_000) {
                      setParseError("File must be smaller than 10 MB");
                      return;
                    }
                    setText(await file.text());
                    setParseError("");
                  }
                }}
              >
                <span>
                  <Upload size={25} />
                </span>
                <strong>Drop your SBOM here</strong>
                <p>or click to choose a file</p>
                <small>JSON · CycloneDX or SPDX · Up to 10 MB</small>
              </button>
              <input
                ref={input}
                type="file"
                accept=".json,application/json"
                className="hidden"
                aria-label="Upload SBOM file"
                onChange={async (e) => {
                  const file = e.target.files?.[0];
                  if (file) {
                    if (file.size > 10_000_000) {
                      setParseError("File must be smaller than 10 MB");
                      return;
                    }
                    setText(await file.text());
                    setParseError("");
                  }
                }}
              />
              <textarea
                aria-label="SBOM JSON"
                placeholder={
                  '{\n  "bomFormat": "CycloneDX",\n  "components": [...]\n}'
                }
                value={text}
                onChange={(e) => setText(e.target.value)}
                spellCheck={false}
              />
            </div>
            <div className="sbom-actions">
              <span>
                <ShieldCheck size={15} />
                {permits(identity,"analyze")?"Processed by your local API":"Your role does not permit analysis"}
              </span>
              <button
                className="button primary"
                disabled={!permits(identity,"analyze") || !text.trim() || analyze.isPending}
                onClick={run}
              >
                {analyze.isPending ? "Analyzing…" : "Analyze dependencies"}
                <ArrowRight size={15} />
              </button>
            </div>
            {parseError && (
              <p className="form-error" role="alert">
                {parseError}
              </p>
            )}
          </section>
          {analyze.error && <ErrorBox error={analyze.error} />}{" "}
          {analyze.data && (
            <section className="panel analysis-results">
              <div className="panel-header">
                <div>
                  <h2>Your dependency exposure</h2>
                  <p>
                    {analyze.data.packages} packages ·{" "}
                    {analyze.data.findings.length} findings ·{" "}
                    {analyze.data.suppressed} suppressed by VEX
                  </p>
                </div>
                <button
                  className="button secondary"
                  onClick={() => download(analyze.data, "sbom-analysis.json")}
                >
                  <ArrowDownToLine size={15} />
                  Export results
                </button>
              </div>
              {analyze.data.unversioned.length > 0 && (
                <div className="note">
                  Unversioned packages could not be assessed:{" "}
                  {analyze.data.unversioned.join(", ")}
                </div>
              )}
              {analyze.data.findings.length ? (
                <div className="finding-list">
                  {analyze.data.findings.map((f, i) => (
                    <div className="finding" key={i}>
                      {f.in_catalog ? <button onClick={() => onSelect(f.vulnerability.id)}>
                        <strong>{f.vulnerability.id}<ArrowUpRight size={14}/></strong><span>{f.purl}</span>
                      </button> : <a className="finding-source" href={`https://osv.dev/vulnerability/${encodeURIComponent(f.advisory.id)}`} target="_blank" rel="noreferrer"><strong>{f.vulnerability.id}<ExternalLink size={14}/></strong><span>{f.purl}</span></a>}
                      <Decision
                        value={
                          f.suppressed ? "Track" : f.vulnerability.ssvc_decision
                        }
                      />
                      <Badge tone={f.suppressed ? "success" : "danger"}>
                        {f.suppressed
                          ? "Suppressed"
                          : `${f.effective_priority} priority`}
                      </Badge>
                      <button
                        className="text-link"
                        onClick={() => {
                          setCve(f.vulnerability.id);
                          setPurl(f.purl);
                          setTab("Create OpenVEX");
                          setSavedDoc(null);
                        }}
                      >
                        Create VEX <Plus size={14} />
                      </button>
                    </div>
                  ))}
                </div>
              ) : (
                <Empty
                  title="No matches returned by OSV"
                  description="Coverage depends on the supplied package coordinates and upstream advisory data. Unversioned components remain unassessed."
                />
              )}
              <div className="note">
                <Info size={15} />
                {analyze.data.trust}
              </div>
            </section>
          )}
        </>
      ) : (
        <section className="panel vex-panel">
          <div>
            <h2>Explain why a finding doesn’t apply.</h2>
            <p className="muted">
              Create an OpenVEX v0.2.0 statement scoped to a specific product
              version.
            </p>
            <form
              onSubmit={(e) => {
                e.preventDefault();
                generate();
              }}
            >
              <label>
                Statement author
                <input
                  required
                  value={author}
                  onChange={(e) => setAuthor(e.target.value)}
                  placeholder="Your organization or team"
                />
              </label>
              <div className="form-grid">
                <label>
                  Vulnerability
                  <input
                    required
                    value={cve}
                    pattern="CVE-[0-9]{4}-[0-9]{4,}"
                    onChange={(e) => setCve(e.target.value)}
                  />
                </label>
                <label>
                  Status
                  <select
                    value={status}
                    onChange={(e) => setStatus(e.target.value)}
                  >
                    {[
                      "not_affected",
                      "affected",
                      "fixed",
                      "under_investigation",
                    ].map((s) => (
                      <option key={s}>{s}</option>
                    ))}
                  </select>
                </label>
              </div>
              <label>
                Versioned product PURL
                <input
                  required
                  value={purl}
                  onChange={(e) => setPurl(e.target.value)}
                  placeholder="pkg:npm/your-package@1.0.0"
                />
              </label>
              {status === "not_affected" && (
                <label>
                  Justification
                  <select
                    value={justification}
                    onChange={(e) => setJustification(e.target.value)}
                  >
                    {justifications.map((j) => (
                      <option key={j}>{j}</option>
                    ))}
                  </select>
                </label>
              )}
              <label>
                Impact statement
                <textarea
                  required
                  value={impact}
                  onChange={(e) => setImpact(e.target.value)}
                  placeholder="Describe the evidence supporting this assessment…"
                />
              </label>
              <div className="note">
                <Info size={15} />
                Saved locally as an unsigned analyst statement. Signing and
                publisher trust validation require a production integration.
              </div>
              <button className="button primary" disabled={!permits(identity,"vex:write") || save.isPending}>
                {save.isPending ? "Saving…" : "Save OpenVEX statement"}
                <ShieldCheck size={15} />
              </button>
            </form>
            {save.error && (
              <p className="form-error" role="alert">
                {save.error.message}
              </p>
            )}
            {savedDoc !== null && (
              <div className="vex-success">
                <Check size={20} />
                <span>
                  Statement saved. Re-analyze the same SBOM to apply it.
                </span>
                <button
                  className="text-link"
                  onClick={() => download(savedDoc, "openvex.json")}
                >
                  Download JSON <ArrowDownToLine size={14} />
                </button>
              </div>
            )}
          </div>
          <aside>
            <FileJson size={35} />
            <h3>Fewer alerts. More evidence.</h3>
            <p>
              Suppression is applied only to the matching CVE and exact
              versioned product PURL.
            </p>
            <p>
              Global intelligence and scores stay intact, preserving the audit
              trail.
            </p>
            <Badge tone="blue">OpenVEX v0.2.0</Badge>
          </aside>
        </section>
      )}
    </>
  );
}

export function Sources() {
 const {data:identity}=useIdentity();
 const qc=useQueryClient();const {data,error}=useQuery({queryKey:['stats'],queryFn:()=>api<Stats>('/api/stats/'),refetchInterval:10000,enabled:permits(identity,'ingest')});
 const sync=useMutation({mutationFn:(source:string)=>api<{queued:boolean}>('/api/admin/ingest',{source}),onSuccess:()=>qc.invalidateQueries({queryKey:['stats']})});
 const {data:jobs}=useQuery({queryKey:['ingestion-jobs'],queryFn:()=>api<{results:{id:number;source_name:string;status:string;detail:string|null}[]}>('/api/admin/jobs'),refetchInterval:10000,enabled:permits(identity,'ingest')});
 return <><PageHeading title="Data sources" description="Public intelligence, traceable evidence, and continuous ingestion."/><div className="source-banner"><Database size={25}/><div><h2>Intelligence starts at the source.</h2><p>{data?.total||0} CVEs ingested. Each connector records its last successful run, source evidence, and failures.</p></div><Badge tone="blue">Open-source stack</Badge></div>{sync.error&&<ErrorBox error={sync.error}/>} {sync.data&&<div className="note"><Check size={15}/>{sync.data.queued?'Sync queued. The worker will pick it up.':'A sync is already queued or running.'}</div>}<section className="panel">{error?<ErrorBox error={error}/>:!data?<Loading/>:<div className="source-list">{data.sources.map(source=><div className="source-row" key={source.source_name}><div className="source-logo"><Database size={20}/></div><div className="source-details"><h3>{source.source_name}</h3><p>{source.last_success_at?`Last success ${new Date(source.last_success_at).toLocaleString()}`:'Awaiting first successful ingestion'} · {source.records||0} records in last run</p>{source.last_error&&<p className="form-error">{source.last_error}</p>}{source.configuration_required&&<p>{source.configuration_required}</p>}{source.coverage&&<p>{source.coverage}</p>}</div><Badge tone={source.status==='Healthy'?'success':source.status==='Error'?'danger':'neutral'}>{source.status}</Badge><button className="button secondary" disabled={!permits(identity,'ingest')||sync.isPending||source.status==='Running'} onClick={()=>sync.mutate(source.source_name)}>Sync now</button></div>)}</div>}</section>{jobs?.results.length? <section className="panel connector-instructions"><h2>Recent ingestion jobs</h2>{jobs.results.slice(0,12).map(job=><div className="note" key={job.id}><span>{job.source_name}</span><Badge>{job.status}</Badge>{job.detail&&<span>{job.detail}</span>}</div>)}</section>:null}<div className="panel connector-instructions"><h2>Continuous source reconciliation</h2><p>The worker runs independently of the API. PostgreSQL commits each page and checkpoint together, and API queries see committed changes immediately.</p><p className="muted small">A failed or blocked upstream source remains visible here. No demonstration records are substituted. Vendor VEX imports require a configured publisher verification process.</p></div></>;
}
export function Developer() {
  const [mcpCopied, setMcpCopied] = useState(false);
  const [mcpCopyError, setMcpCopyError] = useState(false);
  const localDev = import.meta.env.DEV && ["localhost", "127.0.0.1", "[::1]"].includes(window.location.hostname);
  const mcpUrl = localDev ? "http://127.0.0.1:8080/api/mcp" : `${window.location.origin}/api/mcp`;
  const mcpConfig = JSON.stringify({mcpServers: {sentinel: {type: "http", url: mcpUrl, headers: {Authorization: "Bearer <SCOPED_CLIENT_TOKEN>"}}}}, null, 2);
  const [copied, setCopied] = useState(false);
  const example =
    'curl -X POST http://localhost:8080/api/v2/vulnerabilities/filter \\\n  -H "Content-Type: application/json" \\\n  -d \'{"conditions":[{"field":"seen_wild","operator":"eq","value":true}],"limit":10}\'';
  return (
    <>
      <PageHeading
        title="API & integrations"
        description="Bring intelligence into the tools where your team already works."
      >
        <a
          className="button primary"
          href="/scalar"
          target="_blank"
          rel="noreferrer"
        >
          Open API reference
          <ArrowUpRight size={16} />
        </a>
      </PageHeading>
      <div className="developer-hero">
        <TerminalIcon />
        <div>
          <h2>Built to be connected.</h2>
          <p>
            Query CVEs over REST or GraphQL, analyze SBOMs, and export STIX 2.1
            vulnerability objects.
          </p>
          <Badge tone="blue">Authenticated API · v0.2.0</Badge>
        </div>
      </div>
      <section className="panel code-panel mcp-panel">
        <div className="panel-header">
          <div>
            <h2>Connect an AI with MCP</h2>
            <p>Give your MCP-compatible assistant direct access to source-backed intelligence.</p>
          </div>
          <button className="button secondary" onClick={async () => {
            try { await navigator.clipboard.writeText(mcpConfig); setMcpCopyError(false); setMcpCopied(true); setTimeout(() => setMcpCopied(false), 2000); }
            catch { setMcpCopyError(true); }
          }}>{mcpCopied ? <Check size={15}/> : <Copy size={15}/>} {mcpCopied ? "Copied" : "Copy MCP config"}</button>
        </div>
        <p><Badge tone="blue">Streamable HTTP</Badge> <code>{mcpUrl}</code></p>
        <p>In your assistant’s MCP settings, add this server URL and set the Authorization header to <code>Bearer &lt;SCOPED_CLIENT_TOKEN&gt;</code>. Create an expiring client credential with the read scope using the deployment’s client-token utility. Replace the placeholder privately in your client. The operator token grants full administration.</p>
        <pre><code>{mcpConfig}</code></pre>
        {mcpCopyError && <p role="alert">Copy was unavailable. Select and copy the configuration above.</p>}
        <p className="muted small">Configuration keys vary by client. Supports MCP 2025-03-26, 2025-06-18 and 2025-11-25. Clients must support one of these versions and bearer headers; OAuth-only connectors need an authentication gateway.</p>
        <p className="muted small">For local development, keep <code>npm run dev</code> running from the project directory and connect to <code>http://127.0.0.1:8080/api/mcp</code>. If initialization reports “connection refused”, start Sentinel and reconnect your MCP client. PostgreSQL and Valkey alone do not serve MCP. Clients that use <code>serverUrl</code> instead of <code>url</code> should put the endpoint in that field.</p>
        <h3>Available AI tools</h3>
        <p>Search vulnerabilities, retrieve CVE evidence, read detection rules and relationships, search actors and products, look up KB patches, and inspect dataset counts and source status.</p>
        <p className="muted small">Nine read-only tools query the same committed data as this app. For stdio clients, launch <code>node /absolute/path/to/threat-intel/scripts/mcp-stdio.mjs</code> with <code>VI_MCP_URL</code> and <code>VI_API_TOKEN</code> in the client’s environment. Public clients need a reachable HTTPS deployment.</p>
      </section>
      <section className="panel code-panel">
        <div className="panel-header">
          <div>
            <h2>Your first query</h2>
            <p>Find known exploited vulnerabilities, sorted by priority.</p>
          </div>
          <button
            className="button secondary"
            onClick={() => {
              navigator.clipboard
                .writeText(example)
                .then(() => {
                  setCopied(true);
                  setTimeout(() => setCopied(false), 2000);
                })
                .catch(() => {});
            }}
          >
            {copied ? <Check size={15} /> : <Copy size={15} />}{" "}
            {copied ? "Copied" : "Copy request"}
          </button>
        </div>
        <pre>
          <code>{example}</code>
        </pre>
      </section>
      <section className="panel endpoint-list">
        <h2>Available endpoints</h2>
        {[
          ["GET", "/api/stats/", "Dataset counts and ingestion status"],
          [
            "POST",
            "/api/v2/vulnerabilities/filter",
            "Search, filters, facets, and cursor pagination",
          ],
          [
            "GET",
            "/api/vulnerabilities/{id}",
            "CVE evidence and explainable scores",
          ],
          ["POST", "/api/threat-actors", "Actor and ransomware profiles"],
          ["POST", "/api/affected-product", "Unified package search"],
          ["POST", "/api/kb-supercedence", "Cycle-safe patch-chain traversal"],
          ["POST", "/api/v2/sbom/analyze", "CycloneDX / SPDX package analysis"],
          ["POST", "/api/v2/vex", "Validated local OpenVEX statements"],
          ["POST", "/api/graphql", "GraphQL vulnerability query"],
          ["POST", "/api/mcp", "MCP discovery and read-only AI tools"],
          [
            "GET",
            "/api/v21/collections/sentinel/objects/",
            "STIX 2.1 export envelope",
          ],
        ].map(([method, path, desc]) => (
          <div key={path}>
            <Badge tone={method === "GET" ? "success" : "blue"}>{method}</Badge>
            <code>{path}</code>
            <span>{desc}</span>
          </div>
        ))}
      </section>
      <div className="note">
        <Info size={16} />
        Production mode requires an access token, PostgreSQL, and Valkey. Operator sessions use HttpOnly cookies. Keep the public endpoint behind TLS.
      </div>
    </>
  );
}
function TerminalIcon() {
  return (
    <span className="terminal-symbol">
      <Code2 size={40} />
    </span>
  );
}

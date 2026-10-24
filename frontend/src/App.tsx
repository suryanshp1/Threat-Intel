import {useIdentity} from "./identity";
import {AuditManagement} from "./audit";
import { logoutSession } from "./session";
import { TourWelcome, UserTour } from "./tour";
import { hasSeenTour, rememberTour } from "./tour-data";
import { useState, useEffect, useRef } from "react";
import {
  NavLink,
  Routes,
  Route,
  useNavigate,
  useLocation,
} from "react-router-dom";
import {
  ArrowUpRight,
  Bell,
  BookOpen,
  ChevronsUpDown,
  CircleHelp,
  Compass,
  Database,
  Fingerprint,
  Globe2,
  LayoutDashboard,
  LogOut,
  Link2,
  Menu,
  Network,
  Package,
  Search,
  Settings2,
  Shield,
  ShieldCheck,
  Terminal,
  X,
} from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { api, type Stats } from "./types";
import { AccessGate } from "./auth";
import { ThemeToggle } from "./theme";
import { DetailDrawer, useStored } from "./components";
import {
  Overview,
  Explorer,
  Actors,
  SupplyChain,
  PatchLookup,
  Workbench,
  Sources,
  Developer,
} from "./pages";
const navigation = [
  { label: "Overview", path: "/vi", icon: LayoutDashboard },
  { label: "Vulnerabilities", path: "/vi/explore", icon: Shield },
  { label: "Threat actors", path: "/vi/threat-actors", icon: Fingerprint },
  { label: "Ransomware", path: "/vi/ransomware-groups", icon: Network },
  { label: "Supply chain", path: "/vi/supply-chain", icon: Package },
];
export default function App() {
  const {data:identity}=useIdentity();
  const [authRequired,setAuthRequired]=useState(false);
  const [logoutError,setLogoutError]=useState("");
  useEffect(()=>{const onAuth=()=>setAuthRequired(true);window.addEventListener("sentinel-auth-required",onAuth);return()=>window.removeEventListener("sentinel-auth-required",onAuth)},[]);
  const [mobile, setMobile] = useState(false);
  const [compact, setCompact] = useState(() => window.matchMedia("(max-width: 760px)").matches);
  const sidebarRef = useRef<HTMLElement>(null);
  const menuTrigger = useRef<HTMLButtonElement>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [watchOpen, setWatchOpen] = useState(false);
  const [tourActive, setTourActive] = useState(false);
  const tourTrigger = useRef<HTMLButtonElement>(null);
  useEffect(() => { if (authRequired) setTourActive(false); }, [authRequired]);
  const [tourWelcome, setTourWelcome] = useState(() => {
    try { return !hasSeenTour(window.localStorage); } catch { return true; }
  });
  const dismissTourWelcome = () => {
    setTourWelcome(false);
    try { rememberTour(window.localStorage); } catch { /* Storage may be blocked. */ }
  };
  const startTour = () => {
    dismissTourWelcome();
    setMobile(false);
    setWatchOpen(false);
    setTourActive(true);
  };
  const [watch] = useStored<string[]>("sentinel-watchlist", []);
  const navigate = useNavigate();
  const location = useLocation();
  const mobileOpen = compact && mobile && !authRequired;
  useEffect(() => {
    const media = window.matchMedia("(max-width: 760px)");
    const change = () => { setCompact(media.matches); setMobile(false); };
    media.addEventListener("change", change);
    return () => media.removeEventListener("change", change);
  }, []);
  useEffect(() => { setMobile(false); setWatchOpen(false); }, [location.pathname, location.search]);
  useEffect(() => {
    if (!mobileOpen) return;
    const sidebar = sidebarRef.current;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    const controls = () => Array.from(sidebar?.querySelectorAll<HTMLElement>(
      'a[href],button:not(:disabled),input:not(:disabled),[tabindex="0"]',
    ) || []).filter(element => element.getClientRects().length > 0);
    controls()[0]?.focus();
    const handleKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") { event.preventDefault(); setMobile(false); }
      if (event.key !== "Tab") return;
      const items = controls();
      const first = items[0], last = items[items.length - 1];
      if (event.shiftKey && (document.activeElement === first || !sidebar?.contains(document.activeElement))) {
        event.preventDefault(); last?.focus();
      } else if (!event.shiftKey && (document.activeElement === last || !sidebar?.contains(document.activeElement))) {
        event.preventDefault(); first?.focus();
      }
    };
    document.addEventListener("keydown", handleKey);
    return () => {
      document.body.style.overflow = previousOverflow;
      document.removeEventListener("keydown", handleKey);
      menuTrigger.current?.focus();
    };
  }, [mobileOpen]);
  const { data: stats } = useQuery({
    queryKey: ["stats"],
    refetchInterval:30000,
    queryFn: () => api<Stats>("/api/stats/"),
  });
  const current =
    [
      ...navigation,
      { label: "KB lookup", path: "/vi/tools/kb-lookup" },
      { label: "SBOM & VEX", path: "/vi/tools/sbom-vex" },
      { label: "Data sources", path: "/vi/sources" },
      { label: "API & integrations", path: "/vi/developers" },
      { label: "Audit & access", path: "/vi/audit" },
    ].find((n) => n.path === location.pathname)?.label || "Overview";
  if(authRequired)return <AccessGate onAuthenticated={()=>setAuthRequired(false)}/>;
  return (
    <div className="app" data-ui>
      <a href="#main" className="skip-link">
        Skip to content
      </a>
      {mobileOpen && (
        <button
          className="mobile-shade"
          aria-label="Dismiss navigation overlay"
          tabIndex={-1}
          onClick={() => setMobile(false)}
        />
      )}
      <aside
        ref={sidebarRef}
        id="workspace-navigation"
        inert={!!selected || (compact && !mobileOpen)}
        role={mobileOpen ? "dialog" : undefined}
        aria-modal={mobileOpen ? true : undefined}
        aria-label="Workspace navigation"
        onClick={event => {
          if ((event.target as Element).closest("a[href],.workspace")) setMobile(false);
        }}
        className={`sidebar ${mobileOpen ? "open" : ""}`}
      >
        <button className="icon-button mobile-close" aria-label="Close navigation" onClick={() => setMobile(false)}><X size={20} /></button>
        <NavLink to="/vi" className="brand" onClick={() => setMobile(false)}>
          <span className="brand-mark">
            <ShieldCheck size={21} strokeWidth={1.8} />
          </span>
          sentinel<span className="brand-dot">.</span>
        </NavLink>
        <button className="workspace" onClick={() => navigate("/vi/sources")}>
          <span className="workspace-icon">S</span>
          <span>
            Intelligence workspace<small>Community edition</small>
          </span>
          <ChevronsUpDown size={14} />
        </button>
        <div className="nav-group-label">Workspace</div>
        <nav aria-label="Main navigation">
          {navigation.map(({ label, path, icon: Icon }) => (
            <NavLink
              end
              key={path}
              to={path}
              onClick={() => setMobile(false)}
              className={({ isActive }) =>
                `nav-item ${isActive ? "active" : ""}`
              }
            >
              <Icon size={18} />
              <span>{label}</span>
              {label === "Vulnerabilities" && stats && (
                <span className="nav-count">{stats.total}</span>
              )}
            </NavLink>
          ))}
        </nav>
        <div className="nav-group-label tools-label">Analysis tools</div>
        <nav aria-label="Analysis tools">
          <NavLink
            className="nav-item"
            onClick={() => setMobile(false)}
            to="/vi/tools/kb-lookup"
          >
            <Link2 size={18} />
            KB lookup
            <ArrowUpRight size={13} className="nav-end" />
          </NavLink>
          <NavLink
            className="nav-item"
            onClick={() => setMobile(false)}
            to="/vi/tools/sbom-vex"
          >
            <Terminal size={18} />
            SBOM & VEX
            <BadgeNew />
          </NavLink>
        </nav>
        <div className="sidebar-bottom">
          <div className="local-status">
            <span className="status-light" />
            <span>
              Public-source intelligence<small>Persisted, traceable evidence</small>
            </span>
            <Database size={15} />
          </div>
          <NavLink to="/vi/sources" className="nav-item">
            <Settings2 size={17} />
            Data sources
          </NavLink>
          <NavLink to="/vi/developers" className="nav-item">
            <BookOpen size={17} />
            API & integrations
            <ArrowUpRight size={13} className="nav-end" />
          </NavLink>
          {identity?.audit&&<NavLink to="/vi/audit" className="nav-item"><ShieldCheck size={17}/>Audit & access</NavLink>}
          <a
            className="nav-item"
            href="https://nvd.nist.gov/vuln"
            target="_blank"
            rel="noreferrer"
          >
            <CircleHelp size={17} />
            Intelligence reference
          </a>
          <div className="user">
            <div className="avatar">AN</div>
            <span>
              {identity?.id.startsWith("oidc:")?`SSO ${identity.id.slice(5,17)}`:"Operator workspace"}<small>{identity?.role||"Checking access"}</small>
            </span>
            <button className="icon-button" aria-label="Sign out" onClick={async()=>{setLogoutError("");try{await logoutSession();setAuthRequired(true)}catch(e){setLogoutError((e as Error).message)}}}><LogOut size={14}/></button>
          </div>
          {logoutError&&<p role="alert" className="form-error">{logoutError}</p>}
        </div>
      </aside>
      <div className="main-shell" inert={!!selected || mobileOpen}>
        <header className="topbar">
          <div className="breadcrumb">
            <button
              className="icon-button mobile-toggle"
              ref={menuTrigger}
              aria-expanded={mobileOpen}
              aria-controls="workspace-navigation"
              onClick={() => setMobile(true)}
              aria-label="Open navigation"
            >
              <Menu size={20} />
            </button>
            <Globe2 size={15} />
            <span>Intelligence</span>
            <span className="slash">/</span>
            <strong>{current}</strong>
          </div>
          <div className="topbar-actions">
            <button ref={tourTrigger} className="tour-launch" aria-label="User tour" disabled={!identity} onClick={startTour}>
              <Compass size={17} aria-hidden="true" /><span>User tour</span>
            </button>
            <ThemeToggle />
            <form
              className="global-search"
              onSubmit={(e) => {
                e.preventDefault();
                navigate(`/vi/explore?q=${encodeURIComponent(search)}`);
                setSearch("");
              }}
            >
              <Search size={15} />
              <input
                aria-label="Search all intelligence"
                placeholder="Search intelligence…"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
              <kbd>↵</kbd>
            </form>
            <button
              className={`icon-button notification ${watchOpen ? "selected" : ""}`}
              aria-label="Open watchlist"
              onClick={() => setWatchOpen(!watchOpen)}
            >
              <Bell size={18} />
              {watch.length > 0 && <i />}
            </button>
            <div className="avatar small-avatar">AN</div>
          </div>
          {watchOpen && (
            <div className="watch-popover">
              <div className="flex justify-between items-center">
                <h3>Your watchlist</h3>
                <button
                  className="icon-button"
                  aria-label="Close watchlist"
                  onClick={() => setWatchOpen(false)}
                >
                  <X size={17} />
                </button>
              </div>
              <p className="muted small">Saved on this browser.</p>
              {watch.length ? (
                watch.map((id) => (
                  <button
                    key={id}
                    onClick={() => {
                      setSelected(id);
                      setWatchOpen(false);
                    }}
                  >
                    {id}
                    <ArrowUpRight size={15} />
                  </button>
                ))
              ) : (
                <p className="muted">
                  Open a vulnerability and add it to your watchlist.
                </p>
              )}
            </div>
          )}
        </header>
        <main id="main">
          {identity && tourWelcome && <TourWelcome onStart={startTour} onDismiss={dismissTourWelcome} />}
          <Routes>
            <Route path="/" element={<Overview onSelect={setSelected} />} />
            <Route path="/vi" element={<Overview onSelect={setSelected} />} />
            <Route
              path="/vi/explore"
              element={<Explorer onSelect={setSelected} />}
            />
            <Route
              path="/vi/threat-actors"
              element={<Actors onSelect={setSelected} />}
            />
            <Route
              path="/vi/ransomware-groups"
              element={<Actors ransomware onSelect={setSelected} />}
            />
            <Route
              path="/vi/supply-chain"
              element={<SupplyChain onSelect={setSelected} />}
            />
            <Route path="/vi/tools/kb-lookup" element={<PatchLookup />} />
            <Route
              path="/vi/tools/sbom-vex"
              element={<Workbench onSelect={setSelected} />}
            />
            <Route path="/vi/sources" element={<Sources />} />
            <Route path="/vi/developers" element={<Developer />} />
            <Route path="/vi/audit" element={<AuditManagement />} />
            <Route
              path="*"
              element={
                <div className="empty">
                  <h1>Page not found</h1>
                  <NavLink className="button primary" to="/vi">
                    Back to overview
                  </NavLink>
                </div>
              }
            />
          </Routes>
        </main>
        <footer className="app-footer">
          <span>
            <span className="status-light" /> Sentinel Community{" "}
            <span className="footer-version">v0.1.0</span>
          </span>
          <span>Open intelligence. Clear decisions.</span>
          <NavLink to="/vi/sources">
            Source provenance <ArrowUpRight size={12} />
          </NavLink>
        </footer>
      </div>
      {selected && (
        <DetailDrawer
          key={selected}
          id={selected}
          onClose={() => setSelected(null)}
        />
      )}
      {tourActive && <UserTour onClose={() => { setTourActive(false); tourTrigger.current?.focus(); }} />}
    </div>
  );
}
function BadgeNew() {
  return <span className="nav-new">VEX</span>;
}

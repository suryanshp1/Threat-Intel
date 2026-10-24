import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "./types";
import { useIdentity } from "./identity";
import "./audit.css";
type Row = Record<string, unknown>;
type Page = { data: Row[]; next: string | number | null };
interface User {
  id: string;
  issuer: string;
  provider_subject: string;
  label: string;
  role: string;
  disabled: boolean;
  version: number;
  last_login_at: string;
}
async function mutate(path: string, method: string, body?: unknown) {
  const response = await fetch(path, {
    method,
    headers: { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!response.ok) {
    if(response.status===401)window.dispatchEvent(new Event("sentinel-auth-required"));
    let detail = "Request failed";
    try {
      detail = (await response.json()).detail || detail;
    } catch {}
    throw Error(detail);
  }
  return response.json();
}
function timestamp(value: unknown) {
  return typeof value === "string"
    ? new Date(value).toLocaleString()
    : "Unknown";
}
export function AuditManagement() {
  const { data: identity } = useIdentity();
  const [tab, setTab] = useState("Events");
  if (!identity) return <p role="status">Loading access…</p>;
  if (!identity.audit)
    return (
      <section className="panel audit-panel">
        <h1>Audit & access</h1>
        <p>Your role does not grant access to audit records.</p>
      </section>
    );
  return (
    <>
      <div className="page-heading">
        <div>
          <h1>Audit & access</h1>
          <p>Review activity, trace VEX changes and manage workspace access.</p>
        </div>
      </div>
      <div className="tabs page-tabs" aria-label="Audit sections">
        {[
          "Events",
          "VEX history",
          ...(identity.admin ? ["Users & sessions"] : []),
        ].map((name) => (
          <button
            key={name}
            aria-pressed={tab === name}
            className={tab === name ? "active" : ""}
            onClick={() => setTab(name)}
          >
            {name}
          </button>
        ))}
      </div>
      <section className="panel audit-panel">
        {tab === "Events" ? (
          <Events />
        ) : tab === "VEX history" ? (
          <Revisions />
        ) : (
          <Users currentId={identity.id} />
        )}
      </section>
    </>
  );
}
function Events() {
  const [action, setAction] = useState(""),
    [subject, setSubject] = useState(""),
    [filter, setFilter] = useState({ action: "", subject: "" }),
    [cursor, setCursor] = useState<number | undefined>();
  const query = new URLSearchParams({
    limit: "50",
    ...(filter.action ? { action: filter.action } : {}),
    ...(filter.subject ? { subject: filter.subject } : {}),
    ...(cursor ? { before: String(cursor) } : {}),
  });
  const { data, error, isFetching, refetch } = useQuery({
    queryKey: ["audit-events", filter, cursor],
    queryFn: () => api<Page>("/api/audit/events?" + query),
  });
  return (
    <>
      <h2>Activity log</h2>
      <p>
        Append-only application events. Filters match exact action and identity
        values. Records can contain private operational information.
      </p>
      <form
        className="audit-filters"
        onSubmit={(e) => {
          e.preventDefault();
          setCursor(undefined);
          setFilter({ action, subject });
        }}
      >
        <label>
          Action
          <input
            value={action}
            onChange={(e) => setAction(e.target.value)}
            maxLength={512}
            placeholder="e.g. user.access"
          />
        </label>
        <label>
          Identity
          <input
            value={subject}
            onChange={(e) => setSubject(e.target.value)}
            maxLength={512}
            placeholder="operator or identity ID"
          />
        </label>
        <button className="button secondary">Apply filters</button>
        <button
          type="button"
          className="button secondary"
          onClick={() => refetch()}
        >
          Refresh
        </button>
      </form>
      {error && <p role="alert">{error.message}</p>}
      <div className="audit-table">
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Action</th>
              <th>Identity</th>
              <th>Details</th>
            </tr>
          </thead>
          <tbody>
            {data?.data.map((row) => (
              <tr key={String(row.id)}>
                <td>{timestamp(row.created_at)}</td>
                <td>{String(row.action)}</td>
                <td>
                  <code>{String(row.subject)}</code>
                </td>
                <td>
                  <details>
                    <summary>View event {String(row.id)}</summary>
                    <pre>{JSON.stringify(row.detail, null, 2)}</pre>
                  </details>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {!data?.data.length && !isFetching && <p>No matching audit events.</p>}
      <div className="audit-actions">
        <button
          className="button secondary"
          disabled={!cursor}
          onClick={() => setCursor(undefined)}
        >
          Newest
        </button>
        <button
          className="button secondary"
          disabled={!data?.next || isFetching}
          onClick={() => setCursor(Number(data?.next))}
        >
          Older events
        </button>
      </div>
    </>
  );
}
function Revisions() {
  const [input, setInput] = useState(""),
    [id, setId] = useState(""),
    [cursor, setCursor] = useState<number | undefined>();
  const query = new URLSearchParams({
    document_id: id,
    limit: "5",
    ...(cursor ? { before: String(cursor) } : {}),
  });
  const { data, error, isFetching } = useQuery({
    queryKey: ["audit-vex", id, cursor],
    queryFn: () => api<Page>("/api/audit/vex-revisions?" + query),
    enabled: !!id,
  });
  return (
    <>
      <h2>VEX revision history</h2>
      <p>
        Review stored before/after documents. History begins with writes made
        after the security migration.
      </p>
      <form
        className="audit-filters"
        onSubmit={(e) => {
          e.preventDefault();
          setId(input);
          setCursor(undefined);
        }}
      >
        <label>
          Document ID
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            maxLength={512}
            placeholder="urn:uuid:…"
            required
          />
        </label>
        <button className="button secondary">Load history</button>
      </form>
      {error && <p role="alert">{error.message}</p>}
      {data?.data.map((row) => (
        <details className="audit-revision" key={String(row.revision)}>
          <summary>
            Revision {String(row.revision)} · {timestamp(row.created_at)} ·{" "}
            {String(row.subject)}
          </summary>
          <div className="audit-diff">
            <div>
              <h3>Before</h3>
              <pre>{JSON.stringify(row.before_document, null, 2)}</pre>
            </div>
            <div>
              <h3>After</h3>
              <pre>{JSON.stringify(row.after_document, null, 2)}</pre>
            </div>
          </div>
        </details>
      ))}
      {id && !isFetching && data && !data.data.length && (
        <p>No saved revisions for this document.</p>
      )}
      <div className="audit-actions">
        <button
          className="button secondary"
          disabled={!cursor}
          onClick={() => setCursor(undefined)}
        >
          Newest
        </button>
        <button
          className="button secondary"
          disabled={!data?.next || isFetching}
          onClick={() => setCursor(Number(data?.next))}
        >
          Older revisions
        </button>
      </div>
    </>
  );
}
function Users({ currentId }: { currentId: string }) {
  const [after, setAfter] = useState<string | undefined>();
  const { data, error, isFetching, refetch } = useQuery({
    queryKey: ["identity-users", after],
    queryFn: () =>
      api<{ data: User[]; next: string | null }>(
        "/api/admin/users?limit=50" +
          (after ? "&after=" + encodeURIComponent(after) : ""),
      ),
  });
  return (
    <>
      <h2>Users & sessions</h2>
      <p>
        New SSO identities start pending. Assign the minimum required role.
        Changes apply on the next request; in-flight work may finish. Operator
        and integration credentials are managed separately through deployment
        configuration.
      </p>
      <button className="button secondary" onClick={() => refetch()}>
        Refresh users
      </button>
      {error && <p role="alert">{error.message}</p>}
      {data?.data.map((user) => (
        <UserAccess
          key={`${user.id}:${user.version}`}
          user={user}
          currentId={currentId}
        />
      ))}
      {data && !data.data.length && (
        <p>
          No SSO users yet. A user appears after their first verified sign-in.
        </p>
      )}
      <div className="audit-actions">
        <button
          className="button secondary"
          disabled={!after}
          onClick={() => setAfter(undefined)}
        >
          First page
        </button>
        <button
          className="button secondary"
          disabled={!data?.next || isFetching}
          onClick={() => setAfter(data?.next || undefined)}
        >
          Next users
        </button>
      </div>
    </>
  );
}
function UserAccess({ user, currentId }: { user: User; currentId: string }) {
  const [role, setRole] = useState(user.role),
    [disabled, setDisabled] = useState(user.disabled),
    [show, setShow] = useState(false);
  const qc = useQueryClient();
  const save = useMutation({
    mutationFn: () =>
      mutate("/api/admin/users/" + encodeURIComponent(user.id), "PUT", {
        role,
        disabled,
        version: user.version,
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["identity-users"] });
      qc.invalidateQueries({ queryKey: ["audit-events"] });
    },
  });
  const sessions = useQuery({
    queryKey: ["identity-sessions", user.id],
    queryFn: () =>
      api<{ data: Row[]; truncated: boolean }>(
        "/api/admin/users/" + encodeURIComponent(user.id) + "/sessions",
      ),
    enabled: show,
    refetchInterval: show ? 30000 : false,
  });
  const revoke = useMutation({
    mutationFn: (id: string) => mutate("/api/admin/sessions/" + id, "DELETE"),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["identity-sessions", user.id] });
      qc.invalidateQueries({ queryKey: ["audit-events"] });
    },
  });
  const self = currentId === user.id;
  return (
    <article className="audit-user">
      <h3>{user.label}</h3>
      <code className="audit-identity">{user.id}</code>
      <p>
        {user.issuer} · Subject {user.provider_subject} · Last verified sign-in{" "}
        {timestamp(user.last_login_at)}
      </p>
      <form
        className="audit-filters"
        onSubmit={(e) => {
          e.preventDefault();
          save.mutate();
        }}
      >
        <label>
          Role
          <select
            value={role}
            onChange={(e) => setRole(e.target.value)}
            disabled={self}
          >
            {["pending", "reader", "analyst", "auditor", "admin"].map((r) => (
              <option key={r}>{r}</option>
            ))}
          </select>
        </label>
        <label className="audit-checkbox">
          <input
            type="checkbox"
            checked={disabled}
            disabled={self}
            onChange={(e) => setDisabled(e.target.checked)}
          />
          Disable access
        </label>
        <button
          className="button secondary"
          disabled={
            self ||
            save.isPending ||
            (role === user.role && disabled === user.disabled)
          }
        >
          Save access
        </button>
        <button
          type="button"
          className="button secondary"
          onClick={() => setShow(!show)}
        >
          {show ? "Hide sessions" : "View sessions"}
        </button>
      </form>
      {self && (
        <p>Another administrator or the operator must change your access.</p>
      )}
      {save.error && <p role="alert">{save.error.message}</p>}
      {show && (
        <div>
          {sessions.error && <p role="alert">{sessions.error.message}</p>}
          {sessions.data?.data.map((row) => (
            <div className="audit-session" key={String(row.id)}>
              <span>
                Started {timestamp(row.created_at)} · Expires{" "}
                {timestamp(row.expires_at)}
              </span>
              <button
                className="button secondary"
                disabled={revoke.isPending}
                onClick={() => revoke.mutate(String(row.id))}
              >
                Revoke session
              </button>
            </div>
          ))}
          {sessions.data && !sessions.data.data.length && (
            <p>No active sessions.</p>
          )}
          {sessions.data?.truncated && <p>Showing the newest 100 sessions.</p>}
          {revoke.error && <p role="alert">{revoke.error.message}</p>}
        </div>
      )}
    </article>
  );
}

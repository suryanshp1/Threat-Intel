import { ThemeToggle } from "./theme";
import { useEffect, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { ShieldCheck, ArrowRight } from "lucide-react";
export function AccessGate({
  onAuthenticated,
}: {
  onAuthenticated: () => void;
}) {
  const [token, setToken] = useState("");
  const [error, setError] = useState("");
  const [pending, setPending] = useState(false);
  const query = useQueryClient();
  const [sso, setSso] = useState(false);
  useEffect(() => {
    fetch("/api/auth/config")
      .then((r) => (r.ok ? r.json() : null))
      .then((c) => setSso(!!c?.oidc))
      .catch(() => {});
  }, []);
  const notice = new URLSearchParams(window.location.search).get("signin");
  return (
    <main className="access-gate">
      <div className="access-theme-toggle">
        <ThemeToggle />
      </div>
      <div className="panel">
        <ShieldCheck size={35} />
        <h1>Sentinel workspace</h1>
        <p>Sign in to your intelligence workspace.</p>
        {notice === "pending" && (
          <p role="status">
            Your identity was verified. An administrator must approve your
            access before you can sign in.
          </p>
        )}
        {notice === "failed" && (
          <p role="alert">SSO sign-in failed or expired. Please try again.</p>
        )}
        {sso && (
          <button
            className="button primary"
            disabled={pending}
            onClick={async () => {
              setPending(true);
              setError("");
              try {
                const r = await fetch("/api/auth/oidc/start", {
                  method: "POST",
                });
                if (!r.ok) throw Error("SSO is unavailable. Please try again.");
                const data = await r.json();
                window.location.assign(data.authorization_url);
              } catch (e) {
                setError((e as Error).message);
                setPending(false);
              }
            }}
          >
            Sign in with SSO
            <ArrowRight size={16} />
          </button>
        )}
        <p>Operator recovery access</p>
        <form
          onSubmit={async (e) => {
            e.preventDefault();
            setPending(true);
            setError("");
            try {
              const result = await fetch("/api/session", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ token }),
              });
              if (!result.ok)
                throw new Error(
                  (await result.json()).detail || "Sign-in failed",
                );
              setToken("");
              query.clear();
              onAuthenticated();
            } catch (e) {
              setError((e as Error).message);
            } finally {
              setPending(false);
            }
          }}
        >
          <label htmlFor="access-token">Access token</label>
          <input
            id="access-token"
            type="password"
            value={token}
            onChange={(e) => setToken(e.target.value)}
            autoComplete="current-password"
            required
          />
          <button className="button primary" disabled={pending}>
            {pending ? "Signing in…" : "Open workspace"}
            <ArrowRight size={16} />
          </button>
        </form>
        {error && (
          <p role="alert" className="form-error">
            {error}
          </p>
        )}
        <small>
          Your token is exchanged for an HttpOnly session and is never saved in
          browser storage.
        </small>
      </div>
    </main>
  );
}

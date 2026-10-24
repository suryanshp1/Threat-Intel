// Disposable TLS-enabled PostgreSQL. Does not modify the installation's database or certificates.
import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { randomBytes } from "node:crypto";
import net from "node:net";
import assert from "node:assert/strict";
const dir = mkdtempSync("/tmp/sentinel-tls-"),
  name = `sentinel-tls-${process.pid}`,
  password = randomBytes(24).toString("hex");
let proc;
let started = false;
function run(command, args, options = {}) {
  const r = spawnSync(command, args, { encoding: "utf8", ...options });
  if (r.status !== 0)
    throw Error(`${command} fixture operation failed: ${r.stderr}`);
  return r.stdout.trim();
}
function openssl(...args) {
  run("openssl", args, { cwd: dir });
}
async function port() {
  const server = net.createServer();
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const p = server.address().port;
  await new Promise((r) => server.close(r));
  return p;
}
async function stop() {
  if (proc && proc.exitCode === null) {
    proc.kill("SIGTERM");
    await new Promise((r) => proc.once("exit", r));
  }
}
try {
  openssl(
    "req",
    "-x509",
    "-newkey",
    "rsa:2048",
    "-nodes",
    "-keyout",
    "ca.key",
    "-out",
    "ca.crt",
    "-days",
    "1",
    "-subj",
    "/CN=Sentinel test CA",
  );
  openssl(
    "req",
    "-newkey",
    "rsa:2048",
    "-nodes",
    "-keyout",
    "server.key",
    "-out",
    "server.csr",
    "-subj",
    "/CN=localhost",
  );
  writeFileSync(
    dir + "/extensions",
    "subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n",
  );
  openssl(
    "x509",
    "-req",
    "-in",
    "server.csr",
    "-CA",
    "ca.crt",
    "-CAkey",
    "ca.key",
    "-CAcreateserial",
    "-out",
    "server.crt",
    "-days",
    "1",
    "-extfile",
    "extensions",
  );
  openssl(
    "req",
    "-x509",
    "-newkey",
    "rsa:2048",
    "-nodes",
    "-keyout",
    "other.key",
    "-out",
    "other.crt",
    "-days",
    "1",
    "-subj",
    "/CN=Untrusted test CA",
  );
  run("docker", [
    "run",
    "--detach",
    "--rm",
    "--name",
    name,
    "-e",
    `POSTGRES_PASSWORD=${password}`,
    "-e",
    "POSTGRES_DB=sentinel_tls",
    "-p",
    "127.0.0.1::5432",
    "-v",
    dir + ":/fixtures:ro",
    "postgres:17-alpine",
    "sh",
    "-c",
    "cp /fixtures/server.key /tmp/server.key && cp /fixtures/server.crt /tmp/server.crt && chmod 600 /tmp/server.key && chown postgres:postgres /tmp/server.key /tmp/server.crt && exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/tmp/server.crt -c ssl_key_file=/tmp/server.key",
  ]);
  started = true;
  const mapping = run("docker", ["port", name, "5432/tcp"]),
    dbPort = Number(mapping.split(":").at(-1));
  let ready = false;
  for (let i = 0; i < 100; i++) {
    const r = spawnSync(
      "docker",
      ["exec", name, "pg_isready", "-h", "127.0.0.1", "-U", "postgres"],
      { stdio: "ignore" },
    );
    if (r.status === 0) {
      ready = true;
      break;
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  assert.ok(ready, "TLS fixture database readiness");
  async function attempt(host, ca, success) {
    const apiPort = await port();
    const env = {
      ...process.env,
      VI_ENV: "development",
      VI_API_TOKEN: randomBytes(32).toString("hex"),
      DATABASE_URL: `postgresql://postgres:${password}@${host}:${dbPort}/sentinel_tls?application_name=sentinel_tls_probe`,
      VI_DB_TLS_MODE: "verify-full",
      VI_DB_TLS_CA_FILE: dir + "/" + ca,
      PORT: String(apiPort),
      BIND_ADDR: "127.0.0.1",
      VI_OIDC_ISSUER: "",
    };
    delete env.REDIS_URL;
    proc = spawn("backend/target/debug/vi-server", [], {
      env,
      stdio: "ignore",
    });
    let healthy = false;
    for (let i = 0; i < 150; i++) {
      try {
        const r = await fetch(`http://127.0.0.1:${apiPort}/readyz`, {
          signal: AbortSignal.timeout(500),
        });
        if (r.ok) {
          healthy = true;
          break;
        }
      } catch {}
      if (proc.exitCode !== null) break;
      await new Promise((r) => setTimeout(r, 100));
    }
    assert.equal(
      healthy,
      success,
      `${host}/${ca}: certificate and hostname verification`,
    );
    if (success) {
      const ssl = run("docker", [
        "exec",
        name,
        "psql",
        "-X",
        "-U",
        "postgres",
        "-d",
        "sentinel_tls",
        "-Atc",
        "SELECT bool_and(s.ssl) FROM pg_stat_activity a JOIN pg_stat_ssl s ON s.pid=a.pid WHERE a.application_name='sentinel_tls_probe'",
      ]);
      assert.equal(ssl, "t");
    }
    await stop();
  }
  await attempt("localhost", "ca.crt", true);
  await attempt("127.0.0.1", "ca.crt", false);
  await attempt("localhost", "other.crt", false);
  console.log(
    "PASS: PostgreSQL TLS encryption, trusted CA, hostname mismatch and untrusted CA checks.",
  );
} finally {
  await stop();
  if (started) run("docker", ["stop", name]);
  rmSync(dir, { recursive: true, force: true });
}

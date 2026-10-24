// Local test-only identity provider; never used by production application code.
import http from "node:http";
import {
  generateKeyPairSync,
  createHash,
  createHmac,
  sign,
  randomBytes,
} from "node:crypto";
import assert from "node:assert/strict";
export async function oidcFixture() {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
  });
  const jwk = {
    ...publicKey.export({ format: "jwk" }),
    kid: "fixture-key",
    alg: "RS256",
    use: "sig",
  };
  const codes = new Map();
  let issuer;
  let fault = "";
  let tokenCalls = 0;
  const server = http.createServer(async (req, res) => {
    try {
      res.setHeader("Content-Type", "application/json");
      if (req.url === "/.well-known/openid-configuration") {
        if (fault === "redirect") {
          res.writeHead(302, { Location: issuer + "/jwks" });
          res.end();
          return;
        }
        res.end(
          JSON.stringify({
            issuer: fault === "discovery-issuer" ? issuer + "/wrong" : issuer,
            authorization_endpoint: issuer + "/authorize",
            token_endpoint: issuer + "/token",
            jwks_uri: issuer + "/jwks",
            id_token_signing_alg_values_supported: ["RS256"],
            response_types_supported: ["code"],
            subject_types_supported: ["public"],
          }),
        );
        return;
      }
      if (req.url.startsWith("/authorize?")) {
        const p = new URL(req.url, issuer).searchParams;
        const target = new URL(p.get("redirect_uri"));
        assert.equal(target.protocol, "http:");
        assert.ok(["localhost", "127.0.0.1"].includes(target.hostname));
        const code = randomBytes(24).toString("hex");
        codes.set(code, {
          nonce: p.get("nonce"),
          challenge: p.get("code_challenge"),
          redirect: target.toString(),
        });
        target.searchParams.set("state", p.get("state"));
        target.searchParams.set("code", code);
        res.writeHead(302, { Location: target.toString() });
        res.end();
        return;
      }
      if (req.url === "/jwks") {
        res.end(JSON.stringify({ keys: [jwk] }));
        return;
      }
      if (req.url === "/token") {
        tokenCalls++;
        let body = "";
        for await (const chunk of req) {
          body += chunk;
          if (body.length > 10000) throw Error("Oversized fixture request");
        }
        const params = new URLSearchParams(body),
          entry = codes.get(params.get("code"));
        assert.ok(entry);
        codes.delete(params.get("code"));
        assert.equal(params.get("grant_type"), "authorization_code");
        assert.equal(
          createHash("sha256")
            .update(params.get("code_verifier"))
            .digest("base64url"),
          entry.challenge,
        );
        assert.equal(params.get("redirect_uri"), entry.redirect);
        assert.equal(
          req.headers.authorization,
          "Basic " +
            Buffer.from("fixture-client:fixture-secret").toString("base64"),
        );
        const now = Math.floor(Date.now() / 1000),
          access = "fixture-access";
        const claims = {
          iss: issuer,
          aud: "fixture-client",
          sub: "fixture-user",
          name: "Fixture Analyst",
          iat: now,
          exp: now + 3600,
          nonce: entry.nonce,
          at_hash: createHash("sha256")
            .update(access)
            .digest()
            .subarray(0, 16)
            .toString("base64url"),
        };
        if (fault === "issuer") claims.iss = issuer + "/wrong";
        if (fault === "audience") claims.aud = "other-client";
        if (fault === "nonce") claims.nonce = "wrong";
        if (fault === "expired") claims.exp = now - 10;
        if (fault === "future") claims.iat = now + 3600;
        if (fault === "access-hash") claims.at_hash = "wrong";
        if (fault === "authorized-party") {
          claims.aud = ["fixture-client", "other"];
          claims.azp = "other";
        }
        if (fault === "not-before") claims.nbf = now + 3600;
        if(fault==='missing-exp')delete claims.exp;
        const header = Buffer.from(
          JSON.stringify({
            alg: fault==='hmac'?'HS256':"RS256",
            ...(fault==='critical'?{crit:['unsupported-fixture-header']}:{}),
            kid: fault === "key" ? "wrong" : "fixture-key",
            typ: "JWT",
          }),
        ).toString("base64url");
        const payload =
          header +
          "." +
          Buffer.from(JSON.stringify(claims)).toString("base64url");
        let signature = sign(
          "RSA-SHA256",
          Buffer.from(payload),
          privateKey,
        ).toString("base64url");
        if(fault==='hmac')signature=createHmac('sha256','fixture-secret').update(payload).digest('base64url');
        if (fault === "signature")
          signature = Buffer.alloc(256).toString("base64url");
        res.end(
          JSON.stringify({
            access_token: access,
            token_type: "Bearer",
            id_token: payload + "." + signature,
          }),
        );
        return;
      }
      res.writeHead(404);
      res.end("{}");
    } catch {
      res.writeHead(400);
      res.end('{"error":"invalid_request"}');
    }
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  issuer = `http://127.0.0.1:${server.address().port}`;
  return {
    issuer,
    get tokenCalls() {
      return tokenCalls;
    },
    setFault(value) {
      fault = value;
    },
    code(url) {
      const p = new URL(url).searchParams;
      assert.equal(p.get("response_type"), "code");
      assert.equal(p.get("scope"), "openid profile");
      assert.equal(p.get("client_id"), "fixture-client");
      assert.equal(p.get("code_challenge_method"), "S256");
      const code = randomBytes(24).toString("hex");
      codes.set(code, {
        nonce: p.get("nonce"),
        challenge: p.get("code_challenge"),
        redirect: p.get("redirect_uri"),
      });
      return { code, state: p.get("state") };
    },
    async close() {
      await new Promise((r) => server.close(r));
    },
  };
}

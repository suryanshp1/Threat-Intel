//! Authorization-code OIDC. Provider tokens never leave this module or enter logs/storage.
use super::*;
use axum::http::{header, HeaderMap};
use axum::response::Redirect;
use base64::Engine;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use oauth2::reqwest;
use oauth2::{basic::*, *};
use sha2::{Digest, Sha256};
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Extra {
    id_token: String,
}
impl ExtraTokenFields for Extra {}
type Tokens = StandardTokenResponse<Extra, BasicTokenType>;
type Client = oauth2::Client<
    BasicErrorResponse,
    Tokens,
    BasicTokenIntrospectionResponse,
    StandardRevocableToken,
    BasicRevocationErrorResponse,
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointSet,
>;
#[derive(Deserialize)]
struct Metadata {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    id_token_signing_alg_values_supported: Vec<String>,
}
#[derive(Clone)]
pub struct Config {
    issuer: String,
    client_id: String,
    secret: String,
    redirect: String,
    allow_http: bool,
}
impl Config {
    pub(super) fn matches_issuer(&self, issuer: &str) -> bool {
        self.issuer == issuer
    }

    pub fn from_env(production: bool) -> Result<Option<Self>, String> {
        let issuer = std::env::var("VI_OIDC_ISSUER").unwrap_or_default();
        if issuer.is_empty() {
            return Ok(None);
        }
        let required = |name| {
            std::env::var(name)
                .ok()
                .filter(|s| !s.is_empty())
                .ok_or_else(|| format!("{name} is required for OIDC"))
        };
        let origin = required("VI_PUBLIC_ORIGIN")?;
        let origin_url = url::Url::parse(&origin).map_err(|_| "Invalid public origin")?;
        if origin_url.path() != "/"
            || origin_url.query().is_some()
            || origin_url.fragment().is_some()
        {
            return Err(
                "VI_PUBLIC_ORIGIN must be an origin without a path, query or fragment".into(),
            );
        }
        let config = Self {
            issuer,
            client_id: required("VI_OIDC_CLIENT_ID")?,
            secret: required("VI_OIDC_CLIENT_SECRET")?,
            redirect: format!("{}/api/auth/oidc/callback", origin.trim_end_matches('/')),
            allow_http: !production
                && std::env::var("VI_OIDC_ALLOW_HTTP_LOOPBACK").as_deref() == Ok("true"),
        };
        if config.issuer.len() > 2048 || config.client_id.len() > 512 || config.secret.len() > 4096
        {
            return Err("OIDC configuration exceeds supported limits".into());
        }
        validate_url(&config.issuer, config.allow_http)?;
        validate_url(&config.redirect, config.allow_http)?;
        let url = url::Url::parse(&config.issuer).map_err(|_| "Invalid OIDC issuer")?;
        if url.query().is_some() || url.fragment().is_some() {
            return Err("OIDC issuer cannot contain query or fragment".into());
        }
        Ok(Some(config))
    }
    async fn client(&self) -> Result<(Client, Metadata), String> {
        let metadata: Metadata = get_json(
            &format!(
                "{}/.well-known/openid-configuration",
                self.issuer.trim_end_matches('/')
            ),
            self.allow_http,
        )
        .await?;
        if metadata.issuer != self.issuer {
            return Err("OIDC discovery issuer mismatch".into());
        }
        for value in [
            &metadata.authorization_endpoint,
            &metadata.token_endpoint,
            &metadata.jwks_uri,
        ] {
            validate_url(value, self.allow_http)?;
        }
        let client = oauth2::Client::<
            BasicErrorResponse,
            Tokens,
            BasicTokenIntrospectionResponse,
            StandardRevocableToken,
            BasicRevocationErrorResponse,
        >::new(ClientId::new(self.client_id.clone()))
        .set_client_secret(ClientSecret::new(self.secret.clone()))
        .set_auth_uri(
            AuthUrl::new(metadata.authorization_endpoint.clone())
                .map_err(|_| "Invalid authorization URL")?,
        )
        .set_token_uri(
            TokenUrl::new(metadata.token_endpoint.clone()).map_err(|_| "Invalid token URL")?,
        )
        .set_redirect_uri(
            RedirectUrl::new(self.redirect.clone()).map_err(|_| "Invalid redirect URL")?,
        );
        Ok((client, metadata))
    }
}
async fn get_json<T: serde::de::DeserializeOwned>(
    url: &str,
    allow_http: bool,
) -> Result<T, String> {
    let request = http::Request::builder()
        .uri(url)
        .body(Vec::new())
        .map_err(|_| "Invalid provider URL")?;
    let response = bounded_http(request, allow_http)
        .await
        .map_err(|_| "Provider request failed")?;
    if !response.status().is_success() {
        return Err("Provider request failed".into());
    }
    serde_json::from_slice(response.body()).map_err(|_| "Invalid provider JSON".into())
}

fn validate_url(value: &str, allow_http: bool) -> Result<(), String> {
    let url = url::Url::parse(value).map_err(|_| "Invalid OIDC URL")?;
    let local = url.host_str().is_some_and(|h| {
        h == "localhost"
            || h.parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    });
    if (url.scheme() != "https" && !(allow_http && url.scheme() == "http" && local))
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err("OIDC requires HTTPS URLs without credentials or fragments".into());
    }
    Ok(())
}
async fn bounded_http(
    request: HttpRequest,
    allow_http: bool,
) -> Result<HttpResponse, std::io::Error> {
    let fail = || std::io::Error::other("OIDC provider request failed");
    validate_url(&request.uri().to_string(), allow_http).map_err(|_| fail())?;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|_| fail())?;
    let (parts, body) = request.into_parts();
    let mut response = client
        .request(parts.method, parts.uri.to_string())
        .headers(parts.headers)
        .body(body)
        .send()
        .await
        .map_err(|_| fail())?;
    let mut result = http::Response::builder().status(response.status());
    *result.headers_mut().ok_or_else(fail)? = response.headers().clone();
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| fail())? {
        if bytes.len() + chunk.len() > 1024 * 1024 {
            return Err(fail());
        }
        bytes.extend_from_slice(&chunk);
    }
    result.body(bytes).map_err(|_| fail())
}
#[derive(Serialize, Deserialize)]
struct Pending {
    nonce: String,
    verifier: String,
    browser: String,
}
fn browser_cookie(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|s| s.trim().strip_prefix("sentinel_oidc="))
        .filter(|v| v.len() == 72)
}
pub async fn info(State(app): State<App>) -> Json<Value> {
    Json(json!({"oidc":app.security.oidc.is_some(),"operator":true}))
}
pub async fn start(
    State(app): State<App>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
) -> Response {
    if !security::request_origin_allowed(&headers, app.security.production) {
        return err(StatusCode::FORBIDDEN, "Cross-origin login rejected").into_response();
    }
    let Some(config) = &app.security.oidc else {
        return err(StatusCode::NOT_FOUND, "SSO is not configured").into_response();
    };
    let ip = security::client_ip(&headers, peer.ip(), &app.security.trusted_proxies);
    if let Err(r) = security::throttle(
        &app,
        &format!("oidc-start:{}", security::fingerprint(&ip.to_string())),
        20,
        1,
    )
    .await
    {
        return r;
    }
    if let Err(r) = security::throttle(&app, "oidc-start-total", 100, 1).await {
        return r;
    }
    let result=async {
        let (client,_)=config.client().await?;
        let (challenge,verifier)=PkceCodeChallenge::new_random_sha256();
        let nonce=format!("{}{}",uuid::Uuid::new_v4(),uuid::Uuid::new_v4());
        let (url,state)=client.authorize_url(||CsrfToken::new(format!("{}{}",uuid::Uuid::new_v4(),uuid::Uuid::new_v4()))).add_scope(Scope::new("openid".into())).add_scope(Scope::new("profile".into())).add_extra_param("nonce",nonce.clone()).set_pkce_challenge(challenge).url();
        let browser=format!("{}{}",uuid::Uuid::new_v4(),uuid::Uuid::new_v4());
        let pending=Pending{nonce,verifier:verifier.secret().clone(),browser:security::fingerprint(&browser)};
        let mut redis=app.security.redis.as_ref().ok_or("SSO requires Valkey")?.get_multiplexed_async_connection().await.map_err(|_|"SSO state store unavailable")?;
        redis::cmd("SETEX").arg(format!("vi:oidc:{}",security::fingerprint(state.secret()))).arg(300).arg(serde_json::to_string(&pending).map_err(|_|"SSO state error")?).query_async::<()>(&mut redis).await.map_err(|_|"SSO state store unavailable")?;
        let secure=if app.security.production{"; Secure"}else{""};
        Ok::<_,String>(([(header::SET_COOKIE,format!("sentinel_oidc={browser}; HttpOnly; SameSite=Lax; Path=/api/auth/oidc; Max-Age=300{secure}"))],Json(json!({"authorization_url":url.as_str()}))).into_response())
    }.await;
    result.unwrap_or_else(|_| {
        err(
            StatusCode::SERVICE_UNAVAILABLE,
            "SSO sign-in could not be started",
        )
        .into_response()
    })
}
#[derive(Deserialize)]
pub struct Callback {
    state: Option<String>,
    code: Option<String>,
}
pub async fn callback(
    State(app): State<App>,
    headers: HeaderMap,
    Query(query): Query<Callback>,
) -> Response {
    let result =
        tokio::time::timeout(Duration::from_secs(40), complete(&app, &headers, query)).await;
    let mut response = match result {
        Ok(Ok(r)) => r,
        Ok(Err(reason)) => {
            tracing::warn!(event="oidc_signin_failed",reason=%reason,"SSO sign-in rejected");
            Redirect::to("/vi?signin=failed").into_response()
        }
        Err(_) => {
            tracing::warn!(
                event = "oidc_signin_timeout",
                "SSO sign-in exceeded its deadline"
            );
            Redirect::to("/vi?signin=failed").into_response()
        }
    };
    let secure = if app.security.production {
        "; Secure"
    } else {
        ""
    };
    response.headers_mut().append(
        header::SET_COOKIE,
        format!("sentinel_oidc=; HttpOnly; SameSite=Lax; Path=/api/auth/oidc; Max-Age=0{secure}")
            .parse()
            .unwrap(),
    );
    response
        .headers_mut()
        .insert(header::REFERRER_POLICY, "no-referrer".parse().unwrap());
    response
}
async fn complete(app: &App, headers: &HeaderMap, query: Callback) -> Result<Response, String> {
    let config = app.security.oidc.as_ref().ok_or("SSO unavailable")?;
    let state = query
        .state
        .filter(|s| s.len() >= 32 && s.len() <= 256)
        .ok_or("Missing state")?;
    let code = query
        .code
        .filter(|s| !s.is_empty() && s.len() <= 4096)
        .ok_or("Missing code")?;
    let browser = security::fingerprint(browser_cookie(headers).ok_or("Missing browser binding")?);
    let mut redis = app
        .security
        .redis
        .as_ref()
        .ok_or("SSO unavailable")?
        .get_multiplexed_async_connection()
        .await
        .map_err(|_| "SSO unavailable")?;
    // Check browser binding and consume state atomically, across API replicas.
    let pending:Option<String>=redis::Script::new("local v=redis.call('GET',KEYS[1]); if not v then return nil end; local p=cjson.decode(v); if p.browser~=ARGV[1] then return nil end; redis.call('DEL',KEYS[1]); return v").key(format!("vi:oidc:{}",security::fingerprint(&state))).arg(browser).invoke_async(&mut redis).await.map_err(|_|"SSO state failure")?;
    let pending: Pending =
        serde_json::from_str(&pending.ok_or("Expired, replayed or unbound state")?)
            .map_err(|_| "SSO state failure")?;
    let (client, metadata) = config.client().await?;
    let http = |r| bounded_http(r, config.allow_http);
    let token = client
        .exchange_code(AuthorizationCode::new(code))
        .set_pkce_verifier(PkceCodeVerifier::new(pending.verifier))
        .request_async(&http)
        .await
        .map_err(|_| "SSO token exchange failed")?;
    let jwks: jsonwebtoken::jwk::JwkSet = get_json(&metadata.jwks_uri, config.allow_http).await?;
    let claims = verify_id(
        &token.extra_fields().id_token,
        &jwks,
        config,
        &metadata,
        &pending.nonce,
        token.access_token().secret(),
    )?;
    let id = format!(
        "oidc:{}",
        security::fingerprint(&format!("{}\0{}", config.issuer, claims.sub))
    );
    let label = claims
        .preferred_username
        .as_deref()
        .or(claims.name.as_deref())
        .unwrap_or(&claims.sub)
        .chars()
        .filter(|c| !c.is_control())
        .take(160)
        .collect::<String>();
    let user = app
        .db
        .identity_login(&id, &config.issuer, &claims.sub, &label)
        .await
        .map_err(|_| "SSO identity storage failed")?;
    if user["disabled"] == true || user["role"] == "pending" {
        return Ok(Redirect::to("/vi?signin=pending").into_response());
    }
    let ttl = (claims.exp - chrono::Utc::now().timestamp()).clamp(0, 28800);
    if ttl < 1 {
        return Err("Expired token".into());
    }
    let response = security::create_session(
        app,
        credentials::Principal::identity(&user).ok_or("Access not approved")?,
        ttl,
    )
    .await
    .map_err(|_| "SSO session failure")?;
    let mut response = response;
    *response.status_mut() = StatusCode::SEE_OTHER;
    response
        .headers_mut()
        .insert(header::LOCATION, "/vi".parse().unwrap());
    Ok(response)
}
#[derive(Clone, Deserialize)]
struct Claims {
    sub: String,
    exp: i64,
    iat: i64,
    nonce: String,
    aud: Value,
    azp: Option<String>,
    at_hash: Option<String>,
    name: Option<String>,
    preferred_username: Option<String>,
}
fn verify_id(
    raw: &str,
    jwks: &jsonwebtoken::jwk::JwkSet,
    config: &Config,
    metadata: &Metadata,
    nonce: &str,
    access: &str,
) -> Result<Claims, String> {
    let invalid = || "ID token verification failed".to_string();
    if raw.len() > 32768 || jwks.keys.len() > 100 {
        return Err(invalid());
    }
    let header = jsonwebtoken::decode_header(raw).map_err(|_| invalid())?;
    if header.crit.as_ref().is_some_and(|v| !v.is_empty())
        || header.enc.is_some()
        || header.zip.is_some()
    {
        return Err(invalid());
    }
    // Only asymmetric SHA-256 signatures; token-supplied key URLs and embedded keys are never used.
    if !matches!(
        header.alg,
        Algorithm::RS256 | Algorithm::PS256 | Algorithm::ES256
    ) || !metadata
        .id_token_signing_alg_values_supported
        .contains(&format!("{:?}", header.alg))
    {
        return Err(invalid());
    }
    let keys: Vec<_> = jwks
        .keys
        .iter()
        .filter(|key| {
            header
                .kid
                .as_ref()
                .is_none_or(|kid| key.common.key_id.as_ref() == Some(kid))
                && key
                    .common
                    .public_key_use
                    .as_ref()
                    .is_none_or(|u| matches!(u, jsonwebtoken::jwk::PublicKeyUse::Signature))
                && key
                    .common
                    .key_algorithm
                    .as_ref()
                    .is_none_or(|a| format!("{:?}", a) == format!("{:?}", header.alg))
        })
        .collect();
    if keys.len() != 1 {
        return Err(invalid());
    }
    if keys[0]
        .common
        .key_operations
        .as_ref()
        .is_some_and(|ops| !ops.contains(&jsonwebtoken::jwk::KeyOperations::Verify))
    {
        return Err(invalid());
    }
    let key = DecodingKey::from_jwk(keys[0]).map_err(|_| invalid())?;
    let mut validation = Validation::new(header.alg);
    validation.set_issuer(&[&config.issuer]);
    validation.set_audience(&[&config.client_id]);
    validation.set_required_spec_claims(&["exp", "iat", "iss", "aud", "sub"]);
    validation.leeway = 0;
    validation.validate_nbf = true;
    let claims = jsonwebtoken::decode::<Claims>(raw, &key, &validation)
        .map_err(|_| invalid())?
        .claims;
    if claims.sub.is_empty()
        || claims.sub.len() > 512
        || claims.iat > chrono::Utc::now().timestamp() + 60
        || !security::equal(&claims.nonce, nonce)
    {
        return Err(invalid());
    }
    let multi = claims.aud.as_array().is_some_and(|v| v.len() > 1);
    if multi && claims.azp.as_deref() != Some(config.client_id.as_str())
        || claims.azp.as_ref().is_some_and(|v| v != &config.client_id)
    {
        return Err(invalid());
    }
    if let Some(expected) = &claims.at_hash {
        let hash = Sha256::digest(access.as_bytes());
        let actual = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&hash[..16]);
        if !security::equal(expected, &actual) {
            return Err(invalid());
        }
    }
    Ok(claims)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn oidc_transport_policy() {
        assert!(validate_url("https://id.example/realm", false).is_ok());
        assert!(validate_url("http://id.example", true).is_err());
        assert!(validate_url("http://127.0.0.1:18000", false).is_err());
        assert!(validate_url("http://127.0.0.1:18000", true).is_ok());
        assert!(validate_url("https://user:secret@id.example", false).is_err());
    }
}

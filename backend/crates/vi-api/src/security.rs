use super::*;
use crate::credentials::Principal;
use axum::{
    extract::ConnectInfo,
    http::{header, HeaderMap, HeaderValue},
};
use sha2::{Digest, Sha256};
use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
};
use subtle::ConstantTimeEq;
#[derive(Clone)]
pub struct Security {
    pub token: Option<String>,
    pub sessions: Arc<Mutex<HashMap<String, Instant>>>,
    pub redis: Option<redis::Client>,
    pub production: bool,
    clients: Option<PathBuf>,
    pub oidc: Option<crate::oidc::Config>,
    pub(super) trusted_proxies: HashSet<IpAddr>,
}
impl Security {
    pub fn new() -> Result<Self, String> {
        let production = std::env::var("VI_ENV").as_deref() == Ok("production");
        let token = std::env::var("VI_API_TOKEN").ok().filter(|s| !s.is_empty());
        if production && token.as_ref().is_none_or(|s| s.len() < 32) {
            return Err("Production requires VI_API_TOKEN with at least 32 characters".into());
        }
        if token.is_none()
            && (std::env::var("VI_ALLOW_UNAUTHENTICATED").as_deref() != Ok("true")
                || !std::env::var("BIND_ADDR")
                    .unwrap_or_else(|_| "127.0.0.1".into())
                    .parse::<IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback()))
        {
            return Err(
                "Tokenless mode requires VI_ALLOW_UNAUTHENTICATED=true and a loopback BIND_ADDR"
                    .into(),
            );
        }
        let redis = std::env::var("REDIS_URL")
            .ok()
            .map(|s| redis::Client::open(s).map_err(|e| e.to_string()))
            .transpose()?;
        if production && redis.is_none() {
            return Err("Production requires REDIS_URL for shared rate limits".into());
        }
        let trusted_proxies = std::env::var("VI_TRUSTED_PROXIES")
            .unwrap_or_default()
            .split(',')
            .filter(|s| !s.trim().is_empty())
            .map(|s| {
                s.trim().parse().map_err(|_| {
                    "VI_TRUSTED_PROXIES must contain exact proxy IP addresses".to_string()
                })
            })
            .collect::<Result<HashSet<IpAddr>, String>>()?;
        let oidc = crate::oidc::Config::from_env(production)?;
        if oidc.is_some()
            && (redis.is_none() || std::env::var("DATABASE_URL").is_err() || token.is_none())
        {
            return Err("SSO requires PostgreSQL, Valkey and an operator recovery token".into());
        }
        Ok(Self {
            oidc,
            token,
            sessions: Default::default(),
            redis,
            production,
            clients: std::env::var("VI_CLIENT_TOKENS_FILE")
                .ok()
                .filter(|v| !v.is_empty())
                .map(PathBuf::from),
            trusted_proxies,
        })
    }
    pub async fn ready(&self) -> bool {
        match &self.redis {
            Some(redis) => match redis.get_multiplexed_async_connection().await {
                Ok(mut c) => redis::cmd("PING")
                    .query_async::<String>(&mut c)
                    .await
                    .is_ok(),
                Err(_) => false,
            },
            None => !self.production,
        }
    }
}
pub(super) fn fingerprint(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}
pub(super) fn equal(a: &str, b: &str) -> bool {
    fingerprint(a)
        .as_bytes()
        .ct_eq(fingerprint(b).as_bytes())
        .into()
}
fn cookie(headers: &HeaderMap) -> Option<&str> {
    let raw = headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|s| s.trim().strip_prefix("sentinel_session="))?;
    (raw.len() == 72
        && raw
            .get(..36)
            .is_some_and(|s| uuid::Uuid::parse_str(s).is_ok())
        && raw
            .get(36..)
            .is_some_and(|s| uuid::Uuid::parse_str(s).is_ok()))
    .then_some(raw)
}
// Development always serves Vite on these two explicit loopback origins.
// The .env origin may belong to Compose (port 3000), even for a local API.
fn origin_allowed(headers: &HeaderMap, expected: &str, production: bool) -> bool {
    let Some(origin) = headers.get(header::ORIGIN) else {
        return true; // Non-browser clients do not send Origin.
    };
    let Ok(origin) = origin.to_str() else {
        return false;
    };
    origin == expected
        || (!production && ["http://localhost:5173", "http://127.0.0.1:5173"].contains(&origin))
}
pub(super) fn request_origin_allowed(headers: &HeaderMap, production: bool) -> bool {
    let expected =
        std::env::var("VI_PUBLIC_ORIGIN").unwrap_or_else(|_| "http://localhost:5173".into());
    origin_allowed(headers, &expected, production)
}

pub(super) fn client_ip(headers: &HeaderMap, peer: IpAddr, trusted: &HashSet<IpAddr>) -> IpAddr {
    if !trusted.contains(&peer) {
        return peer;
    }
    // Walk from the known immediate proxy towards the first untrusted hop.
    let mut current = peer;
    if let Some(chain) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        if chain.len() > 1024 {
            return peer;
        }
        for part in chain.split(',').rev().take(16) {
            if !trusted.contains(&current) {
                break;
            }
            let Ok(ip) = part.trim().parse() else {
                return peer;
            };
            current = ip;
        }
    }
    current
}
pub(super) async fn throttle(app: &App, key: &str, limit: u32, cost: u32) -> Result<(), Response> {
    let key = format!(
        "vi:rate:{}:{key}",
        fingerprint(app.security.token.as_deref().unwrap_or("local"))
    );
    if let Some(redis) = &app.security.redis {
        let mut conn = redis
            .get_multiplexed_async_connection()
            .await
            .map_err(|_| {
                err(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Rate-limit store unavailable",
                )
                .into_response()
            })?;
        let result:Result<u64,_>=redis::Script::new("local n=redis.call('INCRBY',KEYS[1],ARGV[1]); if n==tonumber(ARGV[1]) then redis.call('EXPIRE',KEYS[1],60) end; return n").key(&key).arg(cost).invoke_async(&mut conn).await;
        match result {
            Ok(n) if n <= limit as u64 => Ok(()),
            Ok(_) => Err(limited()),
            Err(_) => Err(err(
                StatusCode::SERVICE_UNAVAILABLE,
                "Rate-limit store unavailable",
            )
            .into_response()),
        }
    } else {
        let mut buckets = app.buckets.lock().await;
        buckets.retain(|_, v| v.0.elapsed() < Duration::from_secs(60));
        if buckets.len() >= 10000 && !buckets.contains_key(&key) {
            return Err(limited());
        }
        let entry = buckets.entry(key).or_insert((Instant::now(), 0));
        entry.1 = entry.1.saturating_add(cost);
        if entry.1 > limit {
            Err(limited())
        } else {
            Ok(())
        }
    }
}
fn limited() -> Response {
    let mut response = err(StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded").into_response();
    response
        .headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("60"));
    response
}
pub async fn gate(State(app): State<App>, mut req: Request, next: Next) -> Response {
    let headers = req.headers();
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|s| s.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "));
    let mut principal = None;
    if let Some(provided) = bearer {
        if provided.len() > 512 {
            return err(StatusCode::UNAUTHORIZED, "Authentication required").into_response();
        }
        if app
            .security
            .token
            .as_ref()
            .is_some_and(|expected| equal(expected, provided))
        {
            principal = Some(Principal::operator());
        } else {
            match credentials::authenticate(app.security.clients.as_deref(), provided).await {
                Ok(p) => principal = p,
                Err(_) => {
                    return err(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Client credential configuration unavailable",
                    )
                    .into_response()
                }
            }
        }
    } else if let Some(session) = cookie(headers) {
        let key = fingerprint(session);
        let stored = if let Some(redis) = &app.security.redis {
            let mut c = match redis.get_multiplexed_async_connection().await {
                Ok(c) => c,
                Err(_) => {
                    return err(StatusCode::SERVICE_UNAVAILABLE, "Session store unavailable")
                        .into_response()
                }
            };
            match redis::cmd("GET")
                .arg(format!(
                    "vi:session:{}:{key}",
                    fingerprint(app.security.token.as_deref().unwrap_or(""))
                ))
                .query_async::<Option<String>>(&mut c)
                .await
            {
                Ok(v) => v,
                Err(_) => {
                    return err(StatusCode::SERVICE_UNAVAILABLE, "Session store unavailable")
                        .into_response()
                }
            }
        } else {
            let mut sessions = app.security.sessions.lock().await;
            sessions.retain(|_, t| *t > Instant::now());
            sessions.contains_key(&key).then(|| "1".to_string())
        };
        if let Some(stored) = stored {
            match app.db.session_revoked(&key).await {
                Ok(false) => {
                    if stored == "1" {
                        principal = Some(Principal::operator());
                    } else {
                        match app.db.identity_session(&key).await {
                            Ok(Some(user))
                                if user["id"].as_str() == Some(stored.as_str())
                                    && app.security.oidc.as_ref().is_some_and(|c| {
                                        user["issuer"]
                                            .as_str()
                                            .is_some_and(|issuer| c.matches_issuer(issuer))
                                    }) =>
                            {
                                principal = Principal::identity(&user)
                            }
                            Ok(_) => {}
                            Err(_) => {
                                return err(
                                    StatusCode::SERVICE_UNAVAILABLE,
                                    "Identity store unavailable",
                                )
                                .into_response()
                            }
                        }
                    }
                }
                Ok(true) => {}
                Err(_) => {
                    return err(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Session revocation store unavailable",
                    )
                    .into_response()
                }
            }
        }
    } else if app.security.token.is_none() {
        principal = Some(Principal::operator());
    }
    let Some(principal) = principal else {
        return err(StatusCode::UNAUTHORIZED, "Authentication required").into_response();
    };
    let path = req.uri().path();
    if path.ends_with("/mcp")
        || !matches!(
            *req.method(),
            axum::http::Method::GET | axum::http::Method::HEAD | axum::http::Method::OPTIONS
        )
    {
        if !request_origin_allowed(headers, app.security.production) {
            return err(StatusCode::FORBIDDEN, "Cross-origin mutation rejected").into_response();
        }
    }
    if !principal.allows(credentials::required_scope(path, req.method())) {
        return err(
            StatusCode::FORBIDDEN,
            "Credential scope does not permit this operation",
        )
        .into_response();
    }
    let cost = if path.ends_with("/sbom/analyze") || path.ends_with("/admin/ingest") {
        100
    } else if path.ends_with("/download/latest") {
        50
    } else {
        1
    };
    if let Err(r) = throttle(&app, &format!("principal:{}", principal.id), 1000, cost).await {
        return r;
    }
    req.extensions_mut().insert(principal);
    next.run(req).await
}
pub async fn login(
    State(app): State<App>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if !request_origin_allowed(&headers, app.security.production) {
        return err(StatusCode::FORBIDDEN, "Cross-origin login rejected").into_response();
    }
    let Some(expected) = &app.security.token else {
        return Json(json!({"authenticated":true,"mode":"local"})).into_response();
    };
    let ip = client_ip(&headers, peer.ip(), &app.security.trusted_proxies);
    if !equal(body["token"].as_str().unwrap_or(""), expected) {
        if let Err(r) = throttle(
            &app,
            &format!("login-failed:{}", fingerprint(&ip.to_string())),
            20,
            1,
        )
        .await
        {
            return r;
        }
        return err(StatusCode::UNAUTHORIZED, "Invalid access token").into_response();
    }
    // Correct credentials are independent of the anonymous failure budget, including behind a proxy.
    if let Err(r) = throttle(&app, "session-create:operator", 20, 1).await {
        return r;
    }
    create_session(&app, Principal::operator(), 28800)
        .await
        .unwrap_or_else(|r| r)
}
pub(super) async fn create_session(
    app: &App,
    principal: Principal,
    ttl: i64,
) -> Result<Response, Response> {
    let session = format!("{}{}", uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
    let hash = fingerprint(&session);
    let key = format!(
        "vi:session:{}:{hash}",
        fingerprint(app.security.token.as_deref().unwrap_or(""))
    );
    let created: Result<(), String> = async {
        if principal.id.starts_with("oidc:") {
            app.db
                .bind_identity_session(&hash, &principal.id, ttl)
                .await?;
        }
        if let Some(redis) = &app.security.redis {
            let mut c = redis
                .get_multiplexed_async_connection()
                .await
                .map_err(|_| "Session store unavailable")?;
            redis::cmd("SETEX")
                .arg(&key)
                .arg(ttl)
                .arg(if principal.id == "operator" {
                    "1"
                } else {
                    &principal.id
                })
                .query_async::<()>(&mut c)
                .await
                .map_err(|_| "Session store unavailable")?;
        } else {
            app.security.sessions.lock().await.insert(
                hash.clone(),
                Instant::now() + Duration::from_secs(ttl as u64),
            );
        }
        // Record successful creation only after the shared session store accepts it.
        app.db
            .audit(
                "session.login",
                &principal.id,
                json!({"method":if principal.id.starts_with("oidc:"){"oidc"}else{"operator"}}),
            )
            .await?;
        Ok(())
    }
    .await;
    if created.is_err() {
        // No cookie is returned on failure. Revoke any partially created session as well.
        let _ = app.db.revoke_session(&hash).await;
        if let Some(redis) = &app.security.redis {
            if let Ok(mut c) = redis.get_multiplexed_async_connection().await {
                let _ = redis::cmd("DEL").arg(&key).query_async::<u64>(&mut c).await;
            }
        }
        app.security.sessions.lock().await.remove(&hash);
        return Err(err(
            StatusCode::SERVICE_UNAVAILABLE,
            "Session creation or audit persistence failed",
        )
        .into_response());
    }
    let secure = if app.security.production {
        "; Secure"
    } else {
        ""
    };
    Ok(([(header::SET_COOKIE,format!("sentinel_session={session}; HttpOnly; SameSite=Strict; Path=/; Max-Age={ttl}{secure}"))],Json(json!({"authenticated":true,"principal":principal}))).into_response())
}
pub async fn logout(State(app): State<App>, headers: HeaderMap) -> Response {
    if !request_origin_allowed(&headers, app.security.production) {
        return err(StatusCode::FORBIDDEN, "Cross-origin logout rejected").into_response();
    }
    if let Some(session) = cookie(&headers) {
        let key = fingerprint(session);
        if let Some(redis) = &app.security.redis {
            let mut c = match redis.get_multiplexed_async_connection().await {
                Ok(c) => c,
                Err(_) => {
                    return err(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Session store unavailable; logout not completed",
                    )
                    .into_response()
                }
            };
            let redis_key = format!(
                "vi:session:{}:{key}",
                fingerprint(app.security.token.as_deref().unwrap_or(""))
            );
            let stored = match redis::cmd("GET")
                .arg(&redis_key)
                .query_async::<Option<String>>(&mut c)
                .await
            {
                Ok(v) => v,
                Err(_) => {
                    return err(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Session store unavailable; logout not completed",
                    )
                    .into_response()
                }
            };
            if let Some(stored) = stored {
                if app.db.revoke_session(&key).await.is_err() {
                    return err(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Session revocation could not be saved; logout not completed",
                    )
                    .into_response();
                }
                let subject = if stored == "1" {
                    "operator".to_string()
                } else {
                    stored
                };
                if app
                    .db
                    .audit("session.logout", &subject, json!({}))
                    .await
                    .is_err()
                {
                    tracing::warn!(
                        event = "logout_audit_failed",
                        "Session revoked; audit append failed"
                    );
                }
                // The database tombstone already invalidates the cookie on every replica and after restart.
                if redis::cmd("DEL")
                    .arg(&redis_key)
                    .query_async::<u64>(&mut c)
                    .await
                    .is_err()
                {
                    tracing::warn!(
                        event = "logout_cleanup_failed",
                        "Session revoked durably; cache cleanup deferred to TTL"
                    );
                }
            }
        } else {
            if app.db.revoke_session(&key).await.is_err() {
                return err(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Session revocation could not be saved; logout not completed",
                )
                .into_response();
            }
            app.security.sessions.lock().await.remove(&key);
        }
    }
    let secure = if app.security.production {
        "; Secure"
    } else {
        ""
    };
    (
        [(
            header::SET_COOKIE,
            format!("sentinel_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0{secure}"),
        )],
        Json(json!({"authenticated":false})),
    )
        .into_response()
}
pub async fn private_cache(req: Request, next: Next) -> Response {
    let mut response = next.run(req).await;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn development_accepts_both_vite_origins_with_compose_configuration() {
        for origin in [
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            "http://localhost:3000",
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(header::ORIGIN, HeaderValue::from_str(origin).unwrap());
            assert!(
                origin_allowed(&headers, "http://localhost:3000", false),
                "{origin}"
            );
        }
    }

    #[test]
    fn production_requires_the_exact_configured_origin() {
        for origin in [
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            "http://localhost:3000",
            "https://sentinel.test",
            "https://evil.test",
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(header::ORIGIN, HeaderValue::from_str(origin).unwrap());
            assert_eq!(
                origin_allowed(&headers, "https://sentinel.test", true),
                origin == "https://sentinel.test",
                "{origin}"
            );
        }
    }

    #[test]
    fn rejects_untrusted_origins_and_preserves_non_browser_access() {
        let mut headers = HeaderMap::new();
        for production in [false, true] {
            assert!(origin_allowed(
                &headers,
                "http://localhost:3000",
                production
            ));
            for origin in [
                "null",
                "https://evil.test",
                "http://localhost:5174",
                "http://localhost:5173.evil.test",
                "http://127.0.0.2:5173",
                "https://localhost:5173",
            ] {
                headers.insert(header::ORIGIN, HeaderValue::from_str(origin).unwrap());
                assert!(
                    !origin_allowed(&headers, "http://localhost:3000", production),
                    "{origin}"
                );
            }
            headers.insert(header::ORIGIN, HeaderValue::from_bytes(&[0xff]).unwrap());
            assert!(!origin_allowed(
                &headers,
                "http://localhost:3000",
                production
            ));
            headers.clear();
        }
    }
}

/// Bound both handler work and streaming body lifetime; permits survive until body drop.
pub async fn budget(State(app): State<App>, req: Request, next: Next) -> Response {
    use futures_util::StreamExt;
    if !req.uri().path().starts_with("/api/") {
        return next.run(req).await;
    }
    let mut permits = Vec::new();
    match app.requests.clone().try_acquire_owned() {
        Ok(p) => permits.push(p),
        Err(_) => return limited(),
    }
    let export = req.uri().path().ends_with("/download/latest");
    let special = if export {
        Some(app.exports.clone())
    } else if req.uri().path().ends_with("/sbom/analyze") {
        Some(app.analyses.clone())
    } else {
        None
    };
    if let Some(pool) = special {
        match pool.try_acquire_owned() {
            Ok(p) => permits.push(p),
            Err(_) => return limited(),
        }
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    let response = match tokio::time::timeout_at(deadline, next.run(req)).await {
        Ok(r) => r,
        Err(_) => {
            return err(
                StatusCode::GATEWAY_TIMEOUT,
                "Request exceeded its execution budget",
            )
            .into_response()
        }
    };
    let (parts, body) = response.into_parts();
    let stream = body.into_data_stream();
    let max = if export {
        128 * 1024 * 1024
    } else {
        16 * 1024 * 1024
    };
    let bounded = futures_util::stream::try_unfold(
        (stream, permits, 0usize),
        move |(mut stream, permits, total)| async move {
            let item = tokio::time::timeout_at(deadline, stream.next())
                .await
                .map_err(|_| std::io::Error::other("Response deadline exceeded"))?;
            match item {
                None => Ok(None),
                Some(Err(_)) => Err(std::io::Error::other("Response stream failed")),
                Some(Ok(bytes)) => {
                    let total = total + bytes.len();
                    if total > max {
                        return Err(std::io::Error::other("Response exceeds byte budget"));
                    }
                    Ok(Some((bytes, (stream, permits, total))))
                }
            }
        },
    );
    Response::from_parts(parts, axum::body::Body::from_stream(bounded))
}

#[cfg(test)]
mod boundary_tests {
    use super::*;
    use tower::ServiceExt;
    #[test]
    fn forwarded_addresses_are_accepted_only_from_configured_proxies() {
        let peer = "192.0.2.1".parse().unwrap();
        let trusted = HashSet::from([peer]);
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("203.0.113.9, 198.51.100.7"),
        );
        assert_eq!(client_ip(&headers, peer, &HashSet::new()), peer);
        assert_eq!(
            client_ip(&headers, peer, &trusted),
            "198.51.100.7".parse::<IpAddr>().unwrap()
        );
        headers.insert("x-forwarded-for", HeaderValue::from_static("broken"));
        assert_eq!(client_ip(&headers, peer, &trusted), peer);
    }
    #[tokio::test]
    async fn streaming_responses_hold_the_concurrency_permit_until_drop() {
        let app = App {
            db: vi_db::Database::new(),
            security: Security {
                token: Some("test-only".into()),
                sessions: Default::default(),
                redis: None,
                production: false,
                clients: None,
                oidc: None,
                trusted_proxies: Default::default(),
            },
            buckets: Default::default(),
            metrics: Default::default(),
            requests: Arc::new(tokio::sync::Semaphore::new(1)),
            analyses: Arc::new(tokio::sync::Semaphore::new(1)),
            exports: Arc::new(tokio::sync::Semaphore::new(1)),
        };
        let router = Router::new()
            .route(
                "/api/stream",
                get(|| async {
                    axum::body::Body::from_stream(futures_util::stream::pending::<
                        Result<axum::body::Bytes, std::io::Error>,
                    >())
                }),
            )
            .layer(middleware::from_fn_with_state(app.clone(), budget));
        let request = || {
            Request::builder()
                .uri("/api/stream")
                .body(axum::body::Body::empty())
                .unwrap()
        };
        let held = router.clone().oneshot(request()).await.unwrap();
        assert_eq!(held.status(), StatusCode::OK);
        assert_eq!(app.requests.available_permits(), 0);
        let refused = router.clone().oneshot(request()).await.unwrap();
        assert_eq!(refused.status(), StatusCode::TOO_MANY_REQUESTS);
        drop(held);
        assert_eq!(app.requests.available_permits(), 1);
        assert_eq!(
            router.oneshot(request()).await.unwrap().status(),
            StatusCode::OK
        );
    }
}

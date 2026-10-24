use super::*;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::path::Path;
use tokio::io::AsyncReadExt;

#[derive(Clone, Debug, Serialize)]
pub struct Principal {
    pub id: String,
    pub scopes: Vec<String>,
    pub operator: bool,
    pub role: String,
}
impl Principal {
    pub fn operator() -> Self {
        Self {
            id: "operator".into(),
            scopes: vec![],
            operator: true,
            role: "operator".into(),
        }
    }
    pub fn identity(user: &Value) -> Option<Self> {
        if user["disabled"] == true {
            return None;
        }
        let role = user["role"].as_str()?;
        let scopes: &[&str] = match role {
            "reader" => &["read"],
            "analyst" => &["read", "analyze", "vex:write"],
            "auditor" => &["read", "audit:read"],
            "admin" => &[
                "read",
                "analyze",
                "vex:write",
                "ingest",
                "audit:read",
                "admin",
            ],
            _ => return None,
        };
        Some(Self {
            id: user["id"].as_str()?.into(),
            operator: false,
            role: role.into(),
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
        })
    }
    pub fn allows(&self, scope: &str) -> bool {
        scope == "identity"
            || self.operator
            || self.role == "admin" && scope != "operator"
            || self.scopes.iter().any(|s| s == scope)
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Client {
    id: String,
    token_sha256: String,
    scopes: Vec<String>,
    expires_at: String,
}
fn parse(bytes: &[u8], provided: &str) -> Result<Option<Principal>, String> {
    use subtle::ConstantTimeEq;
    let clients: Vec<Client> =
        serde_json::from_slice(bytes).map_err(|_| "Invalid client credential configuration")?;
    if clients.len() > 100 {
        return Err("Too many configured clients".into());
    }
    let hash = format!("{:x}", Sha256::digest(provided.as_bytes()));
    let mut ids = HashSet::new();
    let mut hashes = HashSet::new();
    let mut matched = None;
    for client in clients {
        let expires = chrono::DateTime::parse_from_rfc3339(&client.expires_at)
            .map_err(|_| "Invalid client credential expiry")?;
        if client.id.is_empty()
            || client.id.len() > 64
            || client.id == "operator"
            || client.id == "local"
            || !client
                .id
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
            || !ids.insert(client.id.clone())
            || !hashes.insert(client.token_sha256.clone())
            || client.token_sha256.len() != 64
            || !client
                .token_sha256
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
            || client.scopes.is_empty()
            || client.scopes.len() > 4
            || client
                .scopes
                .iter()
                .any(|s| !["read", "analyze", "vex:write", "ingest"].contains(&s.as_str()))
        {
            return Err("Invalid client credential configuration".into());
        }
        if bool::from(hash.as_bytes().ct_eq(client.token_sha256.as_bytes()))
            && expires > chrono::Utc::now()
        {
            matched = Some(Principal {
                id: client.id,
                scopes: client.scopes,
                operator: false,
                role: "client".into(),
            });
        }
    }
    Ok(matched)
}
pub async fn authenticate(
    path: Option<&Path>,
    provided: &str,
) -> Result<Option<Principal>, String> {
    let Some(path) = path else { return Ok(None) };
    let file = match tokio::fs::File::open(path).await {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("Cannot read client credential configuration".into()),
    };
    let mut bytes = Vec::new();
    file.take(65537)
        .read_to_end(&mut bytes)
        .await
        .map_err(|_| "Cannot read client credential configuration")?;
    if bytes.len() > 65536 {
        return Err("Client credential configuration exceeds limit".into());
    }
    parse(&bytes, provided)
}
pub fn required_scope(path: &str, method: &axum::http::Method) -> &'static str {
    let path = path.strip_prefix("/api").unwrap_or(path);
    match path {
        "/auth/me" => "identity",
        "/audit/events" | "/audit/vex-revisions" => "audit:read",
        p if p.starts_with("/admin/users") || p.starts_with("/admin/sessions") => "admin",
        "/v2/sbom/analyze" => "analyze",
        "/v2/vex" if *method == axum::http::Method::POST => "vex:write",
        "/admin/ingest" | "/admin/jobs" => "ingest",
        "/mcp"
        | "/vulnerabilities"
        | "/v2/vulnerabilities/filter"
        | "/affected-product"
        | "/threat-actors"
        | "/kb-supercedence"
        | "/graphql" => "read",
        _ if matches!(
            *method,
            axum::http::Method::GET | axum::http::Method::HEAD | axum::http::Method::OPTIONS
        ) =>
        {
            "read"
        }
        _ => "operator",
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn human_roles_do_not_inherit_operator_or_administrator_access() {
        for (role, allow, deny) in [
            (
                "reader",
                vec!["read"],
                vec!["analyze", "vex:write", "ingest", "audit:read", "admin"],
            ),
            (
                "analyst",
                vec!["read", "analyze", "vex:write"],
                vec!["ingest", "audit:read", "admin"],
            ),
            (
                "auditor",
                vec!["read", "audit:read"],
                vec!["analyze", "vex:write", "ingest", "admin"],
            ),
            (
                "admin",
                vec![
                    "read",
                    "analyze",
                    "vex:write",
                    "ingest",
                    "audit:read",
                    "admin",
                ],
                vec!["operator"],
            ),
        ] {
            let p = Principal::identity(&json!({"id":"oidc:test","role":role,"disabled":false}))
                .unwrap();
            for scope in allow {
                assert!(p.allows(scope), "{role}/{scope}")
            }
            for scope in deny {
                assert!(!p.allows(scope), "{role}/{scope}")
            }
            assert!(
                Principal::identity(&json!({"id":"oidc:test","role":role,"disabled":true}))
                    .is_none()
            );
        }
        assert!(
            Principal::identity(&json!({"id":"oidc:test","role":"pending","disabled":false}))
                .is_none()
        );
        assert!(
            Principal::identity(&json!({"id":"oidc:test","role":"unknown","disabled":false}))
                .is_none()
        );
    }
    #[test]
    fn scopes_expiry_and_configuration_fail_closed() {
        let mut row = json!({"id":"test-reader","token_sha256":format!("{:x}",Sha256::digest(b"test-secret")),"scopes":["read"],"expires_at":"2999-01-01T00:00:00Z"});
        let principal = parse(json!([row.clone()]).to_string().as_bytes(), "test-secret")
            .unwrap()
            .unwrap();
        assert!(principal.allows("read"));
        assert!(!principal.allows("vex:write"));
        assert!(parse(json!([row.clone()]).to_string().as_bytes(), "wrong")
            .unwrap()
            .is_none());
        row["expires_at"] = json!("2000-01-01T00:00:00Z");
        assert!(
            parse(json!([row.clone()]).to_string().as_bytes(), "test-secret")
                .unwrap()
                .is_none()
        );
        row["scopes"] = json!(["admin"]);
        assert!(parse(json!([row]).to_string().as_bytes(), "test-secret").is_err());
    }
}

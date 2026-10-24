use super::*;
use credentials::Principal;
#[derive(Deserialize, Default)]
pub struct Page {
    limit: Option<i64>,
    before: Option<i64>,
    action: Option<String>,
    subject: Option<String>,
    document_id: Option<String>,
    after: Option<String>,
}
impl Page {
    fn limit(&self) -> Result<i64, (StatusCode, Json<Value>)> {
        let n = self.limit.unwrap_or(50);
        if !(1..=100).contains(&n)
            || self.before.is_some_and(|v| v < 1)
            || [&self.action, &self.subject, &self.document_id, &self.after]
                .iter()
                .any(|s| s.as_ref().is_some_and(|v| v.len() > 512))
        {
            return Err(err(StatusCode::BAD_REQUEST, "Invalid page or filter"));
        }
        Ok(n)
    }
}
#[utoipa::path(get,path="/api/auth/me",tag="Identity",description="Current authenticated identity and capabilities.",responses((status=200,body=Value),(status=401,description="Authentication required")))]
pub async fn me(Extension(p): Extension<Principal>) -> Json<Value> {
    Json(
        json!({"id":p.id,"role":p.role,"scopes":p.scopes,"admin":p.allows("admin"),"audit":p.allows("audit:read")}),
    )
}
#[utoipa::path(get,path="/api/audit/events",tag="Audit",description="Requires auditor or administrator. Exact action/subject filters; maximum 100 events.",params(("limit"=Option<i64>,Query),("before"=Option<i64>,Query),("action"=Option<String>,Query),("subject"=Option<String>,Query)),responses((status=200,body=Value),(status=403,description="Audit access required")))]
pub async fn events(State(app): State<App>, Query(q): Query<Page>) -> ApiResult {
    let limit = q.limit()?;
    app.db
        .audit_page(limit, q.before, q.action, q.subject)
        .await
        .map(Json)
        .map_err(database_error)
}
#[utoipa::path(get,path="/api/audit/vex-revisions",tag="Audit",description="Requires auditor or administrator. Stored VEX before/after history, maximum 10 revisions.",params(("document_id"=String,Query),("limit"=Option<i64>,Query),("before"=Option<i64>,Query)),responses((status=200,body=Value),(status=403,description="Audit access required")))]
pub async fn revisions(State(app): State<App>, Query(q): Query<Page>) -> ApiResult {
    let limit = q.limit()?;
    let id = q
        .document_id
        .filter(|s| !s.is_empty())
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "document_id is required"))?;
    app.db
        .vex_history(&id, limit.min(10), q.before)
        .await
        .map(Json)
        .map_err(database_error)
}
#[utoipa::path(get,path="/api/admin/users",tag="Administration",description="Administrator-only local SSO identities, maximum 100 per page.",params(("limit"=Option<i64>,Query),("after"=Option<String>,Query)),responses((status=200,body=Value),(status=403,description="Administrator required")))]
pub async fn users(State(app): State<App>, Query(q): Query<Page>) -> ApiResult {
    let limit = q.limit()?;
    app.db
        .identity_users(limit, q.after)
        .await
        .map(Json)
        .map_err(database_error)
}
#[derive(Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct Access {
    role: String,
    disabled: bool,
    version: i64,
}
#[utoipa::path(put,path="/api/admin/users/{id}",tag="Administration",description="Assign a local role or disable access. Optimistic version required. Administrators cannot change their own access.",params(("id"=String,Path)),request_body=Access,responses((status=200,body=Value),(status=409,description="Stale version or self-update"),(status=403,description="Administrator required")))]
pub async fn update_user(
    State(app): State<App>,
    Extension(p): Extension<Principal>,
    Path(id): Path<String>,
    Json(body): Json<Access>,
) -> ApiResult {
    if id.len() != 69
        || !id.starts_with("oidc:")
        || body.version < 1
        || !["pending", "reader", "analyst", "auditor", "admin"].contains(&body.role.as_str())
    {
        return Err(err(StatusCode::BAD_REQUEST, "Invalid user or role"));
    }
    if p.id == id {
        return Err(err(
            StatusCode::CONFLICT,
            "Use another administrator or the operator credential to change your own access",
        ));
    }
    match app
        .db
        .set_identity_role(&id, &body.role, body.disabled, body.version, &p.id)
        .await
        .map_err(database_error)?
    {
        true => Ok(Json(json!({"updated":true}))),
        false => Err(err(
            StatusCode::CONFLICT,
            "User changed or no longer exists; refresh before retrying",
        )),
    }
}
#[utoipa::path(get,path="/api/admin/users/{id}/sessions",tag="Administration",description="Administrator-only active SSO sessions. Returned IDs are fingerprints, not cookies. Maximum 100.",params(("id"=String,Path)),responses((status=200,body=Value),(status=403,description="Administrator required")))]
pub async fn sessions(State(app): State<App>, Path(id): Path<String>) -> ApiResult {
    if id.len() > 128 {
        return Err(err(StatusCode::BAD_REQUEST, "Invalid user ID"));
    }
    app.db
        .identity_sessions(&id)
        .await
        .map(Json)
        .map_err(database_error)
}
#[utoipa::path(delete,path="/api/admin/sessions/{id}",tag="Administration",description="Administrator-only durable revocation of an SSO session fingerprint.",params(("id"=String,Path)),responses((status=200,body=Value),(status=404,description="Session not found"),(status=403,description="Administrator required")))]
pub async fn revoke(
    State(app): State<App>,
    Extension(p): Extension<Principal>,
    Path(id): Path<String>,
) -> ApiResult {
    if id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(err(StatusCode::BAD_REQUEST, "Invalid session ID"));
    }
    match app
        .db
        .revoke_identity_session(&id, &p.id)
        .await
        .map_err(database_error)?
    {
        true => Ok(Json(json!({"revoked":true}))),
        false => Err(err(StatusCode::NOT_FOUND, "Session not found")),
    }
}

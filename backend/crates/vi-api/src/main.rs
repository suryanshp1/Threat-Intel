mod credentials;
mod management;
mod mcp;
mod oidc;
mod security;
mod telemetry;
use async_graphql::{Context, EmptyMutation, EmptySubscription, Object, Schema};
use axum::{
    extract::{Path, Query, Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;
use utoipa::OpenApi;
use vi_core::{Vulnerability, JUSTIFICATIONS};
#[derive(Clone)]
struct App {
    db: vi_db::Database,
    security: security::Security,
    buckets: Arc<Mutex<HashMap<String, (Instant, u32)>>>,
    metrics: Arc<telemetry::Metrics>,
    requests: Arc<tokio::sync::Semaphore>,
    analyses: Arc<tokio::sync::Semaphore>,
    exports: Arc<tokio::sync::Semaphore>,
}
type ApiResult = Result<Json<Value>, (StatusCode, Json<Value>)>;
fn err(status: StatusCode, detail: impl ToString) -> (StatusCode, Json<Value>) {
    (
        status,
        Json(json!({"detail":detail.to_string(),"status_code":status.as_u16()})),
    )
}
fn database_error(error: String) -> (StatusCode, Json<Value>) {
    tracing::error!(event = "database_error", error = %error, "Database operation error");
    err(
        StatusCode::SERVICE_UNAVAILABLE,
        "Database operation unavailable",
    )
}

fn validate_lookup(q: &Value) -> Result<(), (StatusCode, Json<Value>)> {
    if ["name", "product", "ecosystem", "cve", "kb"]
        .iter()
        .any(|k| q.get(*k).is_some_and(|v| !v.is_null() && !v.is_string()))
        || ["limit", "skip"].iter().any(|k| {
            q.get(*k)
                .is_some_and(|v| !v.is_null() && v.as_u64().is_none())
        })
    {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "Lookup field has an invalid type",
        ));
    }

    if ["name", "product", "ecosystem", "cve", "kb"]
        .iter()
        .any(|k| q[*k].as_str().is_some_and(|s| s.len() > 512))
        || q["limit"].as_u64().is_some_and(|v| v == 0 || v > 100)
        || q["skip"].as_u64().is_some_and(|v| v > 10000)
    {
        return Err(err(StatusCode::BAD_REQUEST, "Lookup exceeds input limits"));
    }
    Ok(())
}
#[derive(Deserialize, Serialize, Default, utoipa::ToSchema)]
struct Filter {
    #[serde(default)]
    conditions: Vec<Condition>,
    #[serde(default)]
    text_search: String,
    #[serde(default)]
    operator: String,
    sort_by: Option<String>,
    sort_order: Option<String>,
    cursor: Option<String>,
    limit: Option<usize>,
}
#[derive(Deserialize, Serialize, utoipa::ToSchema)]
struct Condition {
    field: String,
    operator: String,
    value: Value,
}
#[utoipa::path(post,path="/api/v2/vulnerabilities/filter",request_body=Filter,responses((status=200,description="Filtered CVE records, facets, and next_cursor",body=Value),(status=400,description="Invalid filter")),tag="Vulnerabilities")]
async fn filter(State(app): State<App>, Json(f): Json<Filter>) -> ApiResult {
    vi_core::validate_query(&serde_json::to_value(&f).unwrap())
        .map_err(|e| err(StatusCode::BAD_REQUEST, e))?;
    let allowed = [
        "id",
        "vendor",
        "ecosystem",
        "cvss",
        "epss_score",
        "priority_score",
        "seen_wild",
        "is_zeroday",
        "exploit_available",
        "exploits.exploit_available",
        "patch_available",
        "patches.patch_available",
        "ssvc_decision",
        "known_ransomware_use",
        "bod_26_04_forensic_triage",
        "tags",
        "product",
        "published",
    ];
    for c in &f.conditions {
        if !allowed.contains(&c.field.as_str())
            || !["eq", "neq", "gt", "gte", "lt", "lte", "in", "contains"]
                .contains(&c.operator.as_str())
        {
            return Err(err(
                StatusCode::BAD_REQUEST,
                "Unsupported filter field or operator",
            ));
        }
    }
    for c in &f.conditions {
        let numeric = ["cvss", "epss_score", "priority_score"].contains(&c.field.as_str());
        let boolean = [
            "seen_wild",
            "is_zeroday",
            "exploit_available",
            "exploits.exploit_available",
            "patch_available",
            "patches.patch_available",
            "known_ransomware_use",
            "bod_26_04_forensic_triage",
        ]
        .contains(&c.field.as_str());
        let valid_value = |v: &Value| {
            if numeric {
                v.is_number()
            } else if boolean {
                v.is_boolean()
            } else {
                v.is_string()
            }
        };
        if c.operator == "in" {
            if !c
                .value
                .as_array()
                .is_some_and(|a| a.iter().all(valid_value))
            {
                return Err(err(
                    StatusCode::BAD_REQUEST,
                    "in requires an array of values matching the field type",
                ));
            }
        } else if !valid_value(&c.value)
            || (["gt", "gte", "lt", "lte"].contains(&c.operator.as_str()) && !numeric)
            || (c.operator == "contains" && (numeric || boolean))
        {
            return Err(err(
                StatusCode::BAD_REQUEST,
                "Filter value or operator does not match the field type",
            ));
        }
    }
    if f.sort_order
        .as_deref()
        .is_some_and(|v| v != "asc" && v != "desc")
    {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "sort_order must be asc or desc",
        ));
    }
    if !["", "and", "or"].contains(&f.operator.as_str()) {
        return Err(err(StatusCode::BAD_REQUEST, "operator must be and or or"));
    }
    let value = serde_json::to_value(f).map_err(|e| err(StatusCode::BAD_REQUEST, e))?;
    app.db.query(&value).await.map(Json).map_err(|e| {
        if e.contains("cursor") || e.contains("sort") {
            err(StatusCode::BAD_REQUEST, e)
        } else {
            database_error(e)
        }
    })
}

#[utoipa::path(get,path="/api/vulnerabilities/{id}",params(("id"=String,Path,description="CVE identifier")),responses((status=200,body=Vulnerability),(status=404,description="CVE not found")),tag="Vulnerabilities")]
async fn detail(State(app): State<App>, Path(id): Path<String>) -> ApiResult {
    app.db
        .get(&id.to_uppercase())
        .await
        .map_err(database_error)?
        .map(|v| Json(serde_json::to_value(v).unwrap()))
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "Vulnerability not found"))
}
#[utoipa::path(get,path="/api/stats/",responses((status=200,body=Value)),tag="Intelligence")]
async fn stats(State(app): State<App>) -> ApiResult {
    app.db.stats().await.map(Json).map_err(database_error)
}
#[utoipa::path(post,path="/api/threat-actors",request_body=Value,responses((status=200,body=Value)),tag="Intelligence")]
async fn actors(State(app): State<App>, Json(q): Json<Value>) -> ApiResult {
    validate_lookup(&q)?;
    app.db
        .entity_page(&["actors", "ransomware"], &q)
        .await
        .map(Json)
        .map_err(database_error)
}

#[utoipa::path(post,path="/api/affected-product",request_body=Value,responses((status=200,body=Value)),tag="Intelligence")]
async fn products(State(app): State<App>, Json(q): Json<Value>) -> ApiResult {
    validate_lookup(&q)?;
    app.db
        .product_page(&q)
        .await
        .map(Json)
        .map_err(database_error)
}

async fn cpe(State(app): State<App>, Query(q): Query<HashMap<String, String>>) -> ApiResult {
    products(State(app), Json(json!({"name":q.get("keyword")}))).await
}
#[utoipa::path(post,path="/api/kb-supercedence",request_body=Value,responses((status=200,body=Value),(status=400,description="Missing KB"),(status=404,description="Unknown KB")),tag="Tools")]
async fn kb(State(app): State<App>, Json(q): Json<Value>) -> ApiResult {
    let id = q["kb"]
        .as_str()
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "kb is required"))?
        .trim()
        .to_uppercase();
    validate_lookup(&q)?;
    let product = q["product"].as_str();
    let mut queue = vec![id.clone()];
    let mut seen = HashSet::new();
    let mut rows = vec![];
    while let Some(current) = queue.pop() {
        if seen.len() >= 100 {
            return Err(err(
                StatusCode::BAD_REQUEST,
                "Patch graph exceeds 100 nodes",
            ));
        }
        if !seen.insert(current.clone()) {
            continue;
        }
        let patches = app
            .db
            .patch_candidates(&current)
            .await
            .map_err(database_error)?;
        for p in patches
            .iter()
            .filter(|p| p["id"] == current && product.is_none_or(|v| p["product"] == v))
        {
            let next: Vec<_> = patches
                .iter()
                .filter(|n| {
                    n["product"] == p["product"]
                        && n["supersedes"]
                            .as_array()
                            .is_some_and(|s| s.contains(&json!(current)))
                })
                .collect();
            let mut row = p.clone();
            row["superseded_by"] = json!(next
                .iter()
                .filter_map(|n| n["id"].as_str())
                .collect::<Vec<_>>());
            for n in next {
                if let Some(id) = n["id"].as_str() {
                    queue.push(id.into())
                }
            }
            if rows.len() >= 100 {
                return Err(err(
                    StatusCode::BAD_REQUEST,
                    "Patch graph exceeds 100 results",
                ));
            }
            rows.push(row);
        }
    }
    if rows.is_empty() {
        return Err(err(
            StatusCode::NOT_FOUND,
            "KB article has not been ingested from Microsoft MSRC",
        ));
    }
    Ok(Json(json!({"kb":id,"results":rows})))
}
async fn search(State(app): State<App>, Query(q): Query<HashMap<String, String>>) -> ApiResult {
    let data=app.db.query(&json!({"text_search":q.get("cve").or(q.get("q")).map(String::as_str).unwrap_or(""),"limit":10})).await.map_err(database_error)?;
    Ok(Json(data["results"].clone()))
}
async fn zerodays(State(app): State<App>) -> ApiResult {
    app.db.query(&json!({"conditions":[{"field":"is_zeroday","operator":"eq","value":true}],"sort_by":"published","limit":100})).await.map(Json).map_err(database_error)
}
#[utoipa::path(get,path="/api/v2/vex",responses((status=200,body=Value)),tag="Tools")]
async fn list_vex(State(app): State<App>, Query(q): Query<HashMap<String, String>>) -> ApiResult {
    let limit = q
        .get("limit")
        .map(|s| s.parse::<usize>())
        .transpose()
        .map_err(|_| err(StatusCode::BAD_REQUEST, "Invalid VEX page limit"))?
        .unwrap_or(100);
    let skip = q
        .get("skip")
        .map(|s| s.parse::<usize>())
        .transpose()
        .map_err(|_| err(StatusCode::BAD_REQUEST, "Invalid VEX page offset"))?
        .unwrap_or(0);
    if limit == 0 || limit > 100 || skip > 10000 {
        return Err(err(StatusCode::BAD_REQUEST, "VEX page exceeds limits"));
    }
    app.db
        .vex_page(limit, skip)
        .await
        .map(Json)
        .map_err(database_error)
}

#[utoipa::path(post,path="/api/v2/vex",request_body=Value,responses((status=200,body=Value),(status=400,description="Invalid OpenVEX")),tag="Tools")]
async fn save_vex(
    State(app): State<App>,
    Extension(principal): Extension<credentials::Principal>,
    Json(doc): Json<Value>,
) -> ApiResult {
    if doc.to_string().len() > 128 * 1024 {
        return Err(err(
            StatusCode::PAYLOAD_TOO_LARGE,
            "VEX document exceeds 128 KiB",
        ));
    }
    if doc["@context"] != "https://openvex.dev/ns/v0.2.0" {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "Expected OpenVEX v0.2.0 context",
        ));
    }
    if doc["author"].as_str().unwrap_or("").trim().is_empty() {
        return Err(err(StatusCode::BAD_REQUEST, "Author is required"));
    }
    let statements = doc["statements"]
        .as_array()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            err(
                StatusCode::BAD_REQUEST,
                "At least one statement is required",
            )
        })?;
    if statements.len() > 100 {
        return Err(err(StatusCode::BAD_REQUEST, "VEX exceeds 100 statements"));
    }
    for stmt in statements {
        let status = stmt["status"].as_str().unwrap_or("");
        if !["affected", "not_affected", "fixed", "under_investigation"].contains(&status) {
            return Err(err(StatusCode::BAD_REQUEST, "Invalid VEX status"));
        }
        if status == "not_affected"
            && !JUSTIFICATIONS.contains(&stmt["justification"].as_str().unwrap_or(""))
        {
            return Err(err(
                StatusCode::BAD_REQUEST,
                "not_affected requires a recognized justification",
            ));
        }
        if stmt["vulnerability"]["name"]
            .as_str()
            .unwrap_or("")
            .is_empty()
            || !stmt["products"].as_array().is_some_and(|p| {
                !p.is_empty()
                    && p.len() <= 100
                    && p.iter().all(|p| {
                        p["@id"].as_str().is_some_and(|id| {
                            id.starts_with("pkg:") && vi_core::package_version(id).is_some()
                        })
                    })
            })
        {
            return Err(err(
                StatusCode::BAD_REQUEST,
                "Each statement needs a CVE and versioned product PURL",
            ));
        }
    }
    if doc["@id"].as_str().is_none_or(|v| v.is_empty()) {
        return Err(err(StatusCode::BAD_REQUEST, "Document @id is required"));
    }
    app.db
        .save_vex(doc.clone(), &principal.id)
        .await
        .map_err(database_error)?;
    Ok(Json(doc))
}

#[utoipa::path(post,path="/api/v2/sbom/analyze",request_body=Value,responses((status=200,body=Value),(status=400,description="Invalid SBOM")),tag="Tools")]
async fn analyze(State(app): State<App>, Json(payload): Json<Value>) -> ApiResult {
    let sbom = payload.get("sbom").unwrap_or(&payload);
    if sbom["bomFormat"] != "CycloneDX" && sbom.get("spdxVersion").is_none() {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "Expected a CycloneDX or SPDX JSON document",
        ));
    }
    let mut purls = Vec::<String>::new();
    fn walk(v: &Value, out: &mut Vec<String>) {
        match v {
            Value::Object(m) => {
                if let Some(p) = m.get("purl").and_then(Value::as_str) {
                    out.push(p.into());
                }
                if m.get("referenceType").and_then(Value::as_str) == Some("purl") {
                    if let Some(p) = m.get("referenceLocator").and_then(Value::as_str) {
                        out.push(p.into());
                    }
                }
                for val in m.values() {
                    walk(val, out);
                }
            }
            Value::Array(a) => {
                for val in a {
                    walk(val, out);
                }
            }
            _ => {}
        }
    }
    walk(sbom, &mut purls);
    purls.sort();
    purls.dedup();
    if purls.is_empty() {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "No package URLs found in the SBOM",
        ));
    }
    if purls.len() > 1000 {
        return Err(err(
            StatusCode::PAYLOAD_TOO_LARGE,
            "SBOM exceeds 1000 unique packages; split the manifest",
        ));
    }
    let unversioned: Vec<_> = purls
        .iter()
        .filter(|p| vi_core::package_version(p).is_none())
        .cloned()
        .collect();
    let versioned: Vec<_> = purls
        .iter()
        .filter(|p| vi_core::package_version(p).is_some())
        .cloned()
        .collect();
    let upstream = vi_ingest::osv_analyze(&versioned).await.map_err(|e| {
        tracing::warn!(error = %e, "OSV analysis query failed");
        err(
            StatusCode::BAD_GATEWAY,
            "OSV could not complete the applicability query; no clean result is inferred",
        )
    })?;
    let docs = app
        .db
        .vex_for_purls(&versioned)
        .await
        .map_err(database_error)?;
    let mut findings = vec![];
    for item in upstream {
        let advisory = &item["advisory"];
        let purl = item["purl"].as_str().unwrap_or("");
        let aliases = advisory["aliases"].as_array().cloned().unwrap_or_default();
        let cve = aliases
            .iter()
            .filter_map(Value::as_str)
            .find(|id| id.starts_with("CVE-"));
        let record = if let Some(id) = cve {
            app.db.get(id).await.map_err(database_error)?
        } else {
            None
        };
        let in_catalog = record.is_some();
        let v = match record {
            Some(v) => serde_json::to_value(v).unwrap(),
            None => match vi_ingest::adapters::from_osv(advisory, purl, &item["provenance"]) {
                Ok(v) => serde_json::to_value(v).unwrap(),
                Err(_) => {
                    json!({"id":advisory["id"],"title":advisory["summary"],"priority_score":0,"ssvc_decision":"Unassessed","sources":["OSV"]})
                }
            },
        };
        let statement = docs
            .iter()
            .rev()
            .flat_map(|d| d["statements"].as_array().cloned().unwrap_or_default())
            .find(|stmt| {
                stmt["vulnerability"]["name"] == v["id"]
                    && stmt["products"]
                        .as_array()
                        .is_some_and(|p| p.iter().any(|p| p["@id"] == purl))
            });
        // Only explicit analyst approval permits unsigned local VEX to suppress findings.
        let trusted = std::env::var("VI_TRUST_LOCAL_VEX").as_deref() == Ok("true");
        let suppressed = trusted
            && statement.as_ref().is_some_and(|s| {
                s["status"] == "fixed"
                    || (s["status"] == "not_affected"
                        && JUSTIFICATIONS.contains(&s["justification"].as_str().unwrap_or("")))
            });
        findings.push(json!({"vulnerability":v,"in_catalog":in_catalog,"purl":purl,"advisory":advisory,"provenance":item["provenance"],"suppressed":suppressed,"effective_priority":if suppressed{json!(0)}else{v["priority_score"].clone()},"statement":statement}));
    }
    findings.sort_by_key(|f| std::cmp::Reverse(f["effective_priority"].as_u64().unwrap_or(0)));
    Ok(Json(
        json!({"packages":purls.len(),"findings":findings,"suppressed":findings.iter().filter(|f|f["suppressed"]==true).count(),"unversioned":unversioned,"trust":"OSV performs ecosystem-aware version matching. Unsigned VEX does not suppress findings unless VI_TRUST_LOCAL_VEX is explicitly enabled."}),
    ))
}
#[utoipa::path(get,path="/api/v2/vulnerabilities/{id}/rules",params(("id"=String,Path,description="CVE identifier")),responses((status=200,body=Value),(status=404,description="Unknown CVE")),tag="Vulnerabilities")]
async fn rules(State(app): State<App>, Path(id): Path<String>) -> ApiResult {
    let mut result = app
        .db
        .entity_links("rules", &id)
        .await
        .map_err(database_error)?;
    result["note"] =
        json!("Source-backed detection artifacts. Review upstream licenses before deployment.");
    Ok(Json(result))
}

#[utoipa::path(get,path="/api/knowledge/{id}",params(("id"=String,Path,description="CWE-79 or OWASP-A01:2025")),responses((status=200,body=Value),(status=404,description="Knowledge entry not found")),tag="Intelligence")]
async fn knowledge(State(app): State<App>, Path(id): Path<String>) -> ApiResult {
    app.db
        .knowledge(&id.to_uppercase())
        .await
        .map_err(database_error)?
        .map(Json)
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "Knowledge entry not found"))
}
async fn relations(State(app): State<App>, Path(id): Path<String>) -> ApiResult {
    let knowledge = app.db.knowledge(&id).await.map_err(database_error)?;
    let mut result = app
        .db
        .entity_links("relationships", &id)
        .await
        .map_err(database_error)?;
    result["knowledge"] = knowledge.unwrap_or(Value::Null);
    Ok(Json(result))
}

#[utoipa::path(get,path="/api/download/latest",responses((status=200,description="Cursor-paginated NDJSON export",body=String)),tag="Intelligence")]
async fn download(State(app): State<App>) -> Response {
    let db = app.db.clone();
    let stream = futures_util::stream::try_unfold(
        (db, None::<String>, false),
        |(db, cursor, done)| async move {
            if done {
                return Ok::<_, std::io::Error>(None);
            }
            let page = db
                .query(&json!({"limit":100,"sort_by":"id","sort_order":"asc","cursor":cursor}))
                .await
                .map_err(std::io::Error::other)?;
            let next = page["next_cursor"].as_str().map(str::to_string);
            let body = page["results"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| format!("{}\n", serde_json::to_string(v).unwrap()))
                .collect::<String>();
            let done = next.is_none();
            Ok(Some((body, (db, next, done))))
        },
    );
    let mut response = axum::body::Body::from_stream(stream).into_response();
    response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        "application/x-ndjson".parse().unwrap(),
    );
    response.headers_mut().insert(
        axum::http::header::CONTENT_DISPOSITION,
        "attachment; filename=sentinel-intelligence.jsonl"
            .parse()
            .unwrap(),
    );
    response
}
struct QueryRoot;
#[Object]
impl QueryRoot {
    async fn vulnerabilities(
        &self,
        ctx: &Context<'_>,
        search: Option<String>,
        limit: Option<u32>,
    ) -> async_graphql::Result<async_graphql::Json<Value>> {
        let app = ctx.data_unchecked::<App>();
        let result=app.db.query(&json!({"text_search":search.unwrap_or_default(),"limit":limit.unwrap_or(20).clamp(1,100)})).await.map_err(async_graphql::Error::new)?;
        Ok(async_graphql::Json(result))
    }
}
async fn graphql(
    State(app): State<App>,
    Json(req): Json<async_graphql::Request>,
) -> Json<async_graphql::Response> {
    Json(
        Schema::build(QueryRoot, EmptyMutation, EmptySubscription)
            .data(app)
            .limit_depth(8)
            .limit_complexity(200)
            .finish()
            .execute(req)
            .await,
    )
}
async fn taxii(State(app): State<App>, Query(q): Query<HashMap<String, String>>) -> Response {
    let limit = q
        .get("limit")
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(100)
        .clamp(1, 100);
    let data = match app
        .db
        .query(&json!({"limit":limit,"cursor":q.get("next"),"sort_by":"id","sort_order":"asc"}))
        .await
    {
        Ok(v) => v,
        Err(e) => return database_error(e).into_response(),
    };
    let objects:Vec<_>=data["results"].as_array().unwrap().iter().map(|v|{let id=v["id"].as_str().unwrap_or("");let stamp=v["ingested_at"].as_str().filter(|s|!s.is_empty()).unwrap_or("1970-01-01T00:00:00Z");json!({"type":"vulnerability","spec_version":"2.1","id":format!("vulnerability--{}",uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_URL,id.as_bytes())),"created":stamp,"modified":stamp,"name":id,"description":v["description"],"external_references":[{"source_name":"cve","external_id":id,"url":format!("https://nvd.nist.gov/vuln/detail/{id}")}]})}).collect();
    ([(axum::http::header::CONTENT_TYPE,"application/taxii+json;version=2.1")],Json(json!({"more":!data["next_cursor"].is_null(),"next":data["next_cursor"],"objects":objects}))).into_response()
}
async fn sources(State(app): State<App>) -> ApiResult {
    app.db
        .checkpoints()
        .await
        .map(|v| Json(json!({"results":v})))
        .map_err(database_error)
}
async fn ingest(
    State(app): State<App>,
    Extension(principal): Extension<credentials::Principal>,
    Json(q): Json<Value>,
) -> ApiResult {
    let source = q["source"]
        .as_str()
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "source is required"))?;
    app.db
        .enqueue(source, &principal.id)
        .await
        .map(Json)
        .map_err(|e| err(StatusCode::BAD_REQUEST, e))
}
async fn jobs(State(app): State<App>) -> ApiResult {
    app.db
        .jobs()
        .await
        .map(|v| Json(json!({"results":v})))
        .map_err(database_error)
}
async fn readiness(State(app): State<App>) -> Response {
    if app.db.ready().await && app.security.ready().await {
        Json(json!({"status":"ready"})).into_response()
    } else {
        err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable").into_response()
    }
}
#[derive(OpenApi)]
#[openapi(
    info(
        title = "Sentinel Intelligence API",
        version = "0.1.0",
        description = "Source-backed vulnerability intelligence API. Production deployments require bearer authentication or an authenticated operator/OIDC HttpOnly session."
    ),
    paths(
        filter,
        detail,
        knowledge,
        stats,
        actors,
        products,
        kb,
        list_vex,
        save_vex,
        analyze,
        rules,
        download,
        management::me,
        management::events,
        management::revisions,
        management::users,
        management::update_user,
        management::sessions,
        management::revoke
    ),
    components(schemas(Vulnerability, Filter, Condition, management::Access))
)]
struct ApiDoc;
async fn openapi() -> Json<Value> {
    Json(serde_json::to_value(ApiDoc::openapi()).expect("OpenAPI serialization"))
}
async fn docs() -> Html<&'static str> {
    Html(include_str!("docs.html"))
}
async fn docs_script() -> impl IntoResponse {
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/javascript; charset=utf-8",
        )],
        include_str!("docs.js"),
    )
}
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    telemetry::init_tracing("sentinel-api");
    let db = vi_db::Database::new();
    db.initialize().await.map_err(std::io::Error::other)?;
    let security = security::Security::new().map_err(std::io::Error::other)?;
    let metrics_collector = Arc::new(telemetry::Metrics::default());
    let app = App {
        db,
        security,
        buckets: Default::default(),
        metrics: metrics_collector.clone(),
        requests: Arc::new(tokio::sync::Semaphore::new(16)),
        analyses: Arc::new(tokio::sync::Semaphore::new(2)),
        exports: Arc::new(tokio::sync::Semaphore::new(2)),
    };
    let api = Router::new()
        .route(
            "/mcp",
            post(mcp::handle).layer(tower_http::limit::RequestBodyLimitLayer::new(64 * 1024)),
        )
        .route("/auth/me", get(management::me))
        .route("/audit/events", get(management::events))
        .route("/audit/vex-revisions", get(management::revisions))
        .route("/admin/users", get(management::users))
        .route(
            "/admin/users/{id}",
            axum::routing::put(management::update_user),
        )
        .route("/admin/users/{id}/sessions", get(management::sessions))
        .route(
            "/admin/sessions/{id}",
            axum::routing::delete(management::revoke),
        )
        .route("/stats/", get(stats))
        .route("/vulnerabilities", post(filter))
        .route("/vulnerabilities/{id}", get(detail))
        .route("/knowledge/{id}", get(knowledge))
        .route("/v2/vulnerabilities/filter", post(filter))
        .route("/v2/vulnerabilities/{id}/rules", get(rules))
        .route("/latest/zerodays", get(zerodays))
        .route("/search/", get(search_handler))
        .route("/search/cpe/", get(cpe))
        .route("/affected-product", post(products))
        .route("/threat-actors", post(actors))
        .route("/kb-supercedence", post(kb))
        .route("/v2/sbom/analyze", post(analyze))
        .route("/v2/vex", get(list_vex).post(save_vex))
        .route("/download/latest", get(download))
        .route("/graphql", post(graphql))
        .route("/v21/collections/sentinel/objects/", get(taxii))
        .route("/metrics", get(metrics))
        .route("/sources", get(sources))
        .route("/admin/ingest", post(ingest))
        .route("/admin/jobs", get(jobs))
        .route("/v2/vulnerabilities/{id}/relationships", get(relations))
        .route_layer(middleware::from_fn_with_state(app.clone(), security::gate));
    let router = Router::new()
        .route(
            "/api/session",
            post(security::login)
                .delete(security::logout)
                .layer(tower_http::limit::RequestBodyLimitLayer::new(4096)),
        )
        .route("/api/auth/config", get(oidc::info))
        .route("/api/auth/oidc/start", post(oidc::start))
        .route("/api/auth/oidc/callback", get(oidc::callback))
        .route("/readyz", get(readiness))
        .nest("/api", api)
        .route(
            "/health",
            get(|| async { Json(json!({"status":"ok","version":"0.1.0"})) }),
        )
        .route("/api-docs/openapi.json", get(openapi))
        .route("/scalar", get(docs))
        .route("/api-docs/ui.js", get(docs_script))
        .route(
            "/taxii2/",
            get(|| async {
                Json(json!({"title":"Sentinel local STIX export","api_roots":["/api/v21/"]}))
            }),
        )
        .layer(middleware::from_fn_with_state(
            metrics_collector.clone(),
            telemetry::track_telemetry,
        ))
        .layer(middleware::from_fn_with_state(
            app.clone(),
            security::budget,
        ))
        .layer(middleware::from_fn(security::private_cache))
        .with_state(app)
        .layer(tower_http::limit::RequestBodyLimitLayer::new(
            10 * 1024 * 1024,
        ));
    let port = std::env::var("PORT").unwrap_or_else(|_| "8080".into());
    let listener = tokio::net::TcpListener::bind(format!(
        "{}:{port}",
        std::env::var("BIND_ADDR").unwrap_or_else(|_| "127.0.0.1".into())
    ))
    .await?;
    tracing::info!(port = %port, "Sentinel API listening");
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown())
    .await?;
    Ok(())
}
async fn search_handler(state: State<App>, q: Query<HashMap<String, String>>) -> ApiResult {
    search(state, q).await
}

async fn shutdown() {
    #[cfg(unix)]
    {
        let mut term =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();
        tokio::select! {_=term.recv()=>{},_=tokio::signal::ctrl_c()=>{}}
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
async fn metrics(State(app): State<App>) -> Response {
    let db_ready = app.db.ready().await;
    let security_ready = app.security.ready().await;
    let stats = app.db.stats().await.ok();
    let body = app
        .metrics
        .render_prometheus(stats.as_ref(), db_ready, security_ready);
    (
        [(axum::http::header::CONTENT_TYPE, "text/plain;version=0.0.4")],
        body,
    )
        .into_response()
}

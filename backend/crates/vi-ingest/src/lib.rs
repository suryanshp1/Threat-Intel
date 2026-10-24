pub mod adapters;
pub mod expansion;
pub mod knowledge;
pub mod scrapers;
use chrono::{Duration, Utc};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{path::PathBuf, time::Duration as Timeout};
use vi_core::SOURCES;
use vi_db::{Batch, Database};

#[derive(Clone)]
pub struct Fetcher {
    client: reqwest::Client,
    cache: PathBuf,
}
#[derive(Clone)]
pub struct Document {
    pub bytes: Vec<u8>,
    pub url: String,
    pub sha256: String,
    pub fetched_at: String,
}
impl Document {
    pub fn json(&self) -> Result<Value, String> {
        serde_json::from_slice(&self.bytes).map_err(|e| format!("Invalid upstream JSON: {e}"))
    }
    pub fn provenance(&self, source: &str) -> Value {
        json!({"source":source,"url":self.url,"sha256":self.sha256,"retrieved_at":self.fetched_at})
    }
}
impl Fetcher {
    pub fn new() -> Result<Self, String> {
        Ok(Self {
            client: reqwest::Client::builder()
                .user_agent("Sentinel-Intelligence/0.2 (open-source vulnerability intelligence)")
                .connect_timeout(Timeout::from_secs(15))
                .timeout(Timeout::from_secs(180))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .map_err(|e| e.to_string())?,
            cache: std::env::var("VI_FEED_CACHE")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("backend/data/feed-cache")),
        })
    }
    pub async fn get(&self, url: &str, headers: &[(&str, &str)]) -> Result<Document, String> {
        self.get_bounded(url, headers, 128 * 1024 * 1024).await
    }
    pub(crate) async fn get_bounded(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        max: usize,
    ) -> Result<Document, String> {
        if !url.starts_with("https://") {
            return Err("Feeds require HTTPS".into());
        }
        tokio::fs::create_dir_all(&self.cache)
            .await
            .map_err(|e| e.to_string())?;
        let key = format!("{:x}", Sha256::digest(url.as_bytes()));
        let path = self.cache.join(&key);
        let meta = self.cache.join(format!("{key}.json"));
        let old: Value = tokio::fs::read(&meta)
            .await
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or(Value::Null);
        let mut request = self.client.get(url);
        for (k, v) in headers {
            request = request.header(*k, *v)
        }
        if path.exists() {
            if let Some(etag) = old["etag"].as_str() {
                request = request.header("If-None-Match", etag)
            } else if let Some(modified) = old["last_modified"].as_str() {
                request = request.header("If-Modified-Since", modified)
            }
        }
        let mut response = request
            .send()
            .await
            .map_err(|e| format!("Upstream transport failed: {e}"))?;
        let now = Utc::now().to_rfc3339();
        if response.status() == reqwest::StatusCode::NOT_MODIFIED {
            if tokio::fs::metadata(&path)
                .await
                .map_err(|e| e.to_string())?
                .len()
                > max as u64
            {
                return Err("Cached upstream document exceeds download limit".into());
            }
            let bytes = tokio::fs::read(&path).await.map_err(|e| e.to_string())?;
            let sha256 = format!("{:x}", Sha256::digest(&bytes));
            return Ok(Document {
                bytes,
                url: url.into(),
                sha256,
                fetched_at: now,
            });
        }
        if !response.status().is_success() {
            let retry = response
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("900");
            return Err(format!(
                "HTTP {} from {} (Retry-After: {retry})",
                response.status().as_u16(),
                url.split('?').next().unwrap_or(url)
            ));
        }
        let metadata = json!({"etag":response.headers().get("etag").and_then(|v|v.to_str().ok()),"last_modified":response.headers().get("last-modified").and_then(|v|v.to_str().ok())});
        if response.content_length().is_some_and(|n| n > max as u64) {
            return Err("Upstream document exceeds download limit".into());
        }
        let mut bytes = vec![];
        while let Some(chunk) = response.chunk().await.map_err(|e| e.to_string())? {
            if bytes.len() + chunk.len() > max {
                return Err(format!("Upstream document exceeds {max} byte limit"));
            }
            bytes.extend_from_slice(&chunk)
        }
        let sha256 = format!("{:x}", Sha256::digest(&bytes));
        let tmp = path.with_extension(format!("{}.tmp", std::process::id()));
        tokio::fs::write(&tmp, &bytes)
            .await
            .map_err(|e| e.to_string())?;
        tokio::fs::rename(&tmp, &path)
            .await
            .map_err(|e| e.to_string())?;
        tokio::fs::write(meta, serde_json::to_vec(&metadata).unwrap())
            .await
            .map_err(|e| e.to_string())?;
        Ok(Document {
            bytes,
            url: url.into(),
            sha256,
            fetched_at: now,
        })
    }
    pub async fn post(&self, url: &str, payload: &Value) -> Result<Value, String> {
        if !url.starts_with("https://") {
            return Err("Upstream API requires HTTPS".into());
        }
        let mut response = self
            .client
            .post(url)
            .json(payload)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if !response.status().is_success() {
            return Err(format!("Upstream API returned {}", response.status()));
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|e| e.to_string())? {
            if bytes.len() + chunk.len() > 1024 * 1024 {
                return Err("Upstream API response exceeds 1 MiB".into());
            }
            bytes.extend_from_slice(&chunk)
        }
        serde_json::from_slice(&bytes).map_err(|e| e.to_string())
    }
}
pub async fn run_source(db: &Database, source: &str, force: bool) -> Result<usize, String> {
    let cadence = SOURCES
        .iter()
        .find(|(s, _)| *s == source)
        .ok_or("Unknown source")?
        .1;
    let mut cp = db
        .checkpoints()
        .await?
        .into_iter()
        .find(|v| v["source_name"] == source)
        .unwrap_or(json!({"source_name":source}));
    if source == "Vendor CSAF / OpenVEX"
        && !std::path::Path::new(
            &std::env::var("VI_VEX_IMPORT_DIR")
                .unwrap_or_else(|_| "backend/data/vex-import".into()),
        )
        .exists()
    {
        cp["status"] = json!("Disabled");
        cp["last_error"] = Value::Null;
        cp["backoff_until"] = Value::Null;
        cp["configuration_required"] =
            json!("Configure a publisher-verified CSAF/OpenVEX import directory");
        db.save_checkpoint(source, cp).await?;
        return Ok(0);
    }
    if cp["backoff_until"]
        .as_str()
        .and_then(|v| chrono::DateTime::parse_from_rfc3339(v).ok())
        .is_some_and(|t| t > Utc::now())
    {
        return Err("Source is in persisted backoff".into());
    }
    if !force
        && cp["next_run_at"]
            .as_str()
            .and_then(|v| chrono::DateTime::parse_from_rfc3339(v).ok())
            .is_some_and(|t| t > Utc::now())
    {
        return Ok(0);
    }
    if !db.claim(source).await? {
        return Ok(0);
    }
    cp["last_error"] = Value::Null;
    cp["configuration_required"] = Value::Null;
    cp["status"] = json!("Running");
    cp["last_started_at"] = json!(Utc::now().to_rfc3339());
    db.save_checkpoint(source, cp.clone()).await?;
    let fetcher = Fetcher::new()?;
    let result = adapters::ingest(db, &fetcher, source, &mut cp).await;
    match &result {
        Ok(count) => {
            cp["status"] = json!("Healthy");
            cp["last_success_at"] = json!(Utc::now().to_rfc3339());
            cp["next_run_at"] =
                json!((Utc::now() + Duration::seconds(cadence as i64)).to_rfc3339());
            cp["records"] = json!(count);
            cp["consecutive_failures"] = json!(0);
            cp["last_error"] = Value::Null;
            cp["backoff_until"] = Value::Null;
        }
        Err(error) => {
            let n = cp["consecutive_failures"].as_u64().unwrap_or(0) + 1;
            let retry = error
                .split("Retry-After: ")
                .nth(1)
                .and_then(|s| s.trim_end_matches(')').parse::<i64>().ok())
                .unwrap_or(60 * 2_i64.pow(n.min(10) as u32));
            cp["status"] = json!("Error");
            cp["last_error"] = json!(error);
            cp["consecutive_failures"] = json!(n);
            cp["backoff_until"] =
                json!((Utc::now() + Duration::seconds(retry.clamp(60, 86400))).to_rfc3339());
        }
    }
    db.save_checkpoint(source, cp).await?;
    db.release(source).await?;
    result
}
pub async fn commit(
    db: &Database,
    source: &str,
    batch: Batch,
    cp: &Value,
) -> Result<usize, String> {
    db.apply(source, batch, cp.clone()).await
}
pub async fn osv_analyze(purls: &[String]) -> Result<Vec<Value>, String> {
    if purls.len() > 1000 || purls.iter().any(|p| p.len() > 2048) {
        return Err("OSV package query exceeds input budget".into());
    }
    tokio::time::timeout(Timeout::from_secs(45), osv_analyze_bounded(purls))
        .await
        .map_err(|_| "OSV analysis exceeded 45 second budget".to_string())?
}
async fn osv_analyze_bounded(purls: &[String]) -> Result<Vec<Value>, String> {
    let f = Fetcher::new()?;
    let mut findings = Vec::new();
    let mut details = std::collections::HashMap::<String, (Value, Value)>::new();
    let mut total_bytes = 0usize;
    let mut output_bytes = 0usize;
    let mut total_pages = 0;
    for chunk in purls.chunks(100) {
        let queries: Vec<_> = chunk
            .iter()
            .map(|p| json!({"package":{"purl":p}}))
            .collect();
        let result = f
            .post(
                "https://api.osv.dev/v1/querybatch",
                &json!({"queries":queries}),
            )
            .await?;
        let results = result["results"].as_array().ok_or("Invalid OSV response")?;
        if results.len() != chunk.len() {
            return Err("OSV response count mismatch".into());
        }
        for (purl, group) in chunk.iter().zip(results) {
            let mut page = group.clone();
            let mut tokens = std::collections::HashSet::new();
            let mut ids = std::collections::HashSet::new();
            loop {
                for v in page["vulns"].as_array().unwrap_or(&vec![]) {
                    let Some(id) = v["id"].as_str() else { continue };
                    if id.is_empty()
                        || id.len() > 128
                        || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                    {
                        return Err("Invalid OSV advisory identifier".into());
                    }
                    if !ids.insert(id.to_string()) {
                        continue;
                    }
                    if findings.len() >= 500 {
                        return Err("OSV analysis exceeds 500 findings; split the manifest".into());
                    }
                    if !details.contains_key(id) {
                        let doc = f
                            .get_bounded(
                                &format!("https://api.osv.dev/v1/vulns/{id}"),
                                &[],
                                1024 * 1024,
                            )
                            .await?;
                        total_bytes += doc.bytes.len();
                        if total_bytes > 8 * 1024 * 1024 {
                            return Err("OSV details exceed 8 MiB; split the manifest".into());
                        }
                        details.insert(id.to_string(), (doc.json()?, doc.provenance("OSV")));
                    }
                    let (advisory, provenance) = details.get(id).unwrap();
                    findings.push(json!({"purl":purl,"advisory":advisory,"provenance":provenance}));
                    output_bytes += serde_json::to_vec(findings.last().unwrap())
                        .map_err(|e| e.to_string())?
                        .len();
                    if output_bytes > 8 * 1024 * 1024 {
                        return Err("OSV output exceeds analysis byte budget".into());
                    }
                }
                let Some(token) = page["next_page_token"].as_str().filter(|t| !t.is_empty()) else {
                    break;
                };
                check_page_token(&mut tokens, token, &mut total_pages)?;
                let response = f
                    .post(
                        "https://api.osv.dev/v1/querybatch",
                        &json!({"queries":[{"package":{"purl":purl},"page_token":token}]}),
                    )
                    .await?;
                if response["results"].as_array().is_none_or(|a| a.len() != 1) {
                    return Err("OSV pagination response mismatch".into());
                }
                page = response["results"][0].clone();
            }
        }
    }
    Ok(findings)
}
fn check_page_token(
    seen: &mut std::collections::HashSet<String>,
    token: &str,
    total: &mut usize,
) -> Result<(), String> {
    if token.len() > 4096 || seen.len() >= 5 || *total >= 50 || !seen.insert(token.to_string()) {
        return Err("OSV pagination exceeded its budget or repeated a token".into());
    }
    *total += 1;
    Ok(())
}
#[cfg(test)]
mod analysis_budget_tests {
    use super::*;
    #[test]
    fn repeated_tokens_and_page_count_fail_closed() {
        let mut seen = std::collections::HashSet::new();
        let mut total = 0;
        assert!(check_page_token(&mut seen, "one", &mut total).is_ok());
        assert!(check_page_token(&mut seen, "one", &mut total).is_err());
        total = 50;
        assert!(check_page_token(&mut seen, "two", &mut total).is_err());
    }
}

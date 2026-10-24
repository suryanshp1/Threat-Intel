//! Fixed-publisher collectors. Reference targets are never fetched or executed.
use crate::{commit, Document, Fetcher};
use chrono::{DateTime, Duration, Utc};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use vi_db::{Batch, Database};

const CVE_SOURCE: &str = "CVE List V5";
const DELTA: &str =
    "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json";
const DEBIAN: &str = "https://security-tracker.debian.org/tracker/data/json";
const POC_SOURCE: &str = "Trickest PoC references";
const PAGE: usize = 50;

fn timestamp(raw: &str) -> Result<DateTime<Utc>, String> {
    DateTime::parse_from_rfc3339(raw)
        .map(|t| t.with_timezone(&Utc))
        .map_err(|_| "Invalid upstream/checkpoint timestamp".into())
}
fn cve(raw: &str) -> Result<&str, String> {
    if raw.len() <= 32 && vi_core::valid_cve(raw) {
        Ok(raw)
    } else {
        Err("Invalid upstream CVE identifier".into())
    }
}
fn text<'a>(v: &'a Value, field: &str) -> Result<&'a str, String> {
    v[field]
        .as_str()
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| format!("Upstream schema missing {field}"))
}
fn patch(doc: &Document, source: &str, id: &str) -> Value {
    json!({"id":id,"sources":[source],"provenance":[doc.provenance(source)],"ingested_at":doc.fetched_at})
}
fn cve_url(id: &str) -> Result<String, String> {
    cve(id)?;
    let parts: Vec<_> = id.split('-').collect();
    let number = parts[2];
    Ok(format!(
        "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{}/{}xxx/{id}.json",
        parts[1],
        &number[..number.len() - 3]
    ))
}

/// Freeze one incremental window. Pending IDs live in the transactional checkpoint,
/// so a later upstream index rotation cannot discard partially processed work.
fn delta_window(doc: &Document, watermark: Option<&str>) -> Result<(Vec<String>, String), String> {
    let data = doc.json()?;
    let rows = data
        .as_array()
        .filter(|a| !a.is_empty())
        .ok_or("Empty CVE delta log")?;
    let mut times = Vec::with_capacity(rows.len());
    for row in rows {
        times.push(timestamp(text(row, "fetchTime")?)?);
    }
    let oldest = *times.iter().min().unwrap();
    let newest = *times.iter().max().unwrap();
    let start = match watermark {
        Some(raw) => {
            let start = timestamp(raw)?;
            if start < oldest {
                return Err("CVE incremental coverage gap: checkpoint predates retained delta history; restore/backfill before resetting this source".into());
            }
            if start > newest {
                return Err("CVE delta log is older than the checkpoint".into());
            }
            start
        }
        None => (newest - Duration::days(1)).max(oldest),
    };
    let mut ids = BTreeSet::new();
    for (row, time) in rows.iter().zip(times) {
        if time < start || (watermark.is_some() && time == start) {
            continue;
        }
        // Ignore upstream links: construct every record URL from validated IDs.
        for kind in ["new", "updated"] {
            for item in row[kind]
                .as_array()
                .ok_or("Invalid CVE delta change list")?
            {
                ids.insert(cve(text(item, "cveId")?)?.to_string());
                if ids.len() > 20_000 {
                    return Err("CVE delta window exceeds 20,000 records".into());
                }
            }
        }
    }
    Ok((ids.into_iter().collect(), newest.to_rfc3339()))
}

pub fn parse_cve(doc: &Document, expected: &str) -> Result<Batch, String> {
    let data = doc.json()?;
    let meta = &data["cveMetadata"];
    if data["dataType"] != "CVE_RECORD" || text(meta, "cveId")? != cve(expected)? {
        return Err("CVE record identity/schema mismatch".into());
    }
    let state = text(meta, "state")?;
    if !["PUBLISHED", "REJECTED"].contains(&state) {
        return Err("Unsupported CVE record state".into());
    }
    let cna = &data["containers"]["cna"];
    if !cna.is_object() {
        return Err("CVE record missing CNA container".into());
    }
    let mut p = patch(doc, CVE_SOURCE, expected);
    p["source_assertions"] = json!([{"source":CVE_SOURCE,"status":state,
        "metadata":meta,"cna":cna,"adp":data["containers"]["adp"],
        "provenance":doc.provenance(CVE_SOURCE)}]);
    if state == "PUBLISHED" {
        let description = cna["descriptions"]
            .as_array()
            .and_then(|a| a.iter().find(|d| d["lang"] == "en"))
            .and_then(|d| d["value"].as_str())
            .unwrap_or("");
        if !description.is_empty() {
            p["description"] = json!(description);
        }
        p["title"] = json!(cna["title"].as_str().unwrap_or(expected));
        if let Some(published) = meta["datePublished"].as_str() {
            p["published"] = json!(published);
        }
        for metric in cna["metrics"].as_array().unwrap_or(&vec![]) {
            let mut found = false;
            for version in ["cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"] {
                if let Some(score) = metric[version]["baseScore"].as_f64() {
                    if !(0.0..=10.0).contains(&score) {
                        return Err("Invalid CNA CVSS score".into());
                    }
                    p["cvss"] = json!(score);
                    p["cvss_known"] = json!(true);
                    p["cvss_vector"] = metric[version]["vectorString"].clone();
                    found = true;
                    break;
                }
            }
            if found {
                break;
            }
        }
        // Preserve all affected product/version structures in the CNA assertion;
        // never flatten multiple products into one global fixed version or PURL.
    }
    let mut b = Batch::default();
    b.vulnerabilities.push(p);
    Ok(b)
}

pub fn parse_debian(doc: &Document) -> Result<Batch, String> {
    let data = doc.json()?;
    let packages = data
        .as_object()
        .filter(|p| !p.is_empty())
        .ok_or("Empty Debian tracker")?;
    let source = "Debian Security Tracker";
    let mut records = BTreeMap::<String, Value>::new();
    let mut assertions = 0;
    for (package, entries) in packages {
        for (id, advisory) in entries
            .as_object()
            .ok_or("Invalid Debian package advisories")?
        {
            // The tracker also contains TEMP identifiers, which are not CVEs.
            if id.starts_with("TEMP-") {
                continue;
            }
            cve(id)?;
            for (release, row) in advisory["releases"]
                .as_object()
                .ok_or("Missing Debian releases")?
            {
                assertions += 1;
                if assertions > 500_000 {
                    return Err("Debian tracker exceeds assertion budget".into());
                }
                let status = text(row, "status")?;
                let fixed = row["fixed_version"].as_str().unwrap_or("");
                let released = status == "resolved" && !fixed.is_empty() && fixed != "0";
                let p = records.entry(id.clone()).or_insert_with(|| {
                    let mut p = patch(doc, source, id);
                    p["remediation_evidence"] = json!([]);
                    p
                });
                p["remediation_evidence"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!({
                    "source":source,"distribution":"Debian","release":release,"product":package,
                    "status":status,"fixed_versions":if released {vec![fixed]} else {vec![]},
                    "fixed_version_raw":row["fixed_version"],"urgency":row["urgency"],
                    "repositories":row["repositories"],"description":advisory["description"],
                    "release_status":if released {"released"} else {"not_reported"},
                    "advisory_url":format!("https://security-tracker.debian.org/tracker/{id}"),
                    "provenance":doc.provenance(source)}));
                if released {
                    p["patch_available"] = json!(true);
                    p["patch_status"] = json!("available");
                }
            }
        }
    }
    if assertions == 0 {
        return Err("Debian tracker contains no CVE release assertions".into());
    }
    Ok(Batch {
        vulnerabilities: records.into_values().collect(),
        ..Default::default()
    })
}

pub fn parse_ubuntu(doc: &Document) -> Result<Batch, String> {
    let data = doc.json()?;
    let notices = data["notices"].as_array().ok_or("Missing Ubuntu notices")?;
    if notices.len() > 20 {
        return Err("Ubuntu page exceeds 20 notices".into());
    }
    let mut b = Batch::default();
    let source = "Ubuntu USN";
    let usn = regex::Regex::new(r"^USN-[0-9]+-[0-9]+$").unwrap();
    let mut assertions = 0;
    for notice in notices {
        let id = text(notice, "id")?;
        if !usn.is_match(id) {
            return Err("Invalid Ubuntu notice ID".into());
        }
        if notice["is_hidden"] == true {
            continue;
        }
        let ids = notice["cves_ids"]
            .as_array()
            .ok_or("Missing explicit Ubuntu CVE mappings")?;
        let packages = notice["release_packages"]
            .as_object()
            .ok_or("Missing Ubuntu release packages")?;
        for id in ids {
            let id = cve(id.as_str().ok_or("Invalid Ubuntu CVE mapping")?)?;
            let mut p = patch(doc, source, id);
            let mut evidence = vec![];
            for (release, rows) in packages {
                for package in rows.as_array().ok_or("Invalid Ubuntu package list")? {
                    // Source package versions avoid presenting every binary as a
                    // CVE-specific match. Preserve notice-level association explicitly.
                    if package["is_source"] != true {
                        continue;
                    }
                    let name = text(package, "name")?;
                    let version = text(package, "version")?;
                    assertions += 1;
                    if assertions > 50_000 {
                        return Err("Ubuntu page exceeds assertion budget".into());
                    }
                    evidence.push(json!({"source":source,"distribution":"Ubuntu","release":release,
                        "product":name,"fixed_versions":[version],"release_status":"released",
                        "mapping_scope":"notice","notice_id":notice["id"],"title":notice["title"],
                        "published_at":notice["published"],"instructions":notice["instructions"],
                        "advisory_url":format!("https://ubuntu.com/security/notices/{}",notice["id"].as_str().unwrap()),
                        "provenance":doc.provenance(source)}));
                }
            }
            if !evidence.is_empty() {
                // A multi-CVE USN lists fixes at notice scope; it does not prove
                // that every listed package fixes each CVE. Do not set global patch availability.
                p["remediation_evidence"] = json!(evidence);
                b.vulnerabilities.push(p);
            }
        }
    }
    Ok(b)
}

pub fn parse_poc(doc: &Document, id: &str) -> Result<Batch, String> {
    cve(id)?;
    let markdown = std::str::from_utf8(&doc.bytes).map_err(|_| "Invalid PoC index UTF-8")?;
    if !markdown
        .lines()
        .next()
        .is_some_and(|l| l.starts_with(&format!("### [{id}]")))
    {
        return Err("PoC index identity/schema mismatch".into());
    }
    let mut in_github = false;
    let mut saw_poc = false;
    let mut links = BTreeSet::new();
    for line in markdown.lines() {
        let line = line.trim();
        if line == "### POC" {
            saw_poc = true;
        }
        if line.starts_with('#') {
            in_github = saw_poc && line == "#### Github";
        }
        if !in_github {
            continue;
        }
        if let Some(raw) = line.strip_prefix("- ") {
            let url = url::Url::parse(raw).map_err(|_| "Invalid PoC reference URL")?;
            if url.scheme() != "https"
                || url.host_str() != Some("github.com")
                || !url.username().is_empty()
                || url.password().is_some()
                || url.port().is_some()
            {
                return Err("Unexpected PoC reference host".into());
            }
            links.insert(url.to_string());
            if links.len() > 500 {
                return Err("PoC index exceeds 500 links per CVE".into());
            }
        }
    }
    if !saw_poc {
        return Err("PoC index missing POC section".into());
    }
    let mut p = patch(doc, POC_SOURCE, id);
    p["poc_references"]=json!(links.into_iter().map(|url|json!({"source":POC_SOURCE,"url":url,
        "verification":"unverified","kind":"community_reference","provenance":doc.provenance(POC_SOURCE)})).collect::<Vec<_>>());
    // Index matches include research and detection projects, not just working exploits.
    // They must not set exploit_available, weaponized, seen_wild or is_zeroday.
    Ok(Batch {
        vulnerabilities: vec![p],
        ..Default::default()
    })
}

pub async fn ingest(
    db: &Database,
    f: &Fetcher,
    source: &str,
    cp: &mut Value,
) -> Result<usize, String> {
    // A run cannot outlive the worker lease. Completed pages have already committed.
    tokio::time::timeout(std::time::Duration::from_secs(300), run(db, f, source, cp))
        .await
        .map_err(|_| {
            "Source exceeded five-minute run budget; completed pages retained".to_string()
        })?
}
async fn run(db: &Database, f: &Fetcher, source: &str, cp: &mut Value) -> Result<usize, String> {
    let mut count = 0;
    match source {
        CVE_SOURCE => {
            if cp["pending"].as_array().is_none_or(|p| p.is_empty()) {
                let doc = f.get_bounded(DELTA, &[], 32 * 1024 * 1024).await?;
                let (ids, end) = delta_window(&doc, cp["watermark"].as_str())?;
                let mut next = cp.clone();
                next["pending"] = json!(ids);
                next["window_end"] = json!(end);
                next["coverage"]=json!("Rolling delta history; initial window is the latest 24 hours, not a historical backfill");
                commit(db, source, Batch::default(), &next).await?;
                *cp = next;
            }
            for _ in 0..PAGE {
                let Some(id) = cp["pending"]
                    .as_array()
                    .and_then(|a| a.first())
                    .and_then(Value::as_str)
                    .map(str::to_string)
                else {
                    break;
                };
                let doc = f.get_bounded(&cve_url(&id)?, &[], 1024 * 1024).await?;
                let b = parse_cve(&doc, &id)?;
                let mut next = cp.clone();
                next["pending"]
                    .as_array_mut()
                    .ok_or("Invalid CVE pending checkpoint")?
                    .remove(0);
                if next["pending"].as_array().unwrap().is_empty() {
                    next["watermark"] = next["window_end"].clone();
                }
                count += commit(db, source, b, &next).await?;
                *cp = next;
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            }
            if cp["pending"].as_array().is_some_and(|a| a.is_empty())
                && cp["watermark"] != cp["window_end"]
            {
                let mut next = cp.clone();
                next["watermark"] = next["window_end"].clone();
                commit(db, source, Batch::default(), &next).await?;
                *cp = next;
            }
        }
        "Debian Security Tracker" => {
            let doc = f.get_bounded(DEBIAN, &[], 128 * 1024 * 1024).await?;
            let b = parse_debian(&doc)?;
            let after = cp["last_cursor"].as_str().unwrap_or("").to_string();
            let mut records = b
                .vulnerabilities
                .into_iter()
                .filter(|p| p["id"].as_str().is_some_and(|id| id > after.as_str()))
                .peekable();
            // A full catalog may exceed a run's deadline. Commit bounded pages
            // so retries resume instead of rolling back an entire day's import.
            while records.peek().is_some() {
                let page: Vec<_> = records.by_ref().take(250).collect();
                let mut next = cp.clone();
                next["last_cursor"] = page.last().unwrap()["id"].clone();
                next["coverage"] = json!("Publisher JSON scanned in 250-CVE committed pages; partial runs resume by ID, changed earlier records refresh on the next cycle");
                count += commit(
                    db,
                    source,
                    Batch {
                        vulnerabilities: page,
                        ..Default::default()
                    },
                    &next,
                )
                .await?;
                *cp = next;
            }
            let mut next = cp.clone();
            next["sha256"] = json!(doc.sha256);
            next["last_cursor"] = json!("");
            commit(db, source, Batch::default(), &next).await?;
            *cp = next;
        }
        "Ubuntu USN" => {
            // Refresh the newest page every run, and advance one historical page.
            // The head refresh keeps current notices fresh during a long backfill.
            let offset = cp["offset"].as_u64().unwrap_or(0);
            if offset > 100_000 {
                return Err("Ubuntu offset exceeds scan budget".into());
            }
            let offsets = if offset == 0 {
                vec![0]
            } else {
                vec![0, offset]
            };
            let mut combined = Batch::default();
            let mut next = cp.clone();
            for page_offset in offsets {
                let url = format!(
                    "https://ubuntu.com/security/notices.json?limit=20&offset={page_offset}"
                );
                let doc = f.get_bounded(&url, &[], 16 * 1024 * 1024).await?;
                let data = doc.json()?;
                combined
                    .vulnerabilities
                    .extend(parse_ubuntu(&doc)?.vulnerabilities);
                let total = data["total_results"]
                    .as_u64()
                    .ok_or("Missing Ubuntu total_results")?;
                if data["offset"].as_u64() != Some(page_offset)
                    || data["limit"].as_u64() != Some(20)
                {
                    return Err("Ubuntu pagination mismatch".into());
                }
                let len = data["notices"].as_array().unwrap().len() as u64;
                if len == 0 && page_offset < total {
                    return Err("Unexpected empty Ubuntu page".into());
                }
                if page_offset == offset {
                    next["offset"] = json!(if offset + len >= total {
                        0
                    } else {
                        offset + len
                    });
                }
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
            next["coverage"] = json!("Newest 20 notices refreshed hourly plus one 20-notice historical page; fixes retain notice-level scope");
            count = commit(db, source, combined, &next).await?;
            *cp = next;
        }
        POC_SOURCE => {
            let after = cp["last_cursor"].as_str().unwrap_or("");
            let ids = db.ids_after(after, PAGE).await?;
            for id in &ids {
                cve(id)?;
                let year = id.split('-').nth(1).unwrap();
                let url =
                    format!("https://raw.githubusercontent.com/trickest/cve/main/{year}/{id}.md");
                let b = match f.get_bounded(&url, &[], 1024 * 1024).await {
                    Ok(doc) => parse_poc(&doc, id)?,
                    Err(e) if e.starts_with("HTTP 404 ") => Batch::default(),
                    Err(e) => return Err(e),
                };
                let mut next = cp.clone();
                next["last_cursor"] = json!(id);
                next["coverage"]=json!("Catalog-scoped rolling scan, 50 CVEs per run; links are unverified community references");
                count += commit(db, source, b, &next).await?;
                *cp = next;
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            }
            if ids.len() < PAGE {
                let mut next = cp.clone();
                next["last_cursor"] = json!("");
                commit(db, source, Batch::default(), &next).await?;
                *cp = next;
            }
        }
        _ => return Err("Unsupported expansion source".into()),
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    fn document(url: &str, data: Value) -> Document {
        let bytes = serde_json::to_vec(&data).unwrap();
        Document {
            sha256: format!("{:x}", Sha256::digest(&bytes)),
            bytes,
            url: url.into(),
            fetched_at: "2026-10-21T12:00:00Z".into(),
        }
    }
    fn record() -> Value {
        json!({"dataType":"CVE_RECORD","cveMetadata":{"cveId":"CVE-2099-1000","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z"},
            "containers":{"cna":{"title":"Publisher title","descriptions":[{"lang":"en","value":"Publisher description"}],
                "affected":[{"vendor":"Example","product":"One","versions":[{"version":"1.0","status":"affected"}]},
                    {"vendor":"Example","product":"Two","defaultStatus":"unknown"}],
                "metrics":[{"cvssV3_1":{"baseScore":7.2,"vectorString":"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"}}]}}})
    }
    #[test]
    fn cna_keeps_competing_assertions_and_product_scope() {
        let doc = document("https://example.test/cve", record());
        let p = &parse_cve(&doc, "CVE-2099-1000").unwrap().vulnerabilities[0];
        let old = vi_core::Vulnerability {
            id: "CVE-2099-1000".into(),
            description: "NVD description".into(),
            cvss: 9.8,
            cvss_known: true,
            ..Default::default()
        };
        let merged = vi_core::merge_record(Some(&old), p).unwrap();
        assert_eq!(merged.description, "NVD description");
        assert_eq!(merged.cvss, 9.8);
        assert_eq!(
            merged.source_assertions[0]["cna"]["metrics"][0]["cvssV3_1"]["baseScore"],
            7.2
        );
        assert_eq!(
            merged.source_assertions[0]["cna"]["affected"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert!(merged.fixed_version.is_empty());
        assert!(merged.purl.is_empty());
        let fresh = vi_core::merge_record(None, p).unwrap();
        assert_eq!(fresh.cvss, 7.2);
        let again = vi_core::merge_record(Some(&merged), p).unwrap();
        assert_eq!(again.source_assertions.len(), 1);
    }
    #[test]
    fn identity_mismatch_and_unsupported_state_fail_closed() {
        let mut v = record();
        assert!(parse_cve(
            &document("https://example.test/cve", v.clone()),
            "CVE-2099-1001"
        )
        .is_err());
        v["cveMetadata"]["state"] = json!("RESERVED");
        assert!(parse_cve(
            &document("https://example.test/cve", v.clone()),
            "CVE-2099-1000"
        )
        .is_err());
        v["cveMetadata"]["state"] = json!("REJECTED");
        let b = parse_cve(&document("https://example.test/cve", v), "CVE-2099-1000").unwrap();
        assert_eq!(
            b.vulnerabilities[0]["source_assertions"][0]["status"],
            "REJECTED"
        );
        assert!(b.vulnerabilities[0].get("cvss").is_none());
    }
    #[test]
    fn delta_orders_deduplicates_and_detects_gaps_without_trusting_links() {
        let doc = document(
            DELTA,
            json!([
            {"fetchTime":"2026-10-21T02:00:00Z","new":[{"cveId":"CVE-2099-1001","githubLink":"https://evil.test/a"}],"updated":[{"cveId":"CVE-2099-1000"}]},
            {"fetchTime":"2026-10-21T01:00:00Z","new":[{"cveId":"CVE-2099-1000"}],"updated":[]}]),
        );
        assert_eq!(
            delta_window(&doc, None).unwrap().0,
            vec!["CVE-2099-1000", "CVE-2099-1001"]
        );
        assert!(delta_window(&doc, Some("2026-10-20T00:00:00Z")).is_err());
        assert!(delta_window(&doc, Some("2026-10-22T00:00:00Z")).is_err());
        assert!(delta_window(&doc, Some("2026-10-21T02:00:00Z"))
            .unwrap()
            .0
            .is_empty());
        assert!(cve_url("CVE-2099-1000")
            .unwrap()
            .ends_with("/2099/1xxx/CVE-2099-1000.json"));
        assert!(cve_url("CVE-2099-1000/../../secret").is_err());
    }
    #[test]
    fn debian_zero_is_not_a_patch_and_versions_are_never_normalized() {
        let doc = document(
            DEBIAN,
            json!({"test":{"CVE-2099-1000":{"description":"Publisher text","releases":{
            "bookworm":{"status":"resolved","fixed_version":"0"},
            "trixie":{"status":"resolved","fixed_version":"1:2.0~rc1-3+deb13u1"},
            "sid":{"status":"open","fixed_version":""}}}}}),
        );
        let b = parse_debian(&doc).unwrap();
        let p = &b.vulnerabilities[0];
        let evidence = p["remediation_evidence"].as_array().unwrap();
        assert_eq!(evidence[0]["fixed_versions"], json!([]));
        assert_eq!(
            evidence[2]["fixed_versions"],
            json!(["1:2.0~rc1-3+deb13u1"])
        );
        assert!(p.get("fixed_version").is_none());
        assert!(p.get("purl").is_none());
        assert_eq!(p["patch_available"], true);
        assert!(parse_debian(&document(DEBIAN, json!({}))).is_err());
    }
    #[test]
    fn ubuntu_maps_explicit_cves_only_and_keeps_notice_scope() {
        let doc = document(
            "https://ubuntu.com/security/notices.json",
            json!({"notices":[{
            "id":"USN-9999-1","cves_ids":["CVE-2099-1000","CVE-2099-1001"],"published":"2099-01-01T00:00:00",
            "description":"CVE-2099-9999 is only prose", "release_packages":{"noble":[
                {"name":"source","version":"1:2.0-0ubuntu1","is_source":true},
                {"name":"binary","version":"1:2.0-0ubuntu1","is_source":false}]}}]}),
        );
        let b = parse_ubuntu(&doc).unwrap();
        assert_eq!(b.vulnerabilities.len(), 2);
        for p in b.vulnerabilities {
            assert!(p.get("patch_available").is_none());
            assert_eq!(p["remediation_evidence"][0]["mapping_scope"], "notice");
            assert_eq!(p["remediation_evidence"].as_array().unwrap().len(), 1);
        }
    }
    #[test]
    fn poc_references_never_assert_working_exploits_or_follow_markdown() {
        let mut doc = document("https://example.test/poc", Value::Null);
        doc.bytes=b"### [CVE-2099-1000](https://example.test)\n### POC\n#### Reference\n- https://example.test/research\n#### Github\n- https://github.com/example/research\n- https://github.com/example/research\n".to_vec();
        let b = parse_poc(&doc, "CVE-2099-1000").unwrap();
        let p = &b.vulnerabilities[0];
        assert_eq!(p["poc_references"].as_array().unwrap().len(), 1);
        assert_eq!(p["poc_references"][0]["verification"], "unverified");
        assert!(p.get("exploit_available").is_none());
        assert!(p.get("seen_wild").is_none());
        doc.bytes
            .extend_from_slice(b"- https://github.com.evil.test/exploit\n");
        assert!(parse_poc(&doc, "CVE-2099-1000").is_err());
    }
    #[tokio::test]
    #[ignore = "Read-only network parser check; no database imports"]
    async fn official_expansion_sources_smoke() {
        let f = Fetcher::new().unwrap();
        let delta = f.get_bounded(DELTA, &[], 32 * 1024 * 1024).await.unwrap();
        let (ids, _) = delta_window(&delta, None).unwrap();
        assert!(!ids.is_empty());
        let doc = f
            .get_bounded(&cve_url(&ids[0]).unwrap(), &[], 1024 * 1024)
            .await
            .unwrap();
        assert_eq!(parse_cve(&doc, &ids[0]).unwrap().vulnerabilities.len(), 1);
        let debian = f.get_bounded(DEBIAN, &[], 128 * 1024 * 1024).await.unwrap();
        assert!(!parse_debian(&debian).unwrap().vulnerabilities.is_empty());
        let ubuntu = f
            .get_bounded(
                "https://ubuntu.com/security/notices.json?limit=20&offset=0",
                &[],
                16 * 1024 * 1024,
            )
            .await
            .unwrap();
        assert!(!parse_ubuntu(&ubuntu).unwrap().vulnerabilities.is_empty());
        let poc = f
            .get_bounded(
                "https://raw.githubusercontent.com/trickest/cve/main/2024/CVE-2024-3094.md",
                &[],
                1024 * 1024,
            )
            .await
            .unwrap();
        assert!(
            !parse_poc(&poc, "CVE-2024-3094").unwrap().vulnerabilities[0]["poc_references"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }
}

//! Fixed-scope vendor advisory scrapers. Downloaded HTML is parsed, never executed.
use crate::{commit, Document, Fetcher};
use chrono::NaiveDate;
use scraper::{ElementRef, Html, Selector};
use serde_json::{json, Value};
use std::time::Duration;
use vi_db::{Batch, Database};

const MAX_DOCUMENT: usize = 8 * 1024 * 1024;
const MAX_RECORDS: usize = 5000;
const HTTPD: &str = "https://httpd.apache.org/security/vulnerabilities_24.html";
const OPENSSL: &str = "https://openssl-library.org/news/vulnerabilities/";
const CURL: &str = "https://curl.se/docs/vuln.json";

fn selector(css: &str) -> Selector {
    Selector::parse(css).expect("static selector")
}
fn text(element: ElementRef<'_>) -> String {
    element
        .descendants()
        .filter_map(|n| {
            let value = n.value().as_text()?;
            if n.ancestors()
                .filter_map(ElementRef::wrap)
                .any(|e| matches!(e.value().name(), "script" | "style" | "noscript"))
            {
                return None;
            }
            Some(value.to_string())
        })
        .collect::<Vec<_>>()
        .join(" ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}
fn next(element: ElementRef<'_>) -> Option<ElementRef<'_>> {
    element.next_siblings().find_map(ElementRef::wrap)
}
fn version(raw: &str) -> bool {
    !raw.is_empty()
        && raw.len() <= 40
        && raw.starts_with(|c: char| c.is_ascii_digit())
        && raw.contains('.')
        && raw
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
}
fn date(raw: &str) -> Option<String> {
    ["%Y-%m-%d", "%e %B %Y"]
        .iter()
        .find_map(|f| NaiveDate::parse_from_str(raw.trim(), f).ok())
        .map(|d| d.to_string())
}
fn html(doc: &Document) -> Result<Html, String> {
    if doc.bytes.len() > MAX_DOCUMENT {
        return Err("Advisory HTML exceeds 8 MiB".into());
    }
    Ok(Html::parse_document(
        std::str::from_utf8(&doc.bytes).map_err(|_| "Advisory HTML is not UTF-8")?,
    ))
}
fn safe_reference(base: &str, href: &str) -> Option<String> {
    let url = url::Url::parse(base).ok()?.join(href).ok()?;
    (matches!(url.scheme(), "https" | "http")
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none())
    .then(|| url.to_string())
}
fn reference(doc: &Document, source: &str, url: &str) -> Value {
    json!({"url":url,"source":source,"provenance":doc.provenance(source)})
}
fn finish(batch: Batch) -> Result<Batch, String> {
    if batch.vulnerabilities.is_empty() || batch.vulnerabilities.len() > MAX_RECORDS {
        return Err(
            "Vendor advisory record count outside bounds; possible page schema change".into(),
        );
    }
    Ok(batch)
}
fn add(
    batch: &mut Batch,
    doc: &Document,
    source: &str,
    id: &str,
    title: &str,
    description: &str,
    mut evidence: Value,
    links: Vec<Value>,
) -> Result<(), String> {
    if !vi_core::valid_cve(id)
        || title.trim().is_empty()
        || title.len() > 1024
        || description.len() > 65536
        || batch.vulnerabilities.len() >= MAX_RECORDS
    {
        return Err("Invalid or oversized vendor advisory".into());
    }
    evidence["source"] = json!(source);
    evidence["title"] = json!(title);
    evidence["description"] = json!(description);
    evidence["provenance"] = doc.provenance(source);
    let url = evidence["advisory_url"].as_str().unwrap_or(&doc.url);
    let mut fields = json!({"id":id,"title":title,"description":description,
        "product":evidence["product"],"sources":[source],"provenance":[doc.provenance(source)],"ingested_at":doc.fetched_at,
        "references":[reference(doc,source,url)],"remediation_evidence":[evidence],"patch_links":links});
    if evidence["release_status"] == "released"
        && evidence["fixed_versions"]
            .as_array()
            .is_some_and(|a| !a.is_empty())
    {
        fields["patch_available"] = json!(true);
        fields["patch_status"] = json!("available");
    }
    // Fixed versions remain scoped to the vendor/product/branch in remediation_evidence.
    // No PURLs, CVSS, actor attribution or global fixed_version are inferred from prose.
    batch.vulnerabilities.push(fields);
    Ok(())
}

pub fn parse_httpd(doc: &Document) -> Result<Batch, String> {
    let page = html(doc)?;
    let mut batch = Batch::default();
    for heading in page.select(&selector("#apcontents dl > dt > h3[id]")) {
        let id = heading.value().attr("id").unwrap_or("");
        if !vi_core::valid_cve(id) {
            continue;
        }
        let dt = heading
            .parent()
            .and_then(ElementRef::wrap)
            .ok_or("HTTPD dt missing")?;
        let body = next(dt)
            .filter(|e| e.value().name() == "dd")
            .ok_or("HTTPD advisory body missing")?;
        let list = dt
            .parent()
            .and_then(ElementRef::wrap)
            .ok_or("HTTPD list missing")?;
        let release = list
            .prev_siblings()
            .filter_map(ElementRef::wrap)
            .find(|e| e.value().name() == "h1")
            .ok_or("HTTPD release heading missing")?;
        let release_text = text(release);
        let fixed = release_text
            .strip_prefix("Fixed in Apache HTTP Server ")
            .filter(|s| version(s));
        let mut affected = String::new();
        let mut released = None;
        for row in body.select(&selector("table tr")) {
            let cells: Vec<_> = row.select(&selector("td")).collect();
            if cells.len() != 2 {
                continue;
            }
            let label = text(cells[0]);
            if label == "Affects" {
                affected = text(cells[1]);
            }
            if let Some(v) = fixed {
                if label == format!("Update {v} released") && !v.contains("-dev") {
                    released = date(&text(cells[1]));
                }
            }
        }
        let mut evidence = json!({"product":"Apache HTTP Server","branch":"2.4","affected_text":affected,"vendor_severity":text(heading).split(':').next(),
            "advisory_url":format!("{}#{id}",doc.url),"release_status":"unknown","fixed_versions":[]});
        if let Some(v) = fixed {
            evidence["planned_fixed_version"] = json!(v);
        }
        if let (Some(v), Some(d)) = (fixed, released) {
            evidence["fixed_versions"] = json!([v]);
            evidence["released_at"] = json!(d);
            evidence["release_status"] = json!("released");
        }
        let description = body
            .select(&selector("p"))
            .map(text)
            .collect::<Vec<_>>()
            .join("\n");
        add(
            &mut batch,
            doc,
            "Apache HTTP Server",
            id,
            &text(heading),
            &description,
            evidence,
            vec![],
        )?;
    }
    finish(batch)
}

fn tomcat_id(p: ElementRef<'_>) -> Option<String> {
    p.select(&selector("strong")).next()?;
    // A prior CVE can appear inside the title's strong element; the primary CVE link is outside it.
    let ids: Vec<_> = p
        .select(&selector("a"))
        .filter(|a| {
            !a.ancestors()
                .filter_map(ElementRef::wrap)
                .any(|e| e.value().name() == "strong")
        })
        .map(text)
        .filter(|id| vi_core::valid_cve(id))
        .collect();
    (ids.len() == 1).then(|| ids[0].clone())
}
pub fn parse_tomcat(doc: &Document, expected_major: &str) -> Result<Batch, String> {
    let page = html(doc)?;
    let mut batch = Batch::default();
    for section in page.select(&selector("#content > h3[id^='Fixed_in_Apache_Tomcat_']")) {
        let section_id = section.value().attr("id").unwrap_or("");
        let fixed = section_id
            .strip_prefix("Fixed_in_Apache_Tomcat_")
            .filter(|s| version(s))
            .ok_or("Tomcat release version missing")?;
        if !fixed.starts_with(&format!("{expected_major}.")) {
            return Err("Tomcat release belongs to an unexpected major version".into());
        }
        let branch = fixed.split('.').take(2).collect::<Vec<_>>().join(".");
        let body = next(section)
            .filter(|e| e.value().name() == "div")
            .ok_or("Tomcat release body missing")?;
        let label = text(section).to_lowercase();
        let release_date = section
            .select(&selector("span"))
            .next()
            .and_then(|e| date(&text(e)));
        let released = !label.contains("not yet released")
            && !fixed.contains("-dev")
            && release_date.is_some();
        let children: Vec<_> = body.children().filter_map(ElementRef::wrap).collect();
        for (index, p) in children.iter().copied().enumerate() {
            let Some(id) = tomcat_id(p) else { continue };
            let group: Vec<_> = children[index + 1..]
                .iter()
                .copied()
                .take_while(|e| tomcat_id(*e).is_none())
                .collect();
            let description = group
                .iter()
                .copied()
                .map(text)
                .collect::<Vec<_>>()
                .join("\n");
            let affected = group
                .iter()
                .copied()
                .map(text)
                .find(|s| s.starts_with("Affects:"))
                .unwrap_or_default();
            let url = format!("{}#{section_id}", doc.url);
            let mut evidence = json!({"product":"Apache Tomcat","branch":branch,"advisory_url":url,
                "affected_text":affected,"vendor_severity":text(p).split(':').next(),"planned_fixed_version":fixed,"release_status":"unreleased","fixed_versions":[]});
            let mut links = Vec::new();
            if released {
                evidence["fixed_versions"] = json!([fixed]);
                evidence["release_status"] = json!("released");
                evidence["released_at"] = json!(release_date);
                for element in &group {
                    // Commit URLs are retained as evidence, and are never fetched.
                    for a in element.select(&selector("a[href]")) {
                        if let Some(url) =
                            safe_reference(&doc.url, a.value().attr("href").unwrap_or(""))
                        {
                            if url.starts_with("https://github.com/apache/tomcat/commit/") {
                                links.push(reference(doc, "Apache Tomcat", &url));
                            }
                        }
                    }
                }
            }
            add(
                &mut batch,
                doc,
                "Apache Tomcat",
                &id,
                &text(p),
                &description,
                evidence,
                links,
            )?;
        }
    }
    finish(batch)
}

pub fn parse_openssl(doc: &Document) -> Result<Batch, String> {
    let page = html(doc)?;
    let mut batch = Batch::default();
    for heading in page.select(&selector("h3[id]")) {
        let id = heading.value().attr("id").unwrap_or("");
        if !vi_core::valid_cve(id) {
            continue;
        }
        let wrapper = heading
            .parent()
            .and_then(ElementRef::wrap)
            .ok_or("OpenSSL heading wrapper missing")?;
        let grid = next(wrapper)
            .filter(|e| e.value().name() == "div" && e.value().classes().any(|c| c == "grid"))
            .ok_or("OpenSSL metadata grid missing")?;
        let cells: Vec<_> = grid.children().filter_map(ElementRef::wrap).collect();
        if cells.len() % 2 != 0 {
            return Err("OpenSSL metadata fields unpaired".into());
        }
        let mut name = id.to_string();
        let mut affected = Vec::new();
        let mut fixes = Vec::new();
        let mut links = Vec::new();
        let mut published = None;
        let mut severity = String::new();
        for pair in cells.chunks_exact(2) {
            match text(pair[0]).as_str() {
                "Title" => name = text(pair[1]),
                "Severity" => severity = text(pair[1]),
                "Published at" => published = date(&text(pair[1])),
                "Affected" => {
                    for li in pair[1].select(&selector("li")) {
                        let raw = text(li);
                        // Keep source syntax. Extract only the explicit exclusive upper bound.
                        if let Some((_, fixed)) = raw.split_once(" before ") {
                            if version(fixed) {
                                fixes.push(json!(fixed));
                            }
                        }
                        affected.push(raw);
                    }
                }
                "References" => {
                    for a in pair[1].select(&selector("a[href]")) {
                        if text(a).ends_with("git commit") {
                            if let Some(url) =
                                safe_reference(&doc.url, a.value().attr("href").unwrap_or(""))
                            {
                                links.push(reference(doc, "OpenSSL", &url));
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        if affected.is_empty() {
            return Err("OpenSSL affected ranges missing".into());
        }
        let description = grid
            .next_siblings()
            .filter_map(ElementRef::wrap)
            .take_while(|e| e.value().name() == "p")
            .map(text)
            .collect::<Vec<_>>()
            .join("\n");
        let evidence = json!({"product":"OpenSSL","affected_ranges":affected,"fixed_versions":fixes,
            "advisory_url":format!("{}#{id}",doc.url),"published":published,"vendor_severity":severity,
            "release_status":if fixes.is_empty(){"unknown"}else{"released"}});
        add(
            &mut batch,
            doc,
            "OpenSSL",
            id,
            &name,
            &description,
            evidence,
            links,
        )?;
    }
    finish(batch)
}

pub fn parse_curl(doc: &Document) -> Result<Batch, String> {
    if doc.bytes.len() > MAX_DOCUMENT {
        return Err("curl feed exceeds 8 MiB".into());
    }
    let data = doc.json()?;
    let rows = data.as_array().ok_or("curl advisory array missing")?;
    if rows.len() > MAX_RECORDS {
        return Err("curl advisory count exceeds limit".into());
    }
    let mut batch = Batch::default();
    for row in rows {
        let aliases = row["aliases"].as_array().ok_or("curl aliases missing")?;
        let cves: Vec<_> = aliases
            .iter()
            .filter_map(Value::as_str)
            .filter(|id| vi_core::valid_cve(id))
            .collect();
        if cves.len() != 1 {
            return Err("curl advisory must identify exactly one CVE".into());
        }
        let id = cves[0];
        if row["id"] != format!("CURL-{id}") {
            return Err("curl advisory ID mismatch".into());
        }
        let title = row["summary"].as_str().ok_or("curl summary missing")?;
        let affected = row["affected"]
            .as_array()
            .ok_or("curl affected ranges missing")?;
        let mut fixes = Vec::new();
        let mut links = Vec::new();
        for package in affected {
            for range in package["ranges"].as_array().unwrap_or(&vec![]) {
                for event in range["events"].as_array().unwrap_or(&vec![]) {
                    let Some(fixed) = event["fixed"].as_str() else {
                        continue;
                    };
                    if range["type"] == "SEMVER" && version(fixed) {
                        fixes.push(json!(fixed));
                    }
                    if range["type"] == "GIT"
                        && range["repo"] == "https://github.com/curl/curl.git"
                        && fixed.len() == 40
                        && fixed.bytes().all(|b| b.is_ascii_hexdigit())
                    {
                        links.push(reference(
                            doc,
                            "curl",
                            &format!("https://github.com/curl/curl/commit/{fixed}"),
                        ));
                    }
                }
            }
        }
        let evidence = json!({"product":"curl/libcurl","advisory_url":format!("https://curl.se/docs/{id}.html"),
            "affected":affected,"fixed_versions":fixes,"published":row["published"],"vendor_severity":row["database_specific"]["severity"],
            "release_status":if fixes.is_empty(){"unknown"}else{"released"}});
        add(
            &mut batch,
            doc,
            "curl",
            id,
            title,
            row["details"].as_str().unwrap_or(""),
            evidence,
            links,
        )?;
        let fields = batch.vulnerabilities.last_mut().unwrap();
        if let Some(published) = row["published"]
            .as_str()
            .filter(|s| chrono::DateTime::parse_from_rfc3339(s).is_ok())
        {
            fields["published"] = json!(published);
        }
    }
    finish(batch)
}

fn urls(source: &str) -> Result<Vec<&'static str>, String> {
    Ok(match source {
        "Apache HTTP Server" => vec![HTTPD],
        "Apache Tomcat" => vec![
            "https://tomcat.apache.org/security-9.html",
            "https://tomcat.apache.org/security-10.html",
            "https://tomcat.apache.org/security-11.html",
        ],
        "OpenSSL" => vec![OPENSSL],
        "curl" => vec![CURL],
        _ => return Err("Unknown vendor scraper".into()),
    })
}
fn parse(doc: &Document, source: &str) -> Result<Batch, String> {
    match source {
        "Apache HTTP Server" => parse_httpd(doc),
        "Apache Tomcat" => {
            let branch = match doc.url.as_str() {
                "https://tomcat.apache.org/security-9.html" => "9",
                "https://tomcat.apache.org/security-10.html" => "10",
                "https://tomcat.apache.org/security-11.html" => "11",
                _ => return Err("Unapproved Tomcat advisory URL".into()),
            };
            parse_tomcat(doc, branch)
        }
        "OpenSSL" => parse_openssl(doc),
        "curl" => parse_curl(doc),
        _ => Err("Unknown vendor scraper".into()),
    }
}
fn restricted_fetcher(base: &Fetcher) -> Result<Fetcher, String> {
    let client = reqwest::Client::builder()
        .user_agent("Sentinel-Intelligence/0.2 (vendor advisory indexing)")
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(45))
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            let same_host = attempt
                .previous()
                .first()
                .is_some_and(|u| u.host_str() == attempt.url().host_str());
            if attempt.previous().len() <= 2 && same_host && attempt.url().scheme() == "https" {
                attempt.follow()
            } else {
                attempt.error("Vendor scraper redirect outside approved HTTPS host")
            }
        }))
        .build()
        .map_err(|e| e.to_string())?;
    Ok(Fetcher {
        client,
        cache: base.cache.clone(),
    })
}
pub async fn ingest(
    db: &Database,
    base: &Fetcher,
    source: &str,
    cp: &mut Value,
) -> Result<usize, String> {
    let f = restricted_fetcher(base)?;
    let mut batch = Batch::default();
    let mut documents = Vec::new();
    for (index, url) in urls(source)?.into_iter().enumerate() {
        if index > 0 {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        let doc = f.get_bounded(url, &[], MAX_DOCUMENT).await?;
        let parsed = parse(&doc, source)?;
        if batch.vulnerabilities.len() + parsed.vulnerabilities.len() > MAX_RECORDS {
            return Err("Vendor source exceeds record limit".into());
        }
        batch.vulnerabilities.extend(parsed.vulnerabilities);
        documents.push(doc.provenance(source));
    }
    // Commit only after every approved branch parses. A failed page cannot publish a partial run.
    cp["documents"] = json!(documents);
    commit(db, source, batch, cp).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    fn document(url: &str, raw: &str) -> Document {
        Document {
            bytes: raw.as_bytes().to_vec(),
            url: url.into(),
            sha256: format!("{:x}", Sha256::digest(raw.as_bytes())),
            fetched_at: "2026-10-19T00:00:00Z".into(),
        }
    }
    fn httpd(release: &str, update: &str) -> Document {
        document(
            HTTPD,
            &format!(
                r#"<div id="apcontents"><h1>Fixed in Apache HTTP Server {release}</h1><dl>
            <dt><h3 id="CVE-2099-1000">low: Fixture &amp; parser</h3></dt><dd>
            <p>Fix for an earlier CVE-2099-9999. <script>do not import this</script></p>
            <table><tr><td>Affects</td><td>2.4.1 through 2.4.9</td></tr>
            <tr><td>{update}</td><td>2026-01-01</td></tr></table></dd></dl></div>"#
            ),
        )
    }
    #[test]
    fn httpd_uses_own_heading_and_only_published_releases() {
        let doc = httpd("2.4.10", "Update 2.4.10 released");
        let batch = parse_httpd(&doc).unwrap();
        assert_eq!(batch.vulnerabilities.len(), 1);
        let v = vi_core::merge_record(None, &batch.vulnerabilities[0]).unwrap();
        assert_eq!(v.id, "CVE-2099-1000");
        assert_eq!(v.title, "low: Fixture & parser");
        assert!(!v.description.contains("do not import"));
        assert!(v.patch_available);
        assert_eq!(
            v.remediation_evidence[0]["fixed_versions"],
            json!(["2.4.10"])
        );
        assert_eq!(
            v.remediation_evidence[0]["provenance"]["sha256"],
            doc.sha256
        );
        assert!(
            v.fixed_version.is_empty()
                && v.purl.is_empty()
                && !v.cvss_known
                && v.actors.is_empty()
                && v.published.is_empty()
        );
        for doc in [
            httpd("2.4.10-dev", "fixed in source tree"),
            httpd("2.4.10", "fixed in 2.4.x by r123"),
        ] {
            let batch = parse_httpd(&doc).unwrap();
            assert_ne!(batch.vulnerabilities[0]["patch_available"], true);
            assert_eq!(
                batch.vulnerabilities[0]["remediation_evidence"][0]["fixed_versions"],
                json!([])
            );
        }
    }
    fn tomcat(status: &str, branch: &str) -> Document {
        document(
            "https://tomcat.apache.org/security-9.html",
            &format!(
                r#"<div id="content">
          <h3 id="Fixed_in_Apache_Tomcat_{branch}.0.10"><span>{status}</span> Fixed in Apache Tomcat {branch}.0.10</h3><div class="text">
          <p><strong>Important: Fix for <a>CVE-2099-9999</a> was incomplete</strong><a>CVE-2099-1000</a></p>
          <p>First scoped description</p><p>Fixed with commit <a href="https://github.com/apache/tomcat/commit/abc">abc</a></p><p>Affects: {branch}.0.0 to {branch}.0.9</p>
          <p><strong>Low: Second issue</strong><a>CVE-2099-1001</a></p><p>Second scoped description</p>
          </div><h3 id="Not_a_vulnerability_in_Tomcat">Not a vulnerability</h3><div class="text"><p><strong>Unrelated</strong><a>CVE-2099-1002</a></p></div></div>"#
            ),
        )
    }
    #[test]
    fn tomcat_does_not_mix_cves_branches_or_unreleased_fixes() {
        let batch = parse_tomcat(&tomcat("2026-01-01", "9"), "9").unwrap();
        assert_eq!(batch.vulnerabilities.len(), 2);
        let first = &batch.vulnerabilities[0];
        assert_eq!(first["id"], "CVE-2099-1000");
        assert!(!first["description"]
            .as_str()
            .unwrap()
            .contains("Second scoped"));
        assert_eq!(first["patch_links"].as_array().unwrap().len(), 1);
        let v = vi_core::merge_record(None, first).unwrap();
        let other = parse_tomcat(&tomcat("2026-01-01", "11"), "11").unwrap();
        let v = vi_core::merge_record(Some(&v), &other.vulnerabilities[0]).unwrap();
        assert_eq!(v.remediation_evidence.len(), 2);
        assert!(v.fixed_version.is_empty());
        let pending = parse_tomcat(&tomcat("not yet released", "9"), "9").unwrap();
        assert_ne!(pending.vulnerabilities[0]["patch_available"], true);
        assert_eq!(pending.vulnerabilities[0]["patch_links"], json!([]));
    }
    #[test]
    fn tomcat_minor_release_context_comes_from_each_heading() {
        let old = tomcat("2026-01-01", "10");
        let newer = document(
            &old.url,
            &String::from_utf8(old.bytes.clone())
                .unwrap()
                .replace("10.0", "10.1"),
        );
        let old_batch = parse_tomcat(&old, "10").unwrap();
        let new_batch = parse_tomcat(&newer, "10").unwrap();
        assert_eq!(
            old_batch.vulnerabilities[0]["remediation_evidence"][0]["branch"],
            "10.0"
        );
        assert_eq!(
            new_batch.vulnerabilities[0]["remediation_evidence"][0]["branch"],
            "10.1"
        );
        assert!(parse_tomcat(&old, "11").is_err());
    }
    #[test]
    fn openssl_retains_multiple_release_ranges_and_ignores_nonissues() {
        let doc = document(
            OPENSSL,
            r##"<main><a href="#CVE-2099-1000"><h3 id="CVE-2099-1000">CVE-2099-1000</h3></a>
          <div class="grid"><div>Title</div><div>Scoped issue</div><div>Published at</div><div>1 January 2026</div>
          <div>Severity</div><div>High</div><div>Affected</div><div><ul><li>from 3.0.0 before 3.0.20</li><li>from 1.1.1 before 1.1.1z</li></ul></div>
          <div>References</div><div><a href="https://github.com/openssl/openssl/commit/abc">3.0.20 git commit</a><a href="javascript:evil">1.1.1z git commit</a></div></div>
          <p>Only this CVE's description. Earlier CVE-2099-9999.</p><h2>Not Vulnerabilities</h2><a>CVE-2099-1001</a></main>"##,
        );
        let batch = parse_openssl(&doc).unwrap();
        assert_eq!(batch.vulnerabilities.len(), 1);
        let v = vi_core::merge_record(None, &batch.vulnerabilities[0]).unwrap();
        assert_eq!(
            v.remediation_evidence[0]["fixed_versions"],
            json!(["3.0.20", "1.1.1z"])
        );
        assert_eq!(v.remediation_evidence[0]["vendor_severity"], "High");
        assert_eq!(v.patch_links.len(), 1);
        assert!(v.patch_available && !v.cvss_known);
        assert!(!v.description.contains("Not Vulnerabilities"));
    }
    fn curl_row() -> Value {
        json!({"id":"CURL-CVE-2099-1000","aliases":["CVE-2099-1000"],"summary":"Scoped curl fixture","details":"Fixture description","published":"2026-01-01T00:00:00Z",
          "database_specific":{"severity":"High"},"affected":[{"ranges":[
          {"type":"SEMVER","events":[{"introduced":"8.0.0"},{"fixed":"8.1.0"},{"introduced":"8.2.0"},{"fixed":"8.3.0"}]},
          {"type":"GIT","repo":"https://github.com/curl/curl.git","events":[{"fixed":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}]}]})
    }
    #[test]
    fn curl_does_not_confuse_commit_hashes_with_release_versions() {
        let batch = parse_curl(&document(CURL, &json!([curl_row()]).to_string())).unwrap();
        let v = vi_core::merge_record(None, &batch.vulnerabilities[0]).unwrap();
        assert_eq!(
            v.remediation_evidence[0]["fixed_versions"],
            json!(["8.1.0", "8.3.0"])
        );
        assert_eq!(v.patch_links.len(), 1);
        assert!(v.fixed_version.is_empty());
        assert_eq!(v.published, "2026-01-01T00:00:00Z");
        let mut row = curl_row();
        row["aliases"] = json!(["CVE-2099-1001"]);
        assert!(parse_curl(&document(CURL, &json!([row]).to_string())).is_err());
    }
    #[test]
    fn empty_or_changed_pages_fail_instead_of_reporting_success() {
        let empty = document(
            HTTPD,
            "<html><h1>Access denied</h1><p>CVE-2099-1000</p></html>",
        );
        assert!(parse_httpd(&empty).is_err());
        assert!(parse_tomcat(&empty, "9").is_err());
        assert!(parse_openssl(&empty).is_err());
        assert!(parse_curl(&document(CURL, "[]")).is_err());
        assert!(parse_curl(&document(CURL, "{}")).is_err());
        assert!(urls("https://attacker.test/").is_err());
        assert!(safe_reference(HTTPD, "javascript:alert(1)").is_none());
        assert!(safe_reference(HTTPD, "https://user:secret@example.test/").is_none());
        let mut oversized = empty.clone();
        oversized.bytes = vec![b'x'; MAX_DOCUMENT + 1];
        assert!(parse_httpd(&oversized).is_err());
    }
    #[tokio::test]
    #[ignore = "Optional live vendor scraper check; reads six official documents without database imports"]
    async fn official_vendor_sources_smoke() {
        let mut base = Fetcher::new().unwrap();
        base.cache =
            std::env::temp_dir().join(format!("sentinel-vendor-smoke-{}", std::process::id()));
        let f = restricted_fetcher(&base).unwrap();
        for source in ["Apache HTTP Server", "Apache Tomcat", "OpenSSL", "curl"] {
            for (index, url) in urls(source).unwrap().into_iter().enumerate() {
                if index > 0 {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                let doc = f
                    .get_bounded(url, &[], MAX_DOCUMENT)
                    .await
                    .unwrap_or_else(|e| panic!("{url}: {e}"));
                let batch = parse(&doc, source).unwrap_or_else(|e| panic!("{url}: {e}"));
                for row in &batch.vulnerabilities {
                    vi_core::merge_record(None, row).unwrap();
                }
                eprintln!(
                    "{source}: {} CVE assertions from {url}",
                    batch.vulnerabilities.len()
                );
            }
        }
        let _ = tokio::fs::remove_dir_all(&base.cache).await;
    }
}

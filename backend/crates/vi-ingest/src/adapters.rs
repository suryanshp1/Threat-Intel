use super::*;
use regex::Regex;
use std::collections::HashMap;
use vi_core::Vulnerability;

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}
fn list<'a>(v: &'a Value, key: &str) -> Result<&'a Vec<Value>, String> {
    v[key]
        .as_array()
        .ok_or_else(|| format!("Upstream schema missing {key}"))
}
fn provenance(doc: &Document, source: &str) -> Value {
    json!({"sources":[source],"provenance":[doc.provenance(source)],"ingested_at":doc.fetched_at})
}
fn patch(doc: &Document, source: &str, id: &str, fields: Value) -> Value {
    let mut p = provenance(doc, source);
    p["id"] = json!(id);
    for (k, v) in fields.as_object().unwrap() {
        p[k] = v.clone()
    }
    p
}
pub fn parse_kev(doc: &Document) -> Result<Batch, String> {
    let data = doc.json()?;
    let mut b = Batch::default();
    for row in list(&data, "vulnerabilities")? {
        let id = row["cveID"].as_str().ok_or("KEV record missing CVE")?;
        b.vulnerabilities.push(patch(doc,"CISA KEV",id,json!({"title":row["vulnerabilityName"],"description":row["shortDescription"],"vendor":row["vendorProject"],"product":row["product"],"seen_wild":true,"known_ransomware_use":row["knownRansomwareCampaignUse"]=="Known","cisa_date_added":row["dateAdded"],"cisa_due_date":row["dueDate"],"remediation":row["requiredAction"],"references":[{"url":format!("https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={id}"),"source":"CISA KEV"}]})));
    }
    Ok(b)
}
pub fn parse_nvd(doc: &Document) -> Result<Batch, String> {
    let data = doc.json()?;
    let mut batch = Batch::default();
    for wrapper in list(&data, "vulnerabilities")? {
        let v = &wrapper["cve"];
        let Some(id) = v["id"].as_str() else { continue };
        if v["vulnStatus"] == "Rejected" {
            continue;
        }
        let description = v["descriptions"]
            .as_array()
            .and_then(|a| a.iter().find(|v| v["lang"] == "en"))
            .and_then(|v| v["value"].as_str())
            .unwrap_or("");
        let metrics = &v["metrics"];
        let metric = [
            "cvssMetricV40",
            "cvssMetricV31",
            "cvssMetricV30",
            "cvssMetricV2",
        ]
        .iter()
        .find_map(|k| {
            metrics[*k]
                .as_array()
                .and_then(|a| a.iter().find(|v| v["type"] == "Primary").or(a.first()))
        });
        let mut fields = json!({"description":description,"title":description.split('.').next().unwrap_or(description).chars().take(150).collect::<String>(),"published":v["published"],"last_modified":v["lastModified"],"references":v["references"].as_array().cloned().unwrap_or_default(),"patch_status":"unknown"});
        if let Some(m) = metric {
            let data = &m["cvssData"];
            fields["cvss"] = data["baseScore"].clone();
            fields["cvss_known"] = json!(data["baseScore"].is_number());
            fields["cvss_vector"] = data["vectorString"].clone();
            let vector = data["vectorString"].as_str().unwrap_or("");
            fields["automatable"] = json!(["/AV:N", "/AC:L", "/PR:N", "/UI:N"]
                .iter()
                .all(|s| vector.contains(s)));
            fields["total_impact"] = json!(
                ["/C:H", "/I:H", "/A:H"].iter().all(|s| vector.contains(s))
                    || ["/VC:H", "/VI:H", "/VA:H"]
                        .iter()
                        .all(|s| vector.contains(s))
            );
        }
        let mut cpes = vec![];
        fn visit(v: &Value, cpes: &mut Vec<String>) {
            match v {
                Value::Object(m) => {
                    if m.get("vulnerable") == Some(&json!(true)) {
                        if let Some(c) = m.get("criteria").and_then(Value::as_str) {
                            cpes.push(c.into())
                        }
                    }
                    for v in m.values() {
                        visit(v, cpes)
                    }
                }
                Value::Array(a) => {
                    for v in a {
                        visit(v, cpes)
                    }
                }
                _ => {}
            }
        }
        visit(&v["configurations"], &mut cpes);
        if let Some(cpe) = cpes.first() {
            let parts: Vec<_> = cpe.split(':').collect();
            if parts.len() > 5 {
                fields["vendor"] = json!(parts[3]);
                fields["product"] = json!(parts[4]);
            }
        }
        fields["cpe"] = json!(cpes);
        fields["affected"] = v["configurations"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .into();
        crate::knowledge::nvd_evidence(doc, v, id, &mut fields, &mut batch);
        fields["patch_available"] = json!(fields["patch_links"]
            .as_array()
            .is_some_and(|a| !a.is_empty()));
        if fields["patch_available"] == true {
            fields["patch_status"] = json!("available");
        }
        batch
            .vulnerabilities
            .push(patch(doc, "NVD 2.0", id, fields));
    }
    Ok(batch)
}
pub async fn ingest(
    db: &Database,
    f: &Fetcher,
    source: &str,
    cp: &mut Value,
) -> Result<usize, String> {
    match source {
        "CISA KEV" => {
            let doc=f.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",&[]).await.or_else(|_|Err("CISA endpoint unavailable".to_string()));
            let doc=match doc{Ok(d)=>d,Err(_)=>f.get("https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json",&[]).await?};
            let b = parse_kev(&doc)?;
            cp["sha256"] = json!(doc.sha256);
            commit(db, source, b, cp).await
        }
        "NVD 2.0" => nvd(db, f, cp).await,
        "CVE List V5" | "Debian Security Tracker" | "Ubuntu USN" | "Trickest PoC references" => {
            crate::expansion::ingest(db, f, source, cp).await
        }
        "Apache HTTP Server" | "Apache Tomcat" | "OpenSSL" | "curl" => {
            crate::scrapers::ingest(db, f, source, cp).await
        }
        "MITRE CWE" | "OWASP Top 10" => crate::knowledge::ingest(db, f, source, cp).await,
        "FIRST EPSS" => epss(db, f, cp).await,
        "MITRE ATT&CK" => attack(db, f, cp).await,
        "RansomLook" => ransomlook(db, f, cp).await,
        "Microsoft MSRC" => msrc(db, f, cp).await,
        "OSV / GHSA" => ghsa(db, f, cp).await,
        "CISA Vulnrichment" => vulnrichment(db, f, cp).await,
        "Nuclei" | "Sigma" | "Suricata" => rules(db, f, source, cp).await,
        "Vendor CSAF / OpenVEX" => vendor_vex(db, f, cp).await,
        _ => Err("Unsupported source".into()),
    }
}
async fn nvd(db: &Database, f: &Fetcher, cp: &mut Value) -> Result<usize, String> {
    let now = Utc::now();
    let start = cp["window_start"]
        .as_str()
        .map(str::to_string)
        .or_else(|| cp["watermark"].as_str().map(str::to_string))
        .unwrap_or_else(|| {
            std::env::var("VI_NVD_START")
                .ok()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| {
                    (now - Duration::days(30))
                        .format("%Y-%m-%dT%H:%M:%S.000")
                        .to_string()
                })
        });
    let end = cp["window_end"]
        .as_str()
        .map(str::to_string)
        .unwrap_or_else(|| {
            let parsed = chrono::NaiveDateTime::parse_from_str(&start, "%Y-%m-%dT%H:%M:%S%.f")
                .unwrap_or_else(|_| (now - Duration::days(30)).naive_utc());
            std::cmp::min(parsed + Duration::days(120), now.naive_utc())
                .format("%Y-%m-%dT%H:%M:%S.000")
                .to_string()
        });
    cp["window_start"] = json!(start);
    cp["window_end"] = json!(end);
    let mut offset = cp["offset"].as_u64().unwrap_or(0);
    let mut count = 0;
    let pages = std::env::var("VI_NVD_PAGES_PER_RUN")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(10);
    let key = std::env::var("NVD_API_KEY").unwrap_or_default();
    for page in 0..pages {
        if page > 0 {
            tokio::time::sleep(Timeout::from_secs(if key.is_empty() { 6 } else { 1 })).await;
        }
        let mut url = url::Url::parse("https://services.nvd.nist.gov/rest/json/cves/2.0").unwrap();
        url.query_pairs_mut()
            .append_pair("lastModStartDate", &start)
            .append_pair("lastModEndDate", &end)
            .append_pair("startIndex", &offset.to_string())
            .append_pair("resultsPerPage", "2000");
        let headers = if key.is_empty() {
            vec![]
        } else {
            vec![("apiKey", key.as_str())]
        };
        let doc = f.get(url.as_str(), &headers).await?;
        let data = doc.json()?;
        let n = list(&data, "vulnerabilities")?.len();
        let total = data["totalResults"]
            .as_u64()
            .ok_or("NVD totalResults missing")?;
        let batch = parse_nvd(&doc)?;
        offset += n as u64;
        cp["offset"] = json!(offset);
        cp["total_results"] = json!(total);
        if offset >= total {
            cp["watermark"] = json!(end);
            cp["window_start"] = Value::Null;
            cp["window_end"] = Value::Null;
            cp["offset"] = json!(0);
        }
        count += commit(db, "NVD 2.0", batch, cp).await?;
        if offset >= total {
            break;
        }
        if n == 0 {
            return Err("NVD returned empty page before totalResults".into());
        }
    }
    Ok(count)
}
async fn epss(db: &Database, f: &Fetcher, cp: &mut Value) -> Result<usize, String> {
    let ids = db.ids().await?;
    let mut count = 0;
    for chunk in ids.chunks(100) {
        let mut url = url::Url::parse("https://api.first.org/data/v1/epss").unwrap();
        url.query_pairs_mut()
            .append_pair("cve", &chunk.join(","))
            .append_pair("limit", "100");
        let doc = f.get(url.as_str(), &[]).await?;
        let data = doc.json()?;
        let mut batch = Batch::default();
        for v in list(&data, "data")? {
            let Some(id) = v["cve"].as_str() else {
                continue;
            };
            let score = v["epss"]
                .as_str()
                .and_then(|s| s.parse::<f64>().ok())
                .ok_or("Invalid EPSS probability")?;
            batch.vulnerabilities.push(patch(
                &doc,
                "FIRST EPSS",
                id,
                json!({"epss_score":score,"epss_known":true}),
            ));
        }
        cp["last_cursor"] = json!(chunk.last());
        count += commit(db, "FIRST EPSS", batch, cp).await?;
        tokio::time::sleep(Timeout::from_millis(200)).await;
    }
    Ok(count)
}
async fn attack(db: &Database, f: &Fetcher, cp: &mut Value) -> Result<usize, String> {
    let doc=f.get("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",&[]).await?;
    let data = doc.json()?;
    let objects = list(&data, "objects")?;
    let mut techniques = HashMap::new();
    for v in objects {
        if v["type"] == "attack-pattern" {
            if let Some(id) = v["id"].as_str() {
                let external = v["external_references"]
                    .as_array()
                    .and_then(|a| a.iter().find(|r| r["source_name"] == "mitre-attack"))
                    .and_then(|r| r["external_id"].as_str())
                    .unwrap_or("");
                techniques.insert(id.to_string(), external.to_string());
            }
        }
    }
    let mut batch = Batch::default();
    for v in objects {
        if v["revoked"] == true || v["x_mitre_deprecated"] == true {
            continue;
        }
        let id = v["id"].as_str().unwrap_or("");
        if v["type"] == "intrusion-set" {
            let name = v["name"].as_str().unwrap_or(id);
            let links: Vec<_> = objects
                .iter()
                .filter(|r| {
                    r["type"] == "relationship"
                        && r["source_ref"] == id
                        && r["relationship_type"] == "uses"
                })
                .filter_map(|r| r["target_ref"].as_str().and_then(|id| techniques.get(id)))
                .cloned()
                .collect();
            batch.entities.push(("actors".into(),name.into(),json!({"id":name,"stix_id":id,"country":"Not attributed by source","code":"—","description":v["description"].as_str().unwrap_or(""),"aliases":v["aliases"].as_array().cloned().unwrap_or_default(),"cves_exploited":[],"target_category":[],"techniques":links,"type":"Threat actor","first_seen":v["created"].as_str().unwrap_or(""),"references":v["external_references"],"source":"MITRE ATT&CK","provenance":doc.provenance("MITRE ATT&CK")})));
        }
        if v["type"] == "relationship" {
            batch.entities.push(("relationships".into(),id.into(),json!({"id":id,"source_ref":v["source_ref"],"target_ref":v["target_ref"],"relationship_type":v["relationship_type"],"description":v["description"],"source":"MITRE ATT&CK","provenance":doc.provenance("MITRE ATT&CK")})));
        }
    }
    cp["sha256"] = json!(doc.sha256);
    commit(db, "MITRE ATT&CK", batch, cp).await
}
async fn ransomlook(db: &Database, f: &Fetcher, cp: &mut Value) -> Result<usize, String> {
    let doc = f.get("https://www.ransomlook.io/api/groups", &[]).await?;
    let data = doc.json()?;
    let mut batch = Batch::default();
    let rows: Vec<(String, Value)> = match &data {
        Value::Object(m) => m.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        Value::Array(a) => a
            .iter()
            .filter_map(|v| {
                v.as_str()
                    .or_else(|| v["name"].as_str())
                    .map(|n| (n.into(), if v.is_object() { v.clone() } else { json!({}) }))
            })
            .collect(),
        _ => return Err("Unexpected RansomLook schema".into()),
    };
    if rows.is_empty() && data.as_array().is_some_and(|a| !a.is_empty()) {
        return Err("Unrecognized RansomLook group records".into());
    }
    for (name, row) in rows {
        let description = row["description"]
            .as_str()
            .or_else(|| row["meta"]["description"].as_str())
            .unwrap_or("");
        batch.entities.push(("ransomware".into(),name.clone(),json!({"id":name,"country":"Unattributed","code":"—","description":description,"aliases":[],"cves_exploited":[],"target_category":[],"techniques":[],"type":"Ransomware","first_seen":row["first_seen"].as_str().unwrap_or(""),"victim_count":row["victim_count"],"infrastructure":row["locations"],"source":"RansomLook","provenance":doc.provenance("RansomLook")})));
    }
    commit(db, "RansomLook", batch, cp).await
}
pub fn from_osv(doc: &Value, purl: &str, origin: &Value) -> Result<Vulnerability, String> {
    let id = doc["aliases"]
        .as_array()
        .and_then(|a| {
            a.iter()
                .find_map(|id| id.as_str().filter(|id| id.starts_with("CVE-")))
        })
        .or_else(|| doc["id"].as_str().filter(|id| id.starts_with("CVE-")))
        .ok_or("OSV advisory has no CVE alias")?;
    let mut v = Vulnerability {
        id: id.into(),
        title: doc["summary"].as_str().unwrap_or(id).into(),
        description: doc["details"].as_str().unwrap_or("").into(),
        published: doc["published"].as_str().unwrap_or("").into(),
        last_modified: doc["modified"].as_str().unwrap_or("").into(),
        aliases: strings(&doc["aliases"]),
        sources: vec!["OSV".into()],
        provenance: vec![origin.clone()],
        purl: vi_core::package_base(purl).into(),
        references: doc["references"].as_array().cloned().unwrap_or_default(),
        affected: doc["affected"].as_array().cloned().unwrap_or_default(),
        ingested_at: Utc::now().to_rfc3339(),
        ..Default::default()
    };
    v.score();
    Ok(v)
}
async fn ghsa(db: &Database, f: &Fetcher, cp: &mut Value) -> Result<usize, String> {
    let mut count = 0;
    let mut page = cp["page"].as_u64().unwrap_or(1);
    let token = std::env::var("GITHUB_TOKEN").unwrap_or_default();
    let auth = format!("Bearer {token}");
    let headers = if token.is_empty() {
        vec![("Accept", "application/vnd.github+json")]
    } else {
        vec![
            ("Accept", "application/vnd.github+json"),
            ("Authorization", auth.as_str()),
        ]
    };
    let since = cp["window_start"]
        .as_str()
        .or_else(|| cp["watermark"].as_str())
        .map(str::to_string)
        .unwrap_or_else(|| {
            (Utc::now() - Duration::days(30))
                .format("%Y-%m-%d")
                .to_string()
        });
    let now = cp["window_end"]
        .as_str()
        .map(str::to_string)
        .unwrap_or_else(|| Utc::now().format("%Y-%m-%d").to_string());
    cp["window_start"] = json!(since);
    cp["window_end"] = json!(now);
    for _ in 0..3 {
        let mut url = url::Url::parse("https://api.github.com/advisories").unwrap();
        url.query_pairs_mut()
            .append_pair("per_page", "100")
            .append_pair("page", &page.to_string())
            .append_pair("sort", "updated")
            .append_pair("direction", "asc")
            .append_pair("modified", &format!("{since}..{now}"));
        let doc = f.get(url.as_str(), &headers).await?;
        let data = doc.json()?;
        let rows = data.as_array().ok_or("Unexpected GHSA response")?;
        let mut batch = Batch::default();
        for a in rows {
            let Some(cve) = a["cve_id"].as_str() else {
                continue;
            };
            let refs: Vec<Value> = a["references"]
                .as_array()
                .map(|v| {
                    v.iter()
                        .filter_map(Value::as_str)
                        .map(|url| json!({"url":url,"source":"GHSA"}))
                        .collect()
                })
                .unwrap_or_default();
            let mut fields = json!({"aliases":[a["ghsa_id"]],"description":a["description"],"title":a["summary"],"published":a["published_at"],"last_modified":a["updated_at"],"references":refs});
            if let Some(score) = a["cvss"]["score"].as_f64() {
                fields["cvss"] = json!(score);
                fields["cvss_known"] = json!(true);
                fields["cvss_vector"] = a["cvss"]["vector_string"].clone();
            }
            for p in a["vulnerabilities"].as_array().unwrap_or(&vec![]) {
                let name = p["package"]["name"].as_str().unwrap_or("");
                let ecosystem = p["package"]["ecosystem"].as_str().unwrap_or("");
                let eco = match ecosystem {
                    "pip" => "pypi",
                    "go" => "golang",
                    "rust" => "cargo",
                    "rubygems" => "gem",
                    e => e,
                };
                let purl = if !name.is_empty() && !eco.is_empty() {
                    format!("pkg:{eco}/{name}")
                } else {
                    String::new()
                };
                let fixed = p["first_patched_version"].as_str().unwrap_or("");
                fields["purl"] = json!(purl);
                fields["ecosystem"] = json!(eco);
                fields["product"] = json!(name);
                if !fixed.is_empty() {
                    fields["fixed_version"] = json!(fixed);
                    fields["patch_available"] = json!(true);
                    fields["patch_status"] = json!("available");
                }
                batch.entities.push(("products".into(),format!("{cve}:{purl}"),json!({"id":format!("{cve}:{purl}"),"name":name,"vendor":"","ecosystem":eco,"purl":purl,"cpe":"","affected_version_range":p["vulnerable_version_range"],"fixed_version":fixed,"cve_id":cve,"is_malicious_package":false,"source":"OSV / GHSA","provenance":doc.provenance("GHSA")})));
            }
            batch
                .vulnerabilities
                .push(patch(&doc, "OSV / GHSA", cve, fields));
        }
        page += 1;
        cp["page"] = json!(page);
        let done = rows.len() < 100;
        if done {
            cp["watermark"] = json!(now);
            cp["window_start"] = Value::Null;
            cp["window_end"] = Value::Null;
            cp["page"] = json!(1);
        }
        count += commit(db, "OSV / GHSA", batch, cp).await?;
        if done {
            break;
        }
        tokio::time::sleep(Timeout::from_secs(1)).await;
    }
    Ok(count)
}
async fn vulnrichment(db: &Database, f: &Fetcher, cp: &mut Value) -> Result<usize, String> {
    let ids = db.ids().await?;
    let cursor = cp["last_cursor"].as_str().unwrap_or("").to_string();
    let candidates: Vec<_> = ids
        .iter()
        .filter(|id| **id > cursor)
        .take(50)
        .cloned()
        .collect();
    let mut count = 0;
    for id in &candidates {
        let year = id.split('-').nth(1).ok_or("Invalid CVE ID")?;
        let number = id.split('-').nth(2).ok_or("Invalid CVE ID")?;
        let folder = format!("{}xxx", &number[..number.len().saturating_sub(3)]);
        let url=format!("https://raw.githubusercontent.com/cisagov/vulnrichment/develop/{year}/{folder}/{id}.json");
        let doc = match f.get(&url, &[]).await {
            Ok(d) => d,
            Err(e) if e.starts_with("HTTP 404") => {
                cp["last_cursor"] = json!(id);
                db.save_checkpoint("CISA Vulnrichment", cp.clone()).await?;
                continue;
            }
            Err(e) => return Err(e),
        };
        let data = doc.json()?;
        let adps = data["containers"]["adp"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        let mut fields = json!({});
        for adp in adps {
            for metric in adp["metrics"].as_array().unwrap_or(&vec![]) {
                if metric["other"]["type"] == "ssvc" {
                    fields["ssvc"] = metric["other"]["content"].clone();
                }
                for key in ["cvssV4_0", "cvssV3_1", "cvssV3_0"] {
                    if let Some(score) = metric[key]["baseScore"].as_f64() {
                        fields["cvss"] = json!(score);
                        fields["cvss_known"] = json!(true);
                        fields["cvss_vector"] = metric[key]["vectorString"].clone();
                        break;
                    }
                }
            }
        }
        cp["last_cursor"] = json!(id);
        let mut b = Batch::default();
        b.vulnerabilities
            .push(patch(&doc, "CISA Vulnrichment", id, fields));
        count += commit(db, "CISA Vulnrichment", b, cp).await?;
    }
    if candidates.len() < 50 {
        cp["last_cursor"] = json!("");
    }
    Ok(count)
}
async fn msrc(db: &Database, f: &Fetcher, cp: &mut Value) -> Result<usize, String> {
    let doc = f
        .get(
            "https://api.msrc.microsoft.com/cvrf/v3.0/updates",
            &[("Accept", "application/json")],
        )
        .await?;
    let data = doc.json()?;
    let mut updates = list(&data, "value")?.clone();
    updates.sort_by(|a, b| b["ID"].as_str().cmp(&a["ID"].as_str()));
    let regex = Regex::new(r"(?:KB)?(\d{7})").unwrap();
    let mut count = 0;
    for update in updates.iter().take(3) {
        let Some(id) = update["ID"].as_str() else {
            continue;
        };
        if !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            continue;
        }
        let doc = f
            .get(
                &format!("https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{id}"),
                &[("Accept", "application/json")],
            )
            .await?;
        let data = doc.json()?;
        let vulns = list(&data, "Vulnerability")?;
        let mut names = HashMap::<String, String>::new();
        fn products(v: &Value, n: &mut HashMap<String, String>) {
            if let Some(id) = v["ProductID"].as_str() {
                if let Some(name) = v["Value"].as_str() {
                    n.insert(id.into(), name.into());
                }
            }
            match v {
                Value::Object(m) => {
                    for v in m.values() {
                        products(v, n)
                    }
                }
                Value::Array(a) => {
                    for v in a {
                        products(v, n)
                    }
                }
                _ => {}
            }
        }
        products(&data["ProductTree"], &mut names);
        let mut b = Batch::default();
        for v in vulns {
            let Some(cve) = v["CVE"].as_str() else {
                continue;
            };
            for fix in v["Remediations"].as_array().unwrap_or(&vec![]) {
                if fix["Type"].as_i64() != Some(2) {
                    continue;
                }
                let desc = fix["Description"]["Value"].as_str().unwrap_or("");
                let Some(capture) = regex.captures(desc) else {
                    continue;
                };
                let kb = format!("KB{}", &capture[1]);
                let supersedes: Vec<_> = regex
                    .captures_iter(fix["Supercedence"].as_str().unwrap_or(""))
                    .map(|c| format!("KB{}", &c[1]))
                    .collect();
                let product_ids = fix["ProductID"].as_array().cloned().unwrap_or_default();
                for product in product_ids {
                    let product = product.as_str().unwrap_or("");
                    let name = names.get(product).map(String::as_str).unwrap_or(product);
                    b.entities.push(("patches".into(),format!("{kb}:{product}"),json!({"id":kb,"product":name,"product_id":product,"build_number":fix["FixedBuild"].as_str().unwrap_or(""),"published":update["CurrentReleaseDate"],"supersedes":supersedes,"cves":[cve],"url":fix["URL"],"source":"Microsoft MSRC","provenance":doc.provenance("Microsoft MSRC")})));
                }
                b.vulnerabilities.push(patch(&doc,"Microsoft MSRC",cve,json!({"patch_available":true,"patch_status":"available","references":[{"url":fix["URL"],"source":"Microsoft MSRC","kb":kb}]})));
            }
        }
        cp["last_cursor"] = json!(id);
        count += commit(db, "Microsoft MSRC", b, cp).await?;
    }
    Ok(count)
}
async fn rules(db: &Database, f: &Fetcher, source: &str, cp: &mut Value) -> Result<usize, String> {
    if source == "Suricata" {
        let doc = f
            .get(
                "https://rules.emergingthreats.net/open/suricata-7.0.3/emerging.rules.tar.gz",
                &[],
            )
            .await?;
        return parse_rule_archive(db, &doc, source, cp).await;
    }
    let repo = if source == "Nuclei" {
        "projectdiscovery/nuclei-templates"
    } else {
        "SigmaHQ/sigma"
    };
    let branch = if source == "Nuclei" { "main" } else { "master" };
    let doc = f
        .get(
            &format!("https://codeload.github.com/{repo}/tar.gz/refs/heads/{branch}"),
            &[],
        )
        .await?;
    parse_rule_archive(db, &doc, source, cp).await
}
async fn parse_rule_archive(
    db: &Database,
    doc: &Document,
    source: &str,
    cp: &mut Value,
) -> Result<usize, String> {
    let document = doc.clone();
    let name = source.to_string();
    let (batch, scanned) = tokio::task::spawn_blocking(move || extract_rules(&document, &name))
        .await
        .map_err(|e| e.to_string())??;
    let resume = if cp["sha256"] == doc.sha256 {
        cp["archive_offset"].as_u64().unwrap_or(0) as usize
    } else {
        0
    };
    let mut entities = batch.entities.into_iter().skip(resume);
    let mut offset = resume;
    let mut total = 0;
    loop {
        let chunk: Vec<_> = entities.by_ref().take(500).collect();
        if chunk.is_empty() {
            break;
        }
        offset += chunk.len();
        cp["sha256"] = json!(doc.sha256);
        cp["archive_offset"] = json!(offset);
        total += commit(
            db,
            source,
            Batch {
                entities: chunk,
                ..Default::default()
            },
            cp,
        )
        .await?;
    }
    cp["archive_offset"] = json!(0);
    cp["scanned_files"] = json!(scanned);
    Ok(total)
}
fn detection_yaml(raw: &str) -> Result<Value, String> {
    let mut budget = serde_saphyr::Budget::default();
    budget.max_depth = 32;
    budget.max_nodes = 25000;
    budget.max_events = 50000;
    budget.max_documents = 1;
    budget.max_aliases = 100;
    budget.max_anchors = 1000;
    budget.max_total_scalar_bytes = 1024 * 1024;
    budget.max_recorded_anchor_bytes = 1024 * 1024;
    let mut options = serde_saphyr::Options::default();
    options.budget = Some(budget);
    serde_saphyr::from_str_with_options(raw, options)
        .map_err(|_| "Detection YAML rejected by parser budget".into())
}
fn extract_rules(doc: &Document, source: &str) -> Result<(Batch, usize), String> {
    use std::io::Read;
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(doc.bytes.as_slice()));
    let cve_regex = Regex::new(r"(?i)CVE-\d{4}-\d{4,}").unwrap();
    let sid_regex = Regex::new(r"sid:(\d+)").unwrap();
    let mut batch = Batch::default();
    let mut scanned = 0;
    let mut expanded = 0_u64;
    for entry in archive.entries().map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        if !entry.header().entry_type().is_file() || entry.size() > 1024 * 1024 {
            continue;
        }
        expanded += entry.size();
        if expanded > 512 * 1024 * 1024 {
            return Err("Rule archive exceeds 512 MB expanded limit".into());
        }
        let path = entry
            .path()
            .map_err(|e| e.to_string())?
            .to_string_lossy()
            .to_string();
        if !(path.ends_with(".yaml") || path.ends_with(".yml") || path.ends_with(".rules")) {
            continue;
        }
        let mut raw = String::new();
        entry
            .take(1024 * 1024)
            .read_to_string(&mut raw)
            .map_err(|e| e.to_string())?;
        scanned += 1;
        if source == "Suricata" {
            for line in raw.lines().filter(|l| !l.trim_start().starts_with('#')) {
                let cves: std::collections::HashSet<_> = cve_regex
                    .find_iter(line)
                    .map(|c| c.as_str().to_uppercase())
                    .collect();
                for cve in cves {
                    let sid = sid_regex
                        .captures(line)
                        .map(|c| c[1].to_string())
                        .unwrap_or_else(|| format!("{:x}", Sha256::digest(line.as_bytes())));
                    batch.entities.push(("rules".into(),format!("suricata:{sid}:{cve}"),json!({"id":format!("suricata:{sid}:{cve}"),"rule_id":sid,"cve_id":cve,"rule_type":"suricata","title":format!("Emerging Threats SID {sid}"),"raw_content":line,"source_url":"https://rules.emergingthreats.net/","source":source,"provenance":doc.provenance(source)})));
                }
            }
        } else {
            let yaml: Value = match detection_yaml(&raw) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let cves: std::collections::HashSet<_> = cve_regex
                .find_iter(&raw)
                .map(|c| c.as_str().to_uppercase())
                .collect();
            let id = yaml["id"].as_str().unwrap_or(&path);
            let title = yaml["title"]
                .as_str()
                .or(yaml["info"]["name"].as_str())
                .unwrap_or(id);
            let repo = if source == "Nuclei" {
                "projectdiscovery/nuclei-templates/blob/main"
            } else {
                "SigmaHQ/sigma/blob/master"
            };
            let relative = path.split_once('/').map(|(_, p)| p).unwrap_or(&path);
            for cve in cves {
                batch.entities.push(("rules".into(),format!("{source}:{id}:{cve}"),json!({"id":format!("{source}:{id}:{cve}"),"rule_id":id,"cve_id":cve,"rule_type":source.to_lowercase(),"title":title,"description":yaml["description"].as_str().or(yaml["info"]["description"].as_str()).unwrap_or(""),"raw_content":raw,"source_url":format!("https://github.com/{repo}/{relative}"),"source":source,"provenance":doc.provenance(source)})));
            }
        }
    }
    Ok((batch, scanned))
}
async fn vendor_vex(db: &Database, f: &Fetcher, cp: &mut Value) -> Result<usize, String> {
    let dir =
        std::env::var("VI_VEX_IMPORT_DIR").unwrap_or_else(|_| "backend/data/vex-import".into());
    let path = std::path::Path::new(&dir);
    if !path.exists() {
        return Err("Set VI_VEX_IMPORT_DIR to a directory of publisher-verified CSAF/OpenVEX documents; automatic untrusted suppression is disabled".into());
    }
    let mut count = 0;
    for entry in std::fs::read_dir(path).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let bytes = std::fs::read(&path).map_err(|e| e.to_string())?;
        if bytes.len() > 10 * 1024 * 1024 {
            return Err("VEX import document exceeds 10 MB".into());
        }
        let doc: Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        if doc["@context"] == "https://openvex.dev/ns/v0.2.0" {
            db.save_vex(doc, "publisher-import").await?;
            count += 1;
        } else if doc["document"]["csaf_version"] == "2.0" {
            for v in doc["vulnerabilities"].as_array().unwrap_or(&vec![]) {
                if let Some(id) = v["cve"].as_str() {
                    let origin = Document {
                        url: format!("file://{}", path.display()),
                        sha256: format!("{:x}", Sha256::digest(&bytes)),
                        bytes: vec![],
                        fetched_at: Utc::now().to_rfc3339(),
                    };
                    let mut b = Batch::default();
                    b.vulnerabilities.push(patch(&origin,"Vendor CSAF / OpenVEX",id,json!({"references":v["references"].as_array().cloned().unwrap_or_default()})));
                    count += commit(db, "Vendor CSAF / OpenVEX", b, cp).await?;
                }
            }
        } else {
            return Err("Unsupported vendor document".into());
        }
    }
    let _ = f;
    Ok(count)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn document(value: Value) -> Document {
        Document {
            bytes: serde_json::to_vec(&value).unwrap(),
            url: "https://example.test/fixture".into(),
            sha256: "test-only".into(),
            fetched_at: "2026-01-01T00:00:00Z".into(),
        }
    }
    #[test]
    fn detection_yaml_parses_data_and_rejects_deep_expansion() {
        let row=detection_yaml("id: fixture\ntitle: Fixture rule\nreferences:\n  - https://example.test/CVE-2099-1000\n").unwrap();
        assert_eq!(row["title"], "Fixture rule");
        assert!(detection_yaml(&format!("{}0{}", "[".repeat(40), "]".repeat(40))).is_err());
        assert!(detection_yaml("---\none: 1\n---\ntwo: 2").is_err());
    }
    #[test]
    fn kev_does_not_invent_cvss_publication_or_actor() {
        let doc = document(
            json!({"vulnerabilities":[{"cveID":"CVE-2099-1000","vulnerabilityName":"Test-only fixture","shortDescription":"Parser assertion","vendorProject":"Test","product":"Fixture","dateAdded":"2026-01-01","dueDate":"2026-01-20","knownRansomwareCampaignUse":"Unknown"}]}),
        );
        let batch = parse_kev(&doc).unwrap();
        let v = vi_core::merge_record(None, &batch.vulnerabilities[0]).unwrap();
        assert!(v.seen_wild);
        assert!(!v.cvss_known);
        assert!(!v.epss_known);
        assert!(v.published.is_empty());
        assert!(v.actors.is_empty());
        assert_eq!(v.ssvc_decision, "Unassessed");
        assert_eq!(v.provenance.len(), 1);
    }
    #[test]
    fn nvd_keeps_authoritative_coordinates_and_vector() {
        let doc = document(
            json!({"vulnerabilities":[{"cve":{"id":"CVE-2099-1000","published":"2026-01-01T00:00:00Z","descriptions":[{"lang":"en","value":"Test parser vulnerability."}],"metrics":{"cvssMetricV31":[{"type":"Primary","cvssData":{"baseScore":9.8,"vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]},"configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:example:fixture:*:*:*:*:*:*:*:*"}]}]}],"references":[{"url":"https://example.test/patch","tags":["Patch"]}]}}]}),
        );
        let b = parse_nvd(&doc).unwrap();
        let v = vi_core::merge_record(None, &b.vulnerabilities[0]).unwrap();
        assert_eq!(v.cvss, 9.8);
        assert!(v.cvss_known && v.automatable && v.patch_available);
        assert_eq!(v.vendor, "example");
        assert_eq!(v.cpe.len(), 1);
        assert!(v.purl.is_empty());
    }
    #[test]
    fn malformed_feed_cannot_be_healthy_empty_import() {
        assert!(parse_kev(&document(json!({"unexpected":[]}))).is_err());
        assert!(parse_nvd(&document(json!({}))).is_err());
    }
}

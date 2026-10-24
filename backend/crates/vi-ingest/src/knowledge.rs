//! Official knowledge sources and explicit NVD remediation evidence.
use crate::{commit, Document, Fetcher};
use regex::Regex;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use vi_db::{Batch, Database};

fn numeric_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 8 && id.bytes().all(|b| b.is_ascii_digit())
}
fn safe_url(raw: &str) -> bool {
    url::Url::parse(raw).is_ok_and(|u| {
        matches!(u.scheme(), "http" | "https")
            && u.host_str().is_some()
            && u.username().is_empty()
            && u.password().is_none()
    })
}
fn relation(batch: &mut Batch, doc: &Document, source: &str, from: &str, to: &str, kind: &str) {
    let id = format!("{from}:{kind}:{to}");
    batch.entities.push((
        "relationships".into(),
        id.clone(),
        json!({
            "id":id,"source_ref":from,"target_ref":to,"relationship_type":kind,
            "source":source,"provenance":doc.provenance(source)
        }),
    ));
}

pub fn nvd_evidence(doc: &Document, cve: &Value, id: &str, fields: &mut Value, batch: &mut Batch) {
    let mut weaknesses = BTreeSet::new();
    let mut evidence = Vec::new();
    for row in cve["weaknesses"].as_array().unwrap_or(&vec![]) {
        for item in row["description"].as_array().unwrap_or(&vec![]) {
            let Some(cwe) = item["value"].as_str() else {
                continue;
            };
            if !cwe.strip_prefix("CWE-").is_some_and(numeric_id) {
                continue;
            }
            weaknesses.insert(cwe.to_string());
            evidence.push(json!({"id":cwe,"source":row["source"],"type":row["type"],"provenance":doc.provenance("NVD 2.0")}));
        }
    }
    for cwe in &weaknesses {
        relation(batch, doc, "NVD 2.0", id, cwe, "has-weakness");
    }
    fields["weaknesses"] = json!(weaknesses);
    fields["weakness_evidence"] = json!(evidence);
    let mut links = Vec::new();
    for r in cve["references"].as_array().unwrap_or(&vec![]) {
        let Some(url) = r["url"].as_str().filter(|u| safe_url(u)) else {
            continue;
        };
        if !r["tags"]
            .as_array()
            .is_some_and(|t| t.contains(&json!("Patch")))
        {
            continue;
        }
        let link = json!({"url":url,"source":"NVD 2.0","reference_source":r["source"],"tags":r["tags"],"provenance":doc.provenance("NVD 2.0")});
        if !links.contains(&link) {
            links.push(link);
        }
    }
    fields["patch_links"] = json!(links);
}

pub fn parse_cwe(doc: &Document) -> Result<Batch, String> {
    let data = doc.json()?;
    let rows = data["Weaknesses"]
        .as_array()
        .ok_or("CWE schema missing Weaknesses")?;
    if rows.is_empty() || rows.len() > 10000 {
        return Err("CWE catalog count outside bounds".into());
    }
    let mut batch = Batch {
        replace_entity_kinds: vec!["weaknesses".into()],
        ..Default::default()
    };
    let mut ids = BTreeSet::new();
    for row in rows {
        let number = row["ID"]
            .as_str()
            .filter(|s| numeric_id(s))
            .ok_or("Invalid CWE ID")?;
        let name = row["Name"]
            .as_str()
            .filter(|s| !s.trim().is_empty())
            .ok_or("CWE name missing")?;
        let id = format!("CWE-{number}");
        if !ids.insert(id.clone()) {
            return Err("Duplicate CWE ID".into());
        }
        batch.entities.push((
            "weaknesses".into(),
            id.clone(),
            json!({
                "id":id,"name":name,"description":row["Description"],"status":row["Status"],
                "url":format!("https://cwe.mitre.org/data/definitions/{number}.html"),
                "source":"MITRE CWE","provenance":doc.provenance("MITRE CWE"),
                "upstream":row
            }),
        ));
    }
    Ok(batch)
}

// Fetch only the ten category documents under the official release's English directory.
const OWASP_ROOT: &str = "https://raw.githubusercontent.com/OWASP/Top10/master/2025/docs/en/";
fn category_files(data: &Value) -> Result<Vec<String>, String> {
    let rows = data
        .as_array()
        .ok_or("OWASP directory response must be an array")?;
    let pattern = Regex::new(r"^A(0[1-9]|10)_2025-[A-Za-z0-9_-]+\.md$").unwrap();
    let mut files = Vec::new();
    let mut ranks = BTreeSet::new();
    for row in rows {
        if row["type"] != "file" {
            continue;
        }
        if let Some(name) = row["name"].as_str().filter(|n| pattern.is_match(n)) {
            if !ranks.insert(name[1..3].to_string()) {
                return Err("Duplicate OWASP category".into());
            }
            files.push(name.to_string());
        }
    }
    if files.len() != 10 {
        return Err("Expected all ten OWASP 2025 category documents".into());
    }
    files.sort();
    Ok(files)
}

pub fn parse_owasp(doc: &Document, rank: &str) -> Result<Batch, String> {
    if !(1..=10).any(|n| rank == format!("{n:02}")) {
        return Err("Invalid OWASP rank".into());
    }
    let text = std::str::from_utf8(&doc.bytes).map_err(|e| e.to_string())?;
    let heading = text
        .lines()
        .next()
        .unwrap_or("")
        .trim_start_matches('#')
        .trim();
    let prefix = format!("A{rank}:2025 ");
    let name = heading
        .strip_prefix(&prefix)
        .ok_or("Unexpected OWASP category heading")?
        .split("![")
        .next()
        .unwrap_or("")
        .trim();
    if name.is_empty() {
        return Err("Empty OWASP category name".into());
    }
    // Only the explicit mapping section supplies mappings; prose and examples do not.
    let section = text
        .lines()
        .skip_while(|l| !l.trim().eq_ignore_ascii_case("## List of Mapped CWEs"))
        .skip(1)
        .take_while(|l| !l.starts_with("## "))
        .collect::<Vec<_>>()
        .join("\n");
    let pattern = Regex::new(
        r"\[CWE-([0-9]+)\b[^\]\n]*\]\(https://cwe\.mitre\.org/data/definitions/([0-9]+)\.html\)",
    )
    .unwrap();
    let mut cwes = BTreeSet::new();
    for cap in pattern.captures_iter(&section) {
        if cap[1] != cap[2] || !numeric_id(&cap[1]) {
            return Err("Inconsistent OWASP CWE link".into());
        }
        cwes.insert(format!("CWE-{}", &cap[1]));
    }
    if cwes.is_empty() {
        return Err("OWASP explicit CWE mappings missing".into());
    }
    let id = format!("OWASP-A{rank}:2025");
    let mut batch = Batch::default();
    for cwe in &cwes {
        relation(&mut batch, doc, "OWASP Top 10", cwe, &id, "maps-to");
    }
    batch.entities.push((
        "categories".into(),
        id.clone(),
        json!({
            "id":id,"name":name,"edition":"2025","cwes":cwes,"source":"OWASP Top 10",
            "url":doc.url,"provenance":doc.provenance("OWASP Top 10")
        }),
    ));
    Ok(batch)
}

pub async fn ingest(
    db: &Database,
    f: &Fetcher,
    source: &str,
    cp: &mut Value,
) -> Result<usize, String> {
    if source == "MITRE CWE" {
        let doc = f
            .get("https://cwe-api.mitre.org/api/v1/cwe/weakness/all", &[])
            .await?;
        let batch = parse_cwe(&doc)?;
        cp["sha256"] = json!(doc.sha256);
        return commit(db, source, batch, cp).await;
    }
    let directory = f
        .get(
            "https://api.github.com/repos/OWASP/Top10/contents/2025/docs/en?ref=master",
            &[],
        )
        .await?;
    let files = category_files(&directory.json()?)?;
    let mut batch = Batch {
        replace_entity_kinds: vec!["categories".into(), "relationships".into()],
        ..Default::default()
    };
    // No partial snapshot commits: preserve the previous edition on any fetch/schema error.
    for file in files {
        let doc = f.get(&format!("{OWASP_ROOT}{file}"), &[]).await?;
        let parsed = parse_owasp(&doc, &file[1..3])?;
        batch.entities.extend(parsed.entities);
    }
    cp["edition"] = json!("2025");
    cp["directory_provenance"] = directory.provenance(source);
    commit(db, source, batch, cp).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    fn document(bytes: Vec<u8>) -> Document {
        Document {
            sha256: format!("{:x}", Sha256::digest(&bytes)),
            bytes,
            url: "https://example.test/official-fixture".into(),
            fetched_at: "2026-01-01T00:00:00Z".into(),
        }
    }
    fn markdown() -> Document {
        document(b"# A01:2025 Fixture category ![icon](icon.png)\nCWE-999 is only prose.\n## List of Mapped CWEs\n* [CWE-79 Fixture](https://cwe.mitre.org/data/definitions/79.html)\n* [CWE-79 Fixture](https://cwe.mitre.org/data/definitions/79.html)\n## References\nCWE-888\n".to_vec())
    }
    #[test]
    fn mappings_use_only_explicit_section_and_keep_provenance() {
        let doc = markdown();
        let batch = parse_owasp(&doc, "01").unwrap();
        assert_eq!(batch.entities.len(), 2);
        let category = &batch.entities.last().unwrap().2;
        assert_eq!(category["cwes"], json!(["CWE-79"]));
        assert_eq!(category["name"], "Fixture category");
        assert_eq!(category["provenance"]["sha256"], doc.sha256);
        assert!(parse_owasp(&doc, "02").is_err());
        assert!(parse_owasp(&document(b"# A01:2025 No mappings".to_vec()), "01").is_err());
        let bad = document(
            String::from_utf8(doc.bytes)
                .unwrap()
                .replace("/79.html", "/89.html")
                .into_bytes(),
        );
        assert!(parse_owasp(&bad, "01").is_err());
    }
    #[test]
    fn directory_requires_ten_distinct_safe_filenames() {
        let mut rows: Vec<Value> = (1..=10)
            .map(|n| json!({"type":"file","name":format!("A{n:02}_2025-Fixture.md")}))
            .collect();
        assert_eq!(category_files(&json!(rows)).unwrap().len(), 10);
        rows.push(json!({"type":"file","name":"../../evil.md","download_url":"http://127.0.0.1"}));
        assert_eq!(category_files(&json!(rows)).unwrap().len(), 10);
        rows.push(rows[0].clone());
        assert!(category_files(&json!(rows)).is_err());
        assert!(category_files(&json!([])).is_err());
    }
    #[test]
    fn cwe_schema_errors_preserve_existing_snapshot() {
        let doc = document(serde_json::to_vec(&json!({"Weaknesses":[{"ID":"79","Name":"Fixture","PotentialMitigations":[{"Description":"Upstream advice"}]}]})).unwrap());
        let batch = parse_cwe(&doc).unwrap();
        assert_eq!(batch.replace_entity_kinds, vec!["weaknesses"]);
        assert_eq!(
            batch.entities[0].2["upstream"]["PotentialMitigations"][0]["Description"],
            "Upstream advice"
        );
        for value in [
            json!({}),
            json!({"Weaknesses":[]}),
            json!({"Weaknesses":[{"ID":"../../evil","Name":"Fixture"}]}),
            json!({"Weaknesses":[{"ID":"79"}]}),
        ] {
            assert!(parse_cwe(&document(serde_json::to_vec(&value).unwrap())).is_err());
        }
    }
    #[test]
    fn nvd_evidence_never_guesses_fixes_or_weaknesses() {
        let doc = document(Vec::new());
        let cve = json!({"weaknesses":[{"source":"nvd@nist.gov","type":"Primary","description":[{"value":"CWE-79"},{"value":"NVD-CWE-noinfo"},{"value":"CWE-79"}]}],"references":[
            {"url":"https://example.test/advisory","tags":["Vendor Advisory"]},
            {"url":"javascript:alert(1)","tags":["Patch"]},
            {"url":"https://example.test/fix","tags":["Patch"]}
        ]});
        let mut fields = json!({});
        let mut batch = Batch::default();
        nvd_evidence(&doc, &cve, "CVE-2099-1000", &mut fields, &mut batch);
        assert_eq!(fields["weaknesses"], json!(["CWE-79"]));
        assert_eq!(batch.entities.len(), 1);
        assert_eq!(fields["patch_links"].as_array().unwrap().len(), 1);
        assert_eq!(fields["patch_links"][0]["url"], "https://example.test/fix");
        let one = vi_core::merge_record(None, &json!({"id":"CVE-2099-1000","weaknesses":fields["weaknesses"],"patch_links":fields["patch_links"]})).unwrap();
        let two = vi_core::merge_record(
            Some(&one),
            &json!({"id":"CVE-2099-1000","weaknesses":["CWE-89"],"patch_links":[]}),
        )
        .unwrap();
        assert_eq!(two.weaknesses, vec!["CWE-79", "CWE-89"]);
        assert_eq!(two.patch_links.len(), 1);
        assert!(two.fixed_version.is_empty());
    }
    fn live_fetcher() -> Fetcher {
        let mut f = Fetcher::new().unwrap();
        f.cache = std::env::temp_dir().join(format!(
            "sentinel-knowledge-smoke-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        f
    }
    #[tokio::test]
    #[ignore = "Optional live check: fetches official CWE and OWASP documents without importing a database"]
    async fn official_knowledge_sources_smoke() {
        let f = live_fetcher();
        let cwe = f
            .get("https://cwe-api.mitre.org/api/v1/cwe/weakness/all", &[])
            .await
            .unwrap();
        assert!(!parse_cwe(&cwe).unwrap().entities.is_empty());
        check_owasp(&f).await;
        let _ = tokio::fs::remove_dir_all(&f.cache).await;
    }
    #[tokio::test]
    #[ignore = "Optional live check: fetches only official OWASP documents without importing a database"]
    async fn official_owasp_sources_smoke() {
        let f = live_fetcher();
        check_owasp(&f).await;
        let _ = tokio::fs::remove_dir_all(&f.cache).await;
    }
    async fn check_owasp(f: &Fetcher) {
        let directory = f
            .get(
                "https://api.github.com/repos/OWASP/Top10/contents/2025/docs/en?ref=master",
                &[],
            )
            .await
            .unwrap();
        for file in category_files(&directory.json().unwrap()).unwrap() {
            let doc = f.get(&format!("{OWASP_ROOT}{file}"), &[]).await.unwrap();
            assert!(!parse_owasp(&doc, &file[1..3]).unwrap().entities.is_empty());
        }
    }
}

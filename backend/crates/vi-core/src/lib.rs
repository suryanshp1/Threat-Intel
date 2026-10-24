use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Clone, Debug, Default, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(default)]
pub struct Vulnerability {
    pub id: String,
    pub title: String,
    pub description: String,
    pub vendor: String,
    pub product: String,
    pub ecosystem: String,
    pub purl: String,
    pub affected_version: String,
    pub fixed_version: String,
    pub cvss: f64,
    pub epss_score: f64,
    pub seen_wild: bool,
    pub exploit_available: bool,
    pub weaponized: bool,
    pub patch_available: bool,
    pub is_zeroday: bool,
    pub known_ransomware_use: bool,
    pub automatable: bool,
    pub total_impact: bool,
    pub bod_26_04_forensic_triage: bool,
    pub supply: u16,
    pub actors: Vec<String>,
    pub tags: Vec<String>,
    pub published: String,
    pub sources: Vec<String>,
    pub priority_score: u16,
    pub ssvc_decision: String,
    pub score_breakdown: Value,
    pub aliases: Vec<String>,
    pub cvss_known: bool,
    pub cvss_vector: Option<String>,
    pub epss_known: bool,
    pub cpe: Vec<String>,
    pub references: Vec<Value>,
    pub weaknesses: Vec<String>,
    pub weakness_evidence: Vec<Value>,
    pub patch_links: Vec<Value>,
    pub remediation_evidence: Vec<Value>,
    pub source_assertions: Vec<Value>,
    pub poc_references: Vec<Value>,
    pub provenance: Vec<Value>,
    pub affected: Vec<Value>,
    pub cisa_date_added: Option<String>,
    pub cisa_due_date: Option<String>,
    pub remediation: Option<String>,
    pub last_modified: String,
    pub ingested_at: String,
    pub patch_status: String,
    pub ssvc: Value,
    pub malicious: bool,
}
impl Vulnerability {
    pub fn score(&mut self) {
        let exploit = if self.seen_wild {
            350.0
        } else if self.weaponized {
            240.0
        } else if self.exploit_available {
            150.0
        } else {
            0.0
        };
        let epss = 250.0 * self.epss_score.clamp(0.0, 1.0).powf(0.75);
        let severity = 15.0 * self.cvss.clamp(0.0, 10.0)
            + if self.automatable { 30.0 } else { 0.0 }
            + if self.patch_status == "unavailable" {
                20.0
            } else {
                0.0
            };
        let threat = if self.known_ransomware_use { 75.0 } else { 0.0 }
            + if self.actors.is_empty() { 0.0 } else { 45.0 }
            + if self.bod_26_04_forensic_triage {
                30.0
            } else {
                0.0
            };
        let supply = self.supply.min(50) as f64;
        self.priority_score = (exploit + epss + severity + threat + supply)
            .round()
            .clamp(0.0, 1000.0) as u16;
        // Never invent an SSVC decision from incomplete organizational inputs.
        if self.ssvc_decision.is_empty() {
            self.ssvc_decision = "Unassessed".into();
        }
        self.score_breakdown = json!({"exploitation":exploit,"epss":epss,"severity":severity,"threat":threat,"supply_chain":supply,"vex_multiplier":1,"method":"PRD additive formula; unknown signals contribute zero","unknown_signals":{"cvss":!self.cvss_known,"epss":!self.epss_known,"patch":self.patch_status.is_empty()||self.patch_status=="unknown"}});
    }
}
#[derive(Clone, Serialize, Deserialize, Default)]
pub struct Store {
    pub vulnerabilities: Vec<Vulnerability>,
    pub actors: Vec<Value>,
    pub ransomware: Vec<Value>,
    pub patches: Vec<Value>,
    pub vex: Vec<Value>,
    pub checkpoints: Vec<Value>,
    #[serde(default)]
    pub rules: Vec<Value>,
    #[serde(default)]
    pub relationships: Vec<Value>,
    #[serde(default)]
    pub products: Vec<Value>,
    #[serde(default)]
    pub revision: u64,
    #[serde(default)]
    pub revoked_sessions: Vec<Value>,
    #[serde(default)]
    pub weaknesses: Vec<Value>,
    #[serde(default)]
    pub categories: Vec<Value>,
}
pub const JUSTIFICATIONS: [&str; 5] = [
    "component_not_present",
    "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
];

pub fn package_base(purl: &str) -> &str {
    let no_qualifiers = purl.split(['?', '#']).next().unwrap_or(purl);
    match no_qualifiers.rfind('@') {
        Some(i) if i > no_qualifiers.rfind('/').unwrap_or(4) => &no_qualifiers[..i],
        _ => no_qualifiers,
    }
}
pub fn package_version(purl: &str) -> Option<&str> {
    let purl = purl.split(['?', '#']).next()?;
    let i = purl.rfind('@')?;
    (i > purl.rfind('/').unwrap_or(4)).then_some(&purl[i + 1..])
}
pub fn version_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    let parts = |v: &str| {
        v.trim_start_matches('v')
            .split(['.', '-', '+'])
            .map(|p| p.parse::<u64>().unwrap_or(0))
            .collect::<Vec<_>>()
    };
    let (mut a, mut b) = (parts(a), parts(b));
    let len = a.len().max(b.len());
    a.resize(len, 0);
    b.resize(len, 0);
    a.cmp(&b)
}
pub fn matches_package(v: &Vulnerability, purl: &str) -> bool {
    if package_base(&v.purl) != package_base(purl) {
        return false;
    }
    let Some(version) = package_version(purl) else {
        return false;
    };
    if !numeric_version(version) {
        return false;
    }
    // Seed ranges use >=lower,<upper. Unknown range formats are never silently matched.
    v.affected_version.split(',').all(|part| {
        let part = part.trim();
        if let Some(n) = part.strip_prefix(">=") {
            numeric_version(n) && version_cmp(version, n).is_ge()
        } else if let Some(n) = part.strip_prefix('<') {
            numeric_version(n) && version_cmp(version, n).is_lt()
        } else {
            version == part
        }
    })
}
fn numeric_version(v: &str) -> bool {
    !v.is_empty()
        && v.split('.')
            .all(|p| !p.is_empty() && p.parse::<u64>().is_ok())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Vulnerability {
        Vulnerability {
            id: "CVE-2099-1000".into(),
            purl: "pkg:generic/test".into(),
            affected_version: ">=7.0.0,<7.0.17".into(),
            fixed_version: "7.0.17".into(),
            ..Default::default()
        }
    }
    #[test]
    fn formula_does_not_copy_incorrect_prd_example() {
        let mut v = fixture();
        v.seen_wild = true;
        v.epss_score = 0.9415;
        v.cvss = 9.8;
        v.automatable = true;
        v.patch_available = true;
        v.known_ransomware_use = true;
        v.bod_26_04_forensic_triage = false;
        v.supply = 13;
        v.actors = vec!["example".into()];
        v.patch_status = "available".into();
        v.score();
        assert_eq!(v.priority_score, 899);
    }
    #[test]
    fn package_matching_is_version_scoped() {
        let v = fixture();
        assert!(matches_package(
            &v,
            &format!("{}@{}", package_base(&v.purl), "7.0.1")
        ));
        assert!(!matches_package(
            &v,
            &format!("{}@{}", package_base(&v.purl), v.fixed_version)
        ));
        assert!(!matches_package(&v, package_base(&v.purl)));
    }
    #[test]
    fn unsupported_versions_never_create_findings() {
        let v = fixture();
        for version in ["garbage", "7.0.1-beta", "7..1", ""] {
            assert!(!matches_package(&v, &format!("{}@{}", v.purl, version)));
        }
    }
    #[test]
    fn scoped_npm_identifiers_preserve_namespace() {
        assert_eq!(
            package_base("pkg:npm/@scope/pkg@1.2.0"),
            "pkg:npm/@scope/pkg"
        );
    }
}

pub const SOURCES: &[(&str, u64)] = &[
    ("CISA KEV", 86400),
    ("NVD 2.0", 7200),
    ("CVE List V5", 300),
    ("Debian Security Tracker", 86400),
    ("Ubuntu USN", 3600),
    ("Trickest PoC references", 600),
    ("FIRST EPSS", 86400),
    ("CISA Vulnrichment", 3600),
    ("OSV / GHSA", 3600),
    ("MITRE ATT&CK", 604800),
    ("MITRE CWE", 604800),
    ("OWASP Top 10", 604800),
    ("RansomLook", 3600),
    ("Microsoft MSRC", 86400),
    ("Apache HTTP Server", 86400),
    ("Apache Tomcat", 86400),
    ("OpenSSL", 86400),
    ("curl", 86400),
    ("Nuclei", 21600),
    ("Sigma", 86400),
    ("Suricata", 86400),
    ("Vendor CSAF / OpenVEX", 86400),
];
pub fn empty_store() -> Store {
    Store{checkpoints:SOURCES.iter().map(|(name,cadence)|json!({"source_name":name,"status":"Pending","interval_seconds":cadence,"last_success_at":null,"consecutive_failures":0,"records":0})).collect(),..Default::default()}
}
/// Apply a source-owned patch. Unknown or absent upstream fields never erase other sources.
pub fn merge_record(
    existing: Option<&Vulnerability>,
    patch: &Value,
) -> Result<Vulnerability, String> {
    let mut value = existing
        .map(|v| serde_json::to_value(v).unwrap())
        .unwrap_or_else(|| json!({}));
    let object = value.as_object_mut().unwrap();
    for (key, item) in patch.as_object().ok_or("Record patch must be an object")? {
        // CNA assertions remain independently inspectable. A supplemental publisher
        // record fills missing display fields without replacing other sources.
        if patch["sources"] == json!(["CVE List V5"])
            && [
                "title",
                "description",
                "published",
                "vendor",
                "product",
                "cvss",
                "cvss_known",
                "cvss_vector",
            ]
            .contains(&key.as_str())
            && existing.is_some_and(|v| match key.as_str() {
                "cvss" | "cvss_known" | "cvss_vector" => v.cvss_known,
                _ => object
                    .get(key)
                    .and_then(Value::as_str)
                    .is_some_and(|s| !s.is_empty()),
            })
        {
            continue;
        }
        if (key == "patch_status"
            && item == "unknown"
            && object.get(key).is_some_and(|v| v == "available"))
            || (key == "patch_available" && item == false && object.get(key) == Some(&json!(true)))
        {
            continue;
        }
        if [
            "sources",
            "provenance",
            "references",
            "weaknesses",
            "weakness_evidence",
            "patch_links",
            "remediation_evidence",
            "source_assertions",
            "poc_references",
            "aliases",
            "cpe",
            "actors",
            "affected",
        ]
        .contains(&key.as_str())
        {
            let array = object.entry(key.clone()).or_insert(json!([]));
            if let Some(items) = item.as_array() {
                let dst = array.as_array_mut().ok_or("Invalid array field")?;
                for v in items {
                    if [
                        "source_assertions",
                        "poc_references",
                        "remediation_evidence",
                    ]
                    .contains(&key.as_str())
                        && dst.iter().any(|old| same_assertion(old, v))
                    {
                        continue;
                    }
                    if !dst.contains(v) {
                        dst.push(v.clone())
                    }
                }
            }
        } else if !item.is_null() {
            object.insert(key.clone(), item.clone());
        }
    }
    let mut record: Vulnerability = serde_json::from_value(value).map_err(|e| e.to_string())?;
    if !valid_cve(&record.id)
        || !record.cvss.is_finite()
        || !(0.0..=10.0).contains(&record.cvss)
        || !record.epss_score.is_finite()
        || !(0.0..=1.0).contains(&record.epss_score)
    {
        return Err("Invalid CVE identifier".into());
    }
    record.score();
    Ok(record)
}

// Page hashes and retrieval times change even when a specific advisory assertion
// does not. Keep its first observation, and retain all fetched documents separately
// in the record-level provenance. Changed content still creates a history entry.
fn same_assertion(a: &Value, b: &Value) -> bool {
    match (a.as_object(), b.as_object()) {
        (Some(a), Some(b)) => {
            a.keys().filter(|k| k.as_str() != "provenance").count()
                == b.keys().filter(|k| k.as_str() != "provenance").count()
                && a.iter()
                    .filter(|(k, _)| k.as_str() != "provenance")
                    .all(|(k, value)| b.get(k) == Some(value))
        }
        _ => a == b,
    }
}

pub fn valid_cve(id: &str) -> bool {
    let p: Vec<_> = id.split('-').collect();
    p.len() == 3
        && p[0] == "CVE"
        && p[1].len() == 4
        && p[1].chars().all(|c| c.is_ascii_digit())
        && p[2].len() >= 4
        && p[2].chars().all(|c| c.is_ascii_digit())
}
#[cfg(test)]
mod production_tests {
    use super::*;
    #[test]
    fn empty_install_never_injects_sample_intelligence() {
        let s = empty_store();
        assert!(
            s.vulnerabilities.is_empty()
                && s.actors.is_empty()
                && s.ransomware.is_empty()
                && s.patches.is_empty()
        );
        assert_eq!(s.checkpoints.len(), SOURCES.len());
    }
    #[test]
    fn enrichment_merges_sources_without_erasing_evidence() {
        let first=merge_record(None,&json!({"id":"CVE-2099-1000","seen_wild":true,"patch_available":true,"patch_status":"available","sources":["CISA KEV"],"provenance":[{"source":"CISA KEV"}]})).unwrap();
        let next=merge_record(Some(&first),&json!({"id":"CVE-2099-1000","epss_known":true,"epss_score":0.9,"sources":["FIRST EPSS"],"patch_available":false,"patch_status":"unknown"})).unwrap();
        assert!(next.seen_wild && next.patch_available && next.epss_known);
        assert_eq!(next.patch_status, "available");
        assert_eq!(next.sources.len(), 2);
    }
    #[test]
    fn scoped_unversioned_purl_is_not_a_version() {
        assert_eq!(package_base("pkg:npm/@scope/name"), "pkg:npm/@scope/name");
        assert_eq!(package_version("pkg:npm/@scope/name"), None);
    }
    #[test]
    fn invalid_probability_is_rejected() {
        assert!(merge_record(None, &json!({"id":"CVE-2099-1000","epss_score":2.0})).is_err());
        assert!(merge_record(None, &json!({"id":"CVE-invalid"})).is_err());
    }
}

/// Shared request-cost bounds for REST, GraphQL, MCP and direct database callers.
pub fn validate_query(value: &Value) -> Result<(), String> {
    if value["text_search"].as_str().is_some_and(|s| s.len() > 512)
        || value["cursor"].as_str().is_some_and(|s| s.len() > 4096)
        || value["conditions"].as_array().is_some_and(|a| a.len() > 30)
        || value["limit"].as_u64().is_some_and(|n| n == 0 || n > 100)
    {
        return Err("Query exceeds input limits".into());
    }
    for condition in value["conditions"].as_array().unwrap_or(&vec![]) {
        let item = &condition["value"];
        if item.as_str().is_some_and(|s| s.len() > 512)
            || item.as_array().is_some_and(|a| {
                a.len() > 100 || a.iter().any(|v| v.as_str().is_some_and(|s| s.len() > 512))
            })
        {
            return Err("Query exceeds input limits".into());
        }
    }
    Ok(())
}
#[cfg(test)]
mod budget_tests {
    use super::*;
    #[test]
    fn query_budgets_cover_arrays_and_text() {
        assert!(validate_query(&json!({"conditions":vec![json!({"value":0});31]})).is_err());
        assert!(validate_query(&json!({"conditions":[{"value":vec!["x";101]}]})).is_err());
        assert!(validate_query(&json!({"text_search":"x".repeat(513)})).is_err());
        assert!(validate_query(&json!({"limit":101})).is_err());
        assert!(validate_query(&json!({"limit":100,"text_search":"x".repeat(512)})).is_ok());
    }
}

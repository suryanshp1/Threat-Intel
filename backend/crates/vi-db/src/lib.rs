use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use deadpool_postgres::Pool;
mod identity;
mod tls;
use serde_json::{json, Value};
use std::{path::PathBuf, sync::Arc};
use tokio::sync::OnceCell;
use tokio_postgres::types::ToSql;
use vi_core::{empty_store, merge_record, Store, Vulnerability};

#[derive(Clone)]
pub struct Database {
    path: PathBuf,
    url: Option<String>,
    pool: Arc<OnceCell<Pool>>,
    owner: Arc<String>,
}
#[derive(Default)]
pub struct Batch {
    pub vulnerabilities: Vec<Value>,
    pub entities: Vec<(String, String, Value)>,
    /// Atomically replace these entity kinds for this source after a complete import.
    pub replace_entity_kinds: Vec<String>,
}
impl Database {
    pub fn new() -> Self {
        Self {
            path: std::env::var("VI_DATA_PATH")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("backend/data/intelligence.json")),
            url: std::env::var("DATABASE_URL").ok(),
            pool: Default::default(),
            owner: Arc::new(uuid::Uuid::new_v4().to_string()),
        }
    }
    pub fn persistent(&self) -> bool {
        self.url.is_some()
    }
    async fn client(&self) -> Result<deadpool_postgres::Object, String> {
        let pool = self
            .pool
            .get_or_try_init(|| async {
                let config: tokio_postgres::Config = self
                    .url
                    .as_deref()
                    .ok_or("DATABASE_URL is required")?
                    .parse()
                    .map_err(|e: tokio_postgres::Error| e.to_string())?;
                Pool::builder(tls::manager(config)?)
                    .max_size(16)
                    .build()
                    .map_err(|e| e.to_string())
            })
            .await?;
        tokio::time::timeout(std::time::Duration::from_secs(10), pool.get())
            .await
            .map_err(|_| "Database pool timeout".to_string())?
            .map_err(|e| e.to_string())
    }
    pub async fn initialize(&self) -> Result<(), String> {
        if self.persistent() {
            let mut client = self.client().await?;
            let transaction = client.transaction().await.map_err(|e| format!("{e:?}"))?;
            transaction
                .query_one("SELECT pg_advisory_xact_lock(739174981)", &[])
                .await
                .map_err(|e| format!("{e:?}"))?;
            transaction
                .batch_execute(include_str!(
                    "../../../migrations/0002_source_backed_intelligence.sql"
                ))
                .await
                .map_err(|e| format!("{e:?}"))?;
            transaction
                .batch_execute(include_str!(
                    "../../../migrations/0003_knowledge_sources.sql"
                ))
                .await
                .map_err(|e| format!("{e:?}"))?;
            transaction
                .batch_execute(include_str!(
                    "../../../migrations/0004_security_controls.sql"
                ))
                .await
                .map_err(|e| format!("{e:?}"))?;
            transaction
                .batch_execute(include_str!("../../../migrations/0005_identity_audit.sql"))
                .await
                .map_err(|e| format!("{e:?}"))?;
            transaction.commit().await.map_err(|e| format!("{e:?}"))?;
            for cp in empty_store().checkpoints {
                client.execute("INSERT INTO ingestion_checkpoints(source_name,data) VALUES($1,$2) ON CONFLICT DO NOTHING",&[&cp["source_name"].as_str().unwrap(),&cp]).await.map_err(|e|e.to_string())?;
            }
        } else if std::env::var("VI_ENV").as_deref() == Ok("production") {
            return Err("Production requires PostgreSQL DATABASE_URL".into());
        }
        Ok(())
    }
    pub async fn revoke_session(&self, hash: &str) -> Result<(), String> {
        let expires = chrono::Utc::now() + chrono::Duration::hours(8);
        if !self.persistent() {
            return self.file_update(|s| {
                s.revoked_sessions.retain(|r| {
                    r["expires_at"]
                        .as_str()
                        .and_then(|v| chrono::DateTime::parse_from_rfc3339(v).ok())
                        .is_some_and(|t| t > chrono::Utc::now())
                });
                if !s.revoked_sessions.iter().any(|r| r["hash"] == hash) {
                    s.revoked_sessions
                        .push(json!({"hash":hash,"expires_at":expires.to_rfc3339()}));
                }
                Ok(())
            });
        }
        let mut c = self.client().await?;
        let tx = c.transaction().await.map_err(|e| e.to_string())?;
        tx.execute(
            "DELETE FROM session_revocations WHERE expires_at<=now()",
            &[],
        )
        .await
        .map_err(|e| e.to_string())?;
        tx.execute("INSERT INTO session_revocations(session_hash,expires_at) VALUES($1,now()+interval '8 hours') ON CONFLICT(session_hash) DO UPDATE SET expires_at=excluded.expires_at", &[&hash]).await.map_err(|e|e.to_string())?;
        tx.commit().await.map_err(|e| e.to_string())
    }
    pub async fn session_revoked(&self, hash: &str) -> Result<bool, String> {
        if !self.persistent() {
            return Ok(self.file_read()?.revoked_sessions.iter().any(|r| {
                r["hash"] == hash
                    && r["expires_at"]
                        .as_str()
                        .and_then(|v| chrono::DateTime::parse_from_rfc3339(v).ok())
                        .is_some_and(|t| t > chrono::Utc::now())
            }));
        }
        Ok(self
            .client()
            .await?
            .query_opt(
                "SELECT 1 FROM session_revocations WHERE session_hash=$1 AND expires_at>now()",
                &[&hash],
            )
            .await
            .map_err(|e| e.to_string())?
            .is_some())
    }
    pub async fn ready(&self) -> bool {
        if self.persistent() {
            match self.client().await {
                Ok(c) => c.simple_query("SELECT 1").await.is_ok(),
                Err(_) => false,
            }
        } else {
            true
        }
    }
    pub async fn load(&self) -> Result<Store, String> {
        if !self.persistent() {
            return self.file_read();
        }
        let c = self.client().await?;
        let mut store = empty_store();
        for row in c
            .query(
                "SELECT data FROM vulnerabilities ORDER BY priority_score DESC,id DESC",
                &[],
            )
            .await
            .map_err(|e| format!("{e:?}"))?
        {
            store
                .vulnerabilities
                .push(serde_json::from_value(row.get(0)).map_err(|e| format!("{e:?}"))?)
        }
        for row in c
            .query(
                "SELECT kind,data FROM intelligence_entities ORDER BY id",
                &[],
            )
            .await
            .map_err(|e| format!("{e:?}"))?
        {
            let kind: String = row.get(0);
            entities_mut(&mut store, &kind)?.push(row.get(1));
        }
        store.checkpoints = self.checkpoints().await?;
        store.vex = self.vex().await?;
        store.revision = self.revision().await?;
        Ok(store)
    }
    fn file_read(&self) -> Result<Store, String> {
        if !self.path.exists() {
            return Ok(empty_store());
        }
        let mut store: Store =
            serde_json::from_slice(&std::fs::read(&self.path).map_err(|e| format!("{e:?}"))?)
                .map_err(|e| format!("{e:?}"))?;
        store
            .vulnerabilities
            .retain(|v| !v.sources.iter().any(|s| s.to_lowercase().contains("demo")));
        store.actors.retain(|v| v["demo"] != true);
        store.ransomware.retain(|v| v["demo"] != true);
        Ok(store)
    }
    fn file_update<T>(&self, f: impl FnOnce(&mut Store) -> Result<T, String>) -> Result<T, String> {
        use fs2::FileExt;
        if let Some(p) = self.path.parent() {
            std::fs::create_dir_all(p).map_err(|e| format!("{e:?}"))?;
        }
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(self.path.with_extension("lock"))
            .map_err(|e| format!("{e:?}"))?;
        lock.lock_exclusive().map_err(|e| format!("{e:?}"))?;
        let mut store = self.file_read()?;
        let result = f(&mut store)?;
        store.revision += 1;
        let tmp = self
            .path
            .with_extension(format!("{}.tmp", std::process::id()));
        let mut out = std::fs::File::create(&tmp).map_err(|e| format!("{e:?}"))?;
        std::io::Write::write_all(
            &mut out,
            &serde_json::to_vec(&store).map_err(|e| format!("{e:?}"))?,
        )
        .map_err(|e| format!("{e:?}"))?;
        out.sync_all().map_err(|e| format!("{e:?}"))?;
        std::fs::rename(tmp, &self.path).map_err(|e| format!("{e:?}"))?;
        Ok(result)
    }
    pub async fn revision(&self) -> Result<u64, String> {
        if !self.persistent() {
            return Ok(self.file_read()?.revision);
        }
        let c = self.client().await?;
        Ok(
            c.query_one("SELECT revision FROM system_state WHERE id=1", &[])
                .await
                .map_err(|e| format!("{e:?}"))?
                .get::<_, i64>(0) as u64,
        )
    }
    pub async fn apply(
        &self,
        source: &str,
        mut batch: Batch,
        checkpoint: Value,
    ) -> Result<usize, String> {
        batch
            .vulnerabilities
            .sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
        batch
            .entities
            .sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));
        let mut combined = std::collections::BTreeMap::<(String, String), Value>::new();
        for (kind, id, mut data) in std::mem::take(&mut batch.entities) {
            if kind == "patches" {
                if let Some(previous) = combined.get(&(kind.clone(), id.clone())) {
                    let mut cves = previous["cves"].as_array().cloned().unwrap_or_default();
                    for cve in data["cves"].as_array().unwrap_or(&vec![]) {
                        if !cves.contains(cve) {
                            cves.push(cve.clone())
                        }
                    }
                    data["cves"] = json!(cves);
                }
            }
            combined.insert((kind, id), data);
        }
        batch.entities = combined
            .into_iter()
            .map(|((kind, id), data)| (kind, id, data))
            .collect();
        let count = batch.vulnerabilities.len() + batch.entities.len();
        if !self.persistent() {
            return self.file_update(|s| {
                for patch in batch.vulnerabilities {
                    let id = patch["id"].as_str().ok_or("Missing CVE ID")?;
                    let existing = s.vulnerabilities.iter().position(|v| v.id == id);
                    let record = merge_record(existing.map(|i| &s.vulnerabilities[i]), &patch)?;
                    if let Some(i) = existing {
                        s.vulnerabilities[i] = record
                    } else {
                        s.vulnerabilities.push(record)
                    }
                }
                for kind in &batch.replace_entity_kinds {
                    entities_mut(s, kind)?.retain(|v| v["source"] != source);
                }
                for (kind, id, data) in batch.entities {
                    let rows = entities_mut(s, &kind)?;
                    if let Some(i) = rows
                        .iter()
                        .position(|v| v["id"] == id && v["source"] == source)
                    {
                        rows[i] = data
                    } else {
                        rows.push(data)
                    }
                }
                set_checkpoint(s, source, checkpoint);
                Ok(count)
            });
        }
        let mut c = self.client().await?;
        let tx = c.transaction().await.map_err(|e| format!("{e:?}"))?;
        for patch in batch.vulnerabilities {
            let id = patch["id"].as_str().ok_or("Missing CVE ID")?;
            tx.query_one(
                "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
                &[&id],
            )
            .await
            .map_err(|e| format!("{e:?}"))?;
            let old = tx
                .query_opt(
                    "SELECT data FROM vulnerabilities WHERE id=$1 FOR UPDATE",
                    &[&id],
                )
                .await
                .map_err(|e| format!("{e:?}"))?
                .map(|r| serde_json::from_value::<Vulnerability>(r.get(0)))
                .transpose()
                .map_err(|e| format!("{e:?}"))?;
            let v = merge_record(old.as_ref(), &patch)?;
            let data = serde_json::to_value(&v).map_err(|e| format!("{e:?}"))?;
            tx.execute("INSERT INTO vulnerabilities(id,data,priority_score,cvss,epss_score,published,ssvc_decision,seen_wild,is_zeroday,ecosystem,vendor) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT(id) DO UPDATE SET data=excluded.data,priority_score=excluded.priority_score,cvss=excluded.cvss,epss_score=excluded.epss_score,published=excluded.published,ssvc_decision=excluded.ssvc_decision,seen_wild=excluded.seen_wild,is_zeroday=excluded.is_zeroday,ecosystem=excluded.ecosystem,vendor=excluded.vendor,updated_at=now()",&[&v.id,&data,&(v.priority_score as i16),&v.cvss,&v.epss_score,&v.published,&v.ssvc_decision,&v.seen_wild,&v.is_zeroday,&v.ecosystem,&v.vendor]).await.map_err(|e|e.to_string())?;
        }
        for kind in &batch.replace_entity_kinds {
            tx.execute(
                "DELETE FROM intelligence_entities WHERE source=$1 AND kind=$2",
                &[&source, &kind],
            )
            .await
            .map_err(|e| e.to_string())?;
        }
        for (kind, id, data) in batch.entities {
            tx.execute("INSERT INTO intelligence_entities(kind,id,source,data) VALUES($1,$2,$3,$4) ON CONFLICT(kind,id,source) DO UPDATE SET data=CASE WHEN excluded.kind='patches' THEN excluded.data || jsonb_build_object('cves',(SELECT jsonb_agg(DISTINCT x) FROM jsonb_array_elements(COALESCE(intelligence_entities.data->'cves','[]'::jsonb)||COALESCE(excluded.data->'cves','[]'::jsonb)) x)) ELSE excluded.data END,updated_at=now()",&[&kind,&id,&source,&data]).await.map_err(|e|e.to_string())?;
        }
        tx.execute("INSERT INTO ingestion_checkpoints(source_name,data) VALUES($1,$2) ON CONFLICT(source_name) DO UPDATE SET data=excluded.data,updated_at=now(),lease_until=CASE WHEN ingestion_checkpoints.lease_until IS NOT NULL THEN now()+interval '15 minutes' ELSE NULL END",&[&source,&checkpoint]).await.map_err(|e|e.to_string())?;
        tx.execute(
            "UPDATE system_state SET revision=revision+1 WHERE id=1",
            &[],
        )
        .await
        .map_err(|e| format!("{e:?}"))?;
        tx.commit().await.map_err(|e| format!("{e:?}"))?;
        Ok(count)
    }
    pub async fn checkpoints(&self) -> Result<Vec<Value>, String> {
        if !self.persistent() {
            return Ok(self.file_read()?.checkpoints);
        }
        let c = self.client().await?;
        Ok(c.query(
            "SELECT data FROM ingestion_checkpoints ORDER BY source_name",
            &[],
        )
        .await
        .map_err(|e| format!("{e:?}"))?
        .iter()
        .map(|r| r.get(0))
        .collect())
    }
    pub async fn save_checkpoint(&self, source: &str, cp: Value) -> Result<(), String> {
        self.apply(source, Batch::default(), cp).await?;
        Ok(())
    }
    pub async fn claim(&self, source: &str) -> Result<bool, String> {
        if !self.persistent() {
            return Ok(true);
        }
        let c = self.client().await?;
        Ok(c.execute("UPDATE ingestion_checkpoints SET lease_until=now()+interval '15 minutes',lease_owner=$2 WHERE source_name=$1 AND (lease_until IS NULL OR lease_until<now())",&[&source,&self.owner.as_str()]).await.map_err(|e|e.to_string())?==1)
    }
    pub async fn release(&self, source: &str) -> Result<(), String> {
        if self.persistent() {
            self.client()
                .await?
                .execute(
                    "UPDATE ingestion_checkpoints SET lease_until=NULL,lease_owner=NULL WHERE source_name=$1 AND lease_owner=$2",
                    &[&source,&self.owner.as_str()],
                )
                .await
                .map_err(|e| format!("{e:?}"))?;
        }
        Ok(())
    }
    pub async fn interrupt(&self, source: &str) -> Result<(), String> {
        if self.persistent() {
            self.client().await?.execute("UPDATE ingestion_checkpoints SET lease_until=NULL,lease_owner=NULL,data=data||jsonb_build_object('status','Pending','interrupted_at',now()::text) WHERE source_name=$1 AND lease_owner=$2",&[&source,&self.owner.as_str()]).await.map_err(|e|format!("{e:?}"))?;
        }
        Ok(())
    }
    pub async fn ids(&self) -> Result<Vec<String>, String> {
        if !self.persistent() {
            return Ok(self
                .file_read()?
                .vulnerabilities
                .into_iter()
                .map(|v| v.id)
                .collect());
        }
        Ok(self
            .client()
            .await?
            .query("SELECT id FROM vulnerabilities ORDER BY id", &[])
            .await
            .map_err(|e| format!("{e:?}"))?
            .iter()
            .map(|r| r.get(0))
            .collect())
    }
    /// Bounded keyset scan for catalog-scoped enrichment workers.
    pub async fn ids_after(&self, after: &str, limit: usize) -> Result<Vec<String>, String> {
        if limit == 0 || limit > 100 {
            return Err("ID page limit must be between 1 and 100".into());
        }
        if !self.persistent() {
            let mut ids: Vec<_> = self
                .file_read()?
                .vulnerabilities
                .into_iter()
                .map(|v| v.id)
                .filter(|id| id.as_str() > after)
                .collect();
            ids.sort();
            ids.truncate(limit);
            return Ok(ids);
        }
        Ok(self
            .client()
            .await?
            .query(
                "SELECT id FROM vulnerabilities WHERE id > $1 ORDER BY id LIMIT $2",
                &[&after, &(limit as i64)],
            )
            .await
            .map_err(|e| e.to_string())?
            .iter()
            .map(|r| r.get(0))
            .collect())
    }
    pub async fn get(&self, id: &str) -> Result<Option<Vulnerability>, String> {
        if !self.persistent() {
            return Ok(self
                .file_read()?
                .vulnerabilities
                .into_iter()
                .find(|v| v.id == id || v.aliases.iter().any(|a| a == id)));
        }
        self.client()
            .await?
            .query_opt(
                "SELECT data FROM vulnerabilities WHERE id=$1 OR data->'aliases' ? $1 LIMIT 1",
                &[&id],
            )
            .await
            .map_err(|e| format!("{e:?}"))?
            .map(|r| serde_json::from_value(r.get(0)).map_err(|e| e.to_string()))
            .transpose()
    }
    pub async fn knowledge(&self, id: &str) -> Result<Option<Value>, String> {
        if !self.persistent() {
            let store = self.file_read()?;
            return Ok(store
                .weaknesses
                .into_iter()
                .chain(store.categories)
                .find(|v| v["id"] == id));
        }
        Ok(self.client().await?.query_opt(
            "SELECT data FROM intelligence_entities WHERE kind IN ('weaknesses','categories') AND id=$1 ORDER BY source LIMIT 1",
            &[&id],
        ).await.map_err(|e| e.to_string())?.map(|r| r.get(0)))
    }
    pub async fn entity_page(&self, kinds: &[&str], q: &Value) -> Result<Value, String> {
        let name = q["name"].as_str().unwrap_or("").to_lowercase();
        let cve = q["cve"].as_str();
        let ecosystem = q["ecosystem"].as_str().unwrap_or("");
        let limit = q["limit"].as_u64().unwrap_or(100).clamp(1, 100) as usize;
        let skip = q["skip"].as_u64().unwrap_or(0).min(10000) as usize;
        if !self.persistent() {
            let mut store = self.file_read()?;
            let mut rows = Vec::new();
            for kind in kinds {
                rows.extend(entities_mut(&mut store, kind)?.clone());
            }
            rows.retain(|v| {
                v["id"]
                    .as_str()
                    .or_else(|| v["name"].as_str())
                    .unwrap_or("")
                    .to_lowercase()
                    .contains(&name)
                    && (ecosystem.is_empty() || v["ecosystem"] == ecosystem)
                    && cve.is_none_or(|id| {
                        v["cves_exploited"]
                            .as_array()
                            .is_some_and(|a| a.contains(&json!(id)))
                    })
            });
            rows.sort_by_key(|v| {
                (
                    v["id"].as_str().unwrap_or("").to_string(),
                    v["source"].as_str().unwrap_or("").to_string(),
                )
            });
            let total = rows.len();
            return Ok(
                json!({"results":rows.into_iter().skip(skip).take(limit).collect::<Vec<_>>(),"total":total}),
            );
        }
        let kinds: Vec<String> = kinds.iter().map(|s| s.to_string()).collect();
        let c = self.client().await?;
        let predicate="kind=ANY($1) AND strpos(lower(COALESCE(data->>'id',data->>'name','')),$2)>0 AND ($3::text IS NULL OR data->'cves_exploited' ? $3) AND ($4='' OR data->>'ecosystem'=$4)";
        let total: i64 = c
            .query_one(
                &format!("SELECT count(*) FROM intelligence_entities WHERE {predicate}"),
                &[&kinds, &name, &cve, &ecosystem],
            )
            .await
            .map_err(|e| e.to_string())?
            .get(0);
        let rows:Vec<Value>=c.query(&format!("SELECT data FROM intelligence_entities WHERE {predicate} ORDER BY id,source LIMIT $5 OFFSET $6"),&[&kinds,&name,&cve,&ecosystem,&(limit as i64),&(skip as i64)]).await.map_err(|e|e.to_string())?.iter().map(|r|r.get(0)).collect();
        Ok(json!({"results":rows,"total":total}))
    }
    pub async fn product_page(&self, q: &Value) -> Result<Value, String> {
        let name = q["name"].as_str().unwrap_or("").to_lowercase();
        let ecosystem = q["ecosystem"].as_str().unwrap_or("");
        let limit = q["limit"].as_u64().unwrap_or(100).clamp(1, 100) as i64;
        let skip = q["skip"].as_u64().unwrap_or(0).min(10000) as i64;
        if !self.persistent() {
            let store = self.file_read()?;
            let mut rows = store.products;
            for v in store.vulnerabilities {
                if !v.purl.is_empty() || !v.cpe.is_empty() {
                    rows.push(json!({"name":v.product,"vendor":v.vendor,"ecosystem":v.ecosystem,"purl":v.purl,"cpe":v.cpe.first().cloned().unwrap_or_default(),"affected_version_range":v.affected_version,"fixed_version":v.fixed_version,"cve_id":v.id,"priority_score":v.priority_score,"is_malicious_package":v.malicious,"provenance":v.provenance}));
                }
            }
            rows.retain(|v| {
                (ecosystem.is_empty() || v["ecosystem"] == ecosystem)
                    && format!("{} {} {} {}", v["name"], v["vendor"], v["purl"], v["cpe"])
                        .to_lowercase()
                        .contains(&name)
            });
            let mut seen = std::collections::HashSet::new();
            rows.retain(|v| seen.insert(format!("{}:{}", v["cve_id"], v["purl"])));
            let total = rows.len();
            return Ok(
                json!({"results":rows.into_iter().skip(skip as usize).take(limit as usize).collect::<Vec<_>>(),"total":total}),
            );
        }
        let cte="WITH candidates AS (SELECT data FROM intelligence_entities WHERE kind='products' UNION ALL SELECT jsonb_build_object('name',data->'product','vendor',data->'vendor','ecosystem',data->'ecosystem','purl',data->'purl','cpe',COALESCE(data->'cpe'->0,'\"\"'::jsonb),'affected_version_range',data->'affected_version','fixed_version',data->'fixed_version','cve_id',id,'priority_score',priority_score,'is_malicious_package',data->'malicious','provenance',data->'provenance') FROM vulnerabilities WHERE COALESCE(data->>'purl','')<>'' OR jsonb_array_length(COALESCE(data->'cpe','[]'))>0), matches AS (SELECT DISTINCT ON(COALESCE(data->>'cve_id',''),COALESCE(data->>'purl','')) data FROM candidates WHERE strpos(lower(concat_ws(' ',data->>'name',data->>'vendor',data->>'purl',data->>'cpe')),$1)>0 AND ($2='' OR data->>'ecosystem'=$2) ORDER BY COALESCE(data->>'cve_id',''),COALESCE(data->>'purl','')) ";
        let c = self.client().await?;
        let total: i64 = c
            .query_one(
                &format!("{cte} SELECT count(*) FROM matches"),
                &[&name, &ecosystem],
            )
            .await
            .map_err(|e| e.to_string())?
            .get(0);
        let rows:Vec<Value>=c.query(&format!("{cte} SELECT data FROM matches ORDER BY data->>'cve_id',data->>'purl' LIMIT $3 OFFSET $4"),&[&name,&ecosystem,&limit,&skip]).await.map_err(|e|e.to_string())?.iter().map(|r|r.get(0)).collect();
        Ok(json!({"results":rows,"total":total}))
    }
    pub async fn entity_links(&self, kind: &str, id: &str) -> Result<Value, String> {
        let mut rows: Vec<Value> = if !self.persistent() {
            self.entities(kind)
                .await?
                .into_iter()
                .filter(|v| v["cve_id"] == id || v["source_ref"] == id || v["target_ref"] == id)
                .take(101)
                .collect()
        } else {
            self.client().await?.query("SELECT data FROM intelligence_entities WHERE kind=$1 AND (data->>'cve_id'=$2 OR data->>'source_ref'=$2 OR data->>'target_ref'=$2) ORDER BY id,source LIMIT 101",&[&kind,&id]).await.map_err(|e|e.to_string())?.iter().map(|r|r.get(0)).collect()
        };
        let truncated = rows.len() > 100;
        rows.truncate(100);
        Ok(json!({"results":rows,"truncated":truncated}))
    }
    pub async fn patch_candidates(&self, id: &str) -> Result<Vec<Value>, String> {
        let rows: Vec<Value> = if !self.persistent() {
            self.entities("patches")
                .await?
                .into_iter()
                .filter(|v| {
                    v["id"] == id
                        || v["supersedes"]
                            .as_array()
                            .is_some_and(|a| a.contains(&json!(id)))
                })
                .take(201)
                .collect()
        } else {
            self.client().await?.query("SELECT data FROM intelligence_entities WHERE kind='patches' AND (data->>'id'=$1 OR data->'supersedes' ? $1) ORDER BY id,source LIMIT 201",&[&id]).await.map_err(|e|e.to_string())?.iter().map(|r|r.get(0)).collect()
        };
        if rows.len() > 200 {
            return Err("Patch graph exceeds query budget".into());
        }
        Ok(rows)
    }
    pub async fn vex_page(&self, limit: usize, skip: usize) -> Result<Value, String> {
        let limit = limit.clamp(1, 100);
        let skip = skip.min(10000);
        let mut rows: Vec<Value> = if !self.persistent() {
            self.file_read()?
                .vex
                .into_iter()
                .rev()
                .skip(skip)
                .take(limit + 1)
                .collect()
        } else {
            self.client()
                .await?
                .query(
                    "SELECT data FROM vex_documents ORDER BY created_at DESC,id LIMIT $1 OFFSET $2",
                    &[&((limit + 1) as i64), &(skip as i64)],
                )
                .await
                .map_err(|e| e.to_string())?
                .iter()
                .map(|r| r.get(0))
                .collect()
        };
        let truncated = rows.len() > limit;
        rows.truncate(limit);
        Ok(json!({"results":rows,"truncated":truncated}))
    }
    pub async fn vex_for_purls(&self, purls: &[String]) -> Result<Vec<Value>, String> {
        if purls.len() > 1000 {
            return Err("Too many VEX product queries".into());
        }
        let rows: Vec<Value> = if !self.persistent() {
            self.file_read()?
                .vex
                .into_iter()
                .filter(|d| {
                    d["statements"].as_array().is_some_and(|s| {
                        s.iter().any(|s| {
                            s["products"].as_array().is_some_and(|p| {
                                p.iter().any(|p| {
                                    p["@id"]
                                        .as_str()
                                        .is_some_and(|id| purls.iter().any(|v| v == id))
                                })
                            })
                        })
                    })
                })
                .take(1001)
                .collect()
        } else {
            self.client().await?.query("SELECT data FROM vex_documents WHERE EXISTS(SELECT 1 FROM jsonb_array_elements(COALESCE(data->'statements','[]')) s CROSS JOIN LATERAL jsonb_array_elements(COALESCE(s->'products','[]')) p WHERE p->>'@id'=ANY($1)) ORDER BY created_at,id LIMIT 1001",&[&purls]).await.map_err(|e|e.to_string())?.iter().map(|r|r.get(0)).collect()
        };
        if rows.len() > 1000 {
            return Err("VEX applicability candidates exceed budget".into());
        }
        Ok(rows)
    }
    pub async fn entities(&self, kind: &str) -> Result<Vec<Value>, String> {
        if !self.persistent() {
            return Ok(entities_mut(&mut self.file_read()?, kind)?.clone());
        }
        Ok(self
            .client()
            .await?
            .query(
                "SELECT data FROM intelligence_entities WHERE kind=$1 ORDER BY id",
                &[&kind],
            )
            .await
            .map_err(|e| format!("{e:?}"))?
            .iter()
            .map(|r| r.get(0))
            .collect())
    }
    pub async fn vex(&self) -> Result<Vec<Value>, String> {
        if !self.persistent() {
            return Ok(self.file_read()?.vex);
        }
        Ok(self
            .client()
            .await?
            .query("SELECT data FROM vex_documents ORDER BY created_at", &[])
            .await
            .map_err(|e| format!("{e:?}"))?
            .iter()
            .map(|r| r.get(0))
            .collect())
    }
    pub async fn save_vex(&self, doc: Value, subject: &str) -> Result<(), String> {
        let id = doc["@id"].as_str().ok_or("VEX @id required")?.to_string();
        if !self.persistent() {
            return self.file_update(|s| {
                if let Some(i) = s.vex.iter().position(|v| v["@id"] == id) {
                    s.vex[i] = doc
                } else {
                    s.vex.push(doc)
                }
                Ok(())
            });
        }
        let mut c = self.client().await?;
        let tx = c.transaction().await.map_err(|e| format!("{e:?}"))?;
        tx.query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended($1,1))",
            &[&id],
        )
        .await
        .map_err(|e| e.to_string())?;
        let before: Option<Value> = tx
            .query_opt(
                "SELECT data FROM vex_documents WHERE id=$1 FOR UPDATE",
                &[&id],
            )
            .await
            .map_err(|e| e.to_string())?
            .map(|r| r.get(0));
        tx.execute("INSERT INTO vex_revisions(document_id,subject,before_document,after_document) VALUES($1,$2,$3,$4)", &[&id,&subject,&before,&doc]).await.map_err(|e| e.to_string())?;
        tx.execute("INSERT INTO vex_documents(id,data) VALUES($1,$2) ON CONFLICT(id) DO UPDATE SET data=excluded.data,created_at=now()",&[&id,&doc]).await.map_err(|e|e.to_string())?;
        tx.execute(
            "INSERT INTO audit_events(action,subject,detail) VALUES('vex.write',$1,$2)",
            &[&subject, &json!({"document_id":id})],
        )
        .await
        .map_err(|e| format!("{e:?}"))?;
        tx.commit().await.map_err(|e| format!("{e:?}"))?;
        Ok(())
    }
    pub async fn enqueue(&self, source: &str, subject: &str) -> Result<Value, String> {
        if !vi_core::SOURCES.iter().any(|(s, _)| *s == source) {
            return Err("Unknown source".into());
        }
        if !self.persistent() {
            return Err(
                "Ingestion jobs require PostgreSQL; use vi-worker --once in file mode".into(),
            );
        }
        let mut c = self.client().await?;
        let tx = c.transaction().await.map_err(|e| e.to_string())?;
        let row=tx.query_opt("INSERT INTO ingestion_jobs(source_name) VALUES($1) ON CONFLICT DO NOTHING RETURNING id",&[&source]).await.map_err(|e|e.to_string())?;
        let result = json!({"queued":row.is_some(),"id":row.map(|r|r.get::<_,i64>(0))});
        tx.execute(
            "INSERT INTO audit_events(action,subject,detail) VALUES('ingest.enqueue',$1,$2)",
            &[
                &subject,
                &json!({"source":source,"queued":result["queued"]}),
            ],
        )
        .await
        .map_err(|e| e.to_string())?;
        tx.commit().await.map_err(|e| e.to_string())?;
        Ok(result)
    }

    pub async fn queued(&self) -> Result<Vec<(i64, String)>, String> {
        if !self.persistent() {
            return Ok(vec![]);
        }
        let c = self.client().await?;
        c.execute("UPDATE ingestion_jobs SET status='queued' WHERE status='running' AND created_at<now()-interval '20 minutes' AND NOT EXISTS(SELECT 1 FROM ingestion_checkpoints cp WHERE cp.source_name=ingestion_jobs.source_name AND cp.lease_until>now())",&[]).await.map_err(|e|e.to_string())?;
        Ok(c.query("UPDATE ingestion_jobs SET status='running' WHERE id IN (SELECT id FROM ingestion_jobs WHERE status='queued' ORDER BY id FOR UPDATE SKIP LOCKED LIMIT 12) RETURNING id,source_name",&[]).await.map_err(|e|e.to_string())?.iter().map(|r|(r.get(0),r.get(1))).collect())
    }
    pub async fn finish_job(&self, id: i64, error: Option<&str>) -> Result<(), String> {
        self.client()
            .await?
            .execute(
                "UPDATE ingestion_jobs SET status=$2,finished_at=now(),detail=$3 WHERE id=$1",
                &[
                    &id,
                    &if error.is_some() {
                        "failed"
                    } else {
                        "succeeded"
                    },
                    &error,
                ],
            )
            .await
            .map_err(|e| format!("{e:?}"))?;
        Ok(())
    }
    pub async fn jobs(&self) -> Result<Vec<Value>, String> {
        if !self.persistent() {
            return Ok(vec![]);
        }
        Ok(self.client().await?.query("SELECT row_to_json(j) FROM (SELECT * FROM ingestion_jobs ORDER BY id DESC LIMIT 100) j",&[]).await.map_err(|e|e.to_string())?.iter().map(|r|r.get(0)).collect())
    }
    pub async fn stats(&self) -> Result<Value, String> {
        let checkpoints = self.checkpoints().await?;
        if !self.persistent() {
            let s = self.file_read()?;
            return Ok(stats_for(&s.vulnerabilities, checkpoints));
        }
        let c = self.client().await?;
        let row=c.query_one("SELECT count(*)::bigint,count(*) FILTER(WHERE seen_wild)::bigint,count(*) FILTER(WHERE is_zeroday)::bigint,count(*) FILTER(WHERE (data->>'exploit_available')::boolean)::bigint,count(*) FILTER(WHERE priority_score>=700)::bigint,max(updated_at)::text FROM vulnerabilities",&[]).await.map_err(|e|e.to_string())?;
        let mut decisions = serde_json::Map::new();
        for r in c
            .query(
                "SELECT ssvc_decision,count(*)::bigint FROM vulnerabilities GROUP BY ssvc_decision",
                &[],
            )
            .await
            .map_err(|e| format!("{e:?}"))?
        {
            decisions.insert(r.get(0), json!(r.get::<_, i64>(1)));
        }
        let activity:Vec<Value>=c.query("SELECT left(published,7) AS month,count(*)::bigint,count(*) FILTER(WHERE seen_wild)::bigint FROM vulnerabilities WHERE published<>'' GROUP BY month ORDER BY month",&[]).await.map_err(|e|e.to_string())?.iter().map(|r|json!({"month":r.get::<_,String>(0),"total":r.get::<_,i64>(1),"kev":r.get::<_,i64>(2)})).collect();
        Ok(
            json!({"total":row.get::<_,i64>(0),"kev":row.get::<_,i64>(1),"zerodays":row.get::<_,i64>(2),"exploits":row.get::<_,i64>(3),"high_priority":row.get::<_,i64>(4),"snapshot":row.get::<_,Option<String>>(5),"decisions":decisions,"mode":"Source-backed intelligence","sources":checkpoints,"activity":activity}),
        )
    }
    pub async fn query(&self, f: &Value) -> Result<Value, String> {
        vi_core::validate_query(f)?;
        if !self.persistent() {
            return query_file(self.file_read()?.vulnerabilities, f);
        }
        let mut values: Vec<Value> = vec![];
        let mut parts = vec![];
        let text = f["text_search"].as_str().unwrap_or("").trim();
        if !text.is_empty() {
            values.push(json!(text));
            let n = values.len();
            parts.push(format!("(search_text @@ plainto_tsquery('simple',${n}::jsonb #>> '{{}}') OR id ILIKE (replace(replace(replace(${n}::jsonb #>> '{{}}','\\','\\\\'),'%','\\%'),'_','\\_') || '%') OR data->>'purl' ILIKE (replace(replace(replace(${n}::jsonb #>> '{{}}','\\','\\\\'),'%','\\%'),'_','\\_') || '%'))"));
        }
        let mut conditions = vec![];
        for condition in f["conditions"].as_array().unwrap_or(&vec![]) {
            let key = canonical(condition["field"].as_str().ok_or("Missing field")?)?;
            let op = condition["operator"].as_str().ok_or("Missing operator")?;
            values.push(condition["value"].clone());
            let n = values.len();
            let path = format!("data->'{key}'");
            conditions.push(match op {
                "eq" => format!("{path}=${n}::jsonb"),
                "neq" => format!("{path}<>${n}::jsonb"),
                "gt" | "gte" | "lt" | "lte" => format!(
                    "({path} #>> '{{}}')::numeric {} (${n}::jsonb #>> '{{}}')::numeric",
                    match op {
                        "gt" => ">",
                        "gte" => ">=",
                        "lt" => "<",
                        _ => "<=",
                    }
                ),
                "in" => format!(
                    "EXISTS(SELECT 1 FROM jsonb_array_elements(${n}::jsonb) x WHERE x={path})"
                ),
                "contains" => format!(
                    "position(lower(${n}::jsonb #>> '{{}}') in lower(coalesce({path}::text,'')))>0"
                ),
                _ => return Err("Unsupported operator".into()),
            });
        }
        if !conditions.is_empty() {
            parts.push(format!(
                "({})",
                conditions.join(if f["operator"] == "or" {
                    " OR "
                } else {
                    " AND "
                })
            ));
        }
        let predicate = if parts.is_empty() {
            "TRUE".into()
        } else {
            parts.join(" AND ")
        };
        let c = self.client().await?;
        let refs: Vec<&(dyn ToSql + Sync)> =
            values.iter().map(|v| v as &(dyn ToSql + Sync)).collect();
        let total: i64 = c
            .query_one(
                &format!("SELECT count(*)::bigint FROM vulnerabilities WHERE {predicate}"),
                &refs,
            )
            .await
            .map_err(|e| format!("{e:?}"))?
            .get(0);
        let mut facets = serde_json::Map::new();
        for r in c.query(&format!("SELECT ssvc_decision,count(*)::bigint FROM vulnerabilities WHERE {predicate} GROUP BY ssvc_decision"),&refs).await.map_err(|e|e.to_string())?{facets.insert(r.get(0),json!(r.get::<_,i64>(1)));}
        let sort = f["sort_by"].as_str().unwrap_or("priority_score");
        if !["priority_score", "epss_score", "cvss", "published", "id"].contains(&sort) {
            return Err("Unsupported sort field".into());
        }
        let asc = f["sort_order"] == "asc";
        let direction = if asc { "ASC" } else { "DESC" };
        let mut cursor_clause = String::new();
        if let Some(cursor) = f["cursor"].as_str() {
            let decoded: Value = serde_json::from_slice(
                &URL_SAFE_NO_PAD
                    .decode(cursor)
                    .map_err(|_| "Malformed cursor")?,
            )
            .map_err(|_| "Malformed cursor")?;
            let id = decoded["id"].as_str().ok_or("Malformed cursor")?;
            values.push(decoded["sort_value"].clone());
            let n = values.len();
            values.push(json!(id));
            let m = values.len();
            let cast = if ["id", "published"].contains(&sort) {
                "text"
            } else {
                "double precision"
            };
            cursor_clause = format!(
                " AND ({sort},id) {} ((${n}::jsonb #>> '{{}}')::{cast},${m}::jsonb #>> '{{}}')",
                if asc { ">" } else { "<" }
            );
        }
        let limit = f["limit"].as_u64().unwrap_or(20).clamp(1, 100);
        let refs: Vec<&(dyn ToSql + Sync)> =
            values.iter().map(|v| v as &(dyn ToSql + Sync)).collect();
        let mut rows:Vec<Value>=c.query(&format!("SELECT data FROM vulnerabilities WHERE {predicate}{cursor_clause} ORDER BY {sort} {direction},id {direction} LIMIT {}",limit+1),&refs).await.map_err(|e|e.to_string())?.iter().map(|r|r.get(0)).collect();
        let more = rows.len() > limit as usize;
        rows.truncate(limit as usize);
        let next = if more {
            rows.last().map(|v| {
                URL_SAFE_NO_PAD.encode(
                    serde_json::to_vec(&json!({"id":v["id"],"sort_value":v[sort]})).unwrap(),
                )
            })
        } else {
            None
        };
        Ok(json!({"results":rows,"total":total,"facets":facets,"next_cursor":next}))
    }
}
fn set_checkpoint(s: &mut Store, source: &str, cp: Value) {
    if let Some(i) = s
        .checkpoints
        .iter()
        .position(|v| v["source_name"] == source)
    {
        s.checkpoints[i] = cp
    } else {
        s.checkpoints.push(cp)
    }
}
fn entities_mut<'a>(s: &'a mut Store, kind: &str) -> Result<&'a mut Vec<Value>, String> {
    match kind {
        "actors" => Ok(&mut s.actors),
        "ransomware" => Ok(&mut s.ransomware),
        "patches" => Ok(&mut s.patches),
        "rules" => Ok(&mut s.rules),
        "relationships" => Ok(&mut s.relationships),
        "products" => Ok(&mut s.products),
        "weaknesses" => Ok(&mut s.weaknesses),
        "categories" => Ok(&mut s.categories),
        _ => Err("Unknown entity kind".into()),
    }
}
fn canonical(key: &str) -> Result<&str, String> {
    let key = match key {
        "exploits.exploit_available" => "exploit_available",
        "patches.patch_available" => "patch_available",
        k => k,
    };
    if [
        "id",
        "vendor",
        "ecosystem",
        "cvss",
        "epss_score",
        "priority_score",
        "seen_wild",
        "is_zeroday",
        "exploit_available",
        "patch_available",
        "ssvc_decision",
        "known_ransomware_use",
        "bod_26_04_forensic_triage",
        "tags",
        "product",
        "published",
    ]
    .contains(&key)
    {
        Ok(key)
    } else {
        Err("Unsupported filter field".into())
    }
}
fn query_file(rows: Vec<Vulnerability>, f: &Value) -> Result<Value, String> {
    let text = f["text_search"].as_str().unwrap_or("").to_lowercase();
    let mut records: Vec<Value> = rows
        .into_iter()
        .map(|v| serde_json::to_value(v).unwrap())
        .filter(|v| {
            text.is_empty()
                || format!(
                    "{} {} {} {} {} {}",
                    v["id"], v["title"], v["description"], v["vendor"], v["product"], v["purl"]
                )
                .to_lowercase()
                .contains(&text)
        })
        .collect();
    let conditions = f["conditions"].as_array().cloned().unwrap_or_default();
    records.retain(|v| {
        let matches = |c: &Value| {
            let k = canonical(c["field"].as_str().unwrap_or("")).unwrap_or("");
            let val = &v[k];
            match c["operator"].as_str().unwrap_or("") {
                "eq" => *val == c["value"],
                "neq" => *val != c["value"],
                "in" => c["value"].as_array().is_some_and(|a| a.contains(val)),
                "contains" => val
                    .to_string()
                    .to_lowercase()
                    .contains(&c["value"].as_str().unwrap_or("").to_lowercase()),
                "gt" => val.as_f64() > c["value"].as_f64(),
                "gte" => val.as_f64() >= c["value"].as_f64(),
                "lt" => val.as_f64() < c["value"].as_f64(),
                "lte" => val.as_f64() <= c["value"].as_f64(),
                _ => false,
            }
        };
        conditions.is_empty()
            || if f["operator"] == "or" {
                conditions.iter().any(matches)
            } else {
                conditions.iter().all(matches)
            }
    });
    let sort = f["sort_by"].as_str().unwrap_or("priority_score");
    let asc = f["sort_order"] == "asc";
    records.sort_by(|a, b| {
        let cmp = if a[sort].is_number() {
            a[sort].as_f64().partial_cmp(&b[sort].as_f64()).unwrap()
        } else {
            a[sort].as_str().cmp(&b[sort].as_str())
        }
        .then(a["id"].as_str().cmp(&b["id"].as_str()));
        if asc {
            cmp
        } else {
            cmp.reverse()
        }
    });
    let total = records.len();
    let mut facets = serde_json::Map::new();
    for v in &records {
        let name = v["ssvc_decision"].as_str().unwrap_or("Unassessed");
        let n = facets.get(name).and_then(Value::as_u64).unwrap_or(0);
        facets.insert(name.into(), json!(n + 1));
    }
    if let Some(cursor) = f["cursor"].as_str() {
        let decoded: Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(cursor)
                .map_err(|_| "Malformed cursor")?,
        )
        .map_err(|_| "Malformed cursor")?;
        let pos = records
            .iter()
            .position(|v| v["id"] == decoded["id"] && v[sort] == decoded["sort_value"])
            .ok_or("Cursor no longer exists in this result set")?;
        records = records.into_iter().skip(pos + 1).collect();
    }
    let limit = f["limit"].as_u64().unwrap_or(20).clamp(1, 100) as usize;
    let more = records.len() > limit;
    records.truncate(limit);
    let next = if more {
        records.last().map(|v| {
            URL_SAFE_NO_PAD
                .encode(serde_json::to_vec(&json!({"id":v["id"],"sort_value":v[sort]})).unwrap())
        })
    } else {
        None
    };
    Ok(json!({"results":records,"total":total,"facets":facets,"next_cursor":next}))
}
fn stats_for(v: &[Vulnerability], sources: Vec<Value>) -> Value {
    let mut decisions = serde_json::Map::new();
    let mut activity = std::collections::BTreeMap::<String, (usize, usize)>::new();
    for r in v {
        let n = decisions
            .get(&r.ssvc_decision)
            .and_then(Value::as_u64)
            .unwrap_or(0);
        decisions.insert(r.ssvc_decision.clone(), json!(n + 1));
        if r.published.len() >= 7 {
            let entry = activity.entry(r.published[..7].into()).or_default();
            entry.0 += 1;
            entry.1 += r.seen_wild as usize;
        }
    }
    json!({"total":v.len(),"kev":v.iter().filter(|v|v.seen_wild).count(),"zerodays":v.iter().filter(|v|v.is_zeroday).count(),"exploits":v.iter().filter(|v|v.exploit_available).count(),"high_priority":v.iter().filter(|v|v.priority_score>=700).count(),"decisions":decisions,"sources":sources,"mode":"Source-backed intelligence","snapshot":v.iter().map(|v|&v.ingested_at).max(),"activity":activity.into_iter().map(|(month,(total,kev))|json!({"month":month,"total":total,"kev":kev})).collect::<Vec<_>>()})
}

#[cfg(test)]
mod knowledge_tests {
    use super::*;
    #[tokio::test]
    async fn evidence_and_checkpoint_roundtrip_with_bounded_id_scan() {
        let path =
            std::env::temp_dir().join(format!("sentinel-evidence-{}.json", uuid::Uuid::new_v4()));
        let db = Database {
            path: path.clone(),
            url: None,
            ..Database::new()
        };
        let evidence = json!({"source":"Debian Security Tracker","distribution":"Debian","release":"bookworm",
            "product":"example","fixed_versions":["1:2.0~rc1-3+deb12u1"],
            "provenance":{"url":"https://example.test/feed","retrieved_at":"2026-10-21T00:00:00Z","sha256":"first"}});
        for id in ["CVE-2099-1002", "CVE-2099-1000", "CVE-2099-1001"] {
            db.apply("Debian Security Tracker", Batch { vulnerabilities:vec![json!({"id":id,
                "remediation_evidence":[evidence],"poc_references":[{"url":"https://github.com/example/research","verification":"unverified"}]})],
                ..Default::default() }, json!({"source_name":"Debian Security Tracker","cursor":id})).await.unwrap();
        }
        let mut changed_page = evidence.clone();
        changed_page["provenance"]["retrieved_at"] = json!("2026-10-22T00:00:00Z");
        changed_page["provenance"]["sha256"] = json!("second");
        db.apply(
            "Debian Security Tracker",
            Batch {
                vulnerabilities: vec![
                    json!({"id":"CVE-2099-1000","remediation_evidence":[changed_page]}),
                ],
                ..Default::default()
            },
            json!({"source_name":"Debian Security Tracker","cursor":"committed"}),
        )
        .await
        .unwrap();
        let reopened = Database {
            path: path.clone(),
            url: None,
            ..Database::new()
        };
        let v = reopened.get("CVE-2099-1000").await.unwrap().unwrap();
        assert_eq!(v.remediation_evidence.len(), 1);
        assert_eq!(
            v.remediation_evidence[0]["fixed_versions"][0],
            "1:2.0~rc1-3+deb12u1"
        );
        assert!(!v.exploit_available && !v.seen_wild);
        assert_eq!(
            reopened.ids_after("CVE-2099-1000", 1).await.unwrap(),
            vec!["CVE-2099-1001"]
        );
        assert!(reopened.ids_after("", 101).await.is_err());
        assert_eq!(
            reopened
                .checkpoints()
                .await
                .unwrap()
                .into_iter()
                .find(|p| p["source_name"] == "Debian Security Tracker")
                .unwrap()["cursor"],
            "committed"
        );
        assert!(reopened
            .apply(
                "Debian Security Tracker",
                Batch {
                    vulnerabilities: vec![
                        json!({"id":"CVE-2099-1000","title":"Must roll back"}),
                        json!({"id":"invalid"})
                    ],
                    ..Default::default()
                },
                json!({"source_name":"Debian Security Tracker","cursor":"must-not-advance"})
            )
            .await
            .is_err());
        assert_ne!(
            reopened.get("CVE-2099-1000").await.unwrap().unwrap().title,
            "Must roll back"
        );
        assert_eq!(
            reopened
                .checkpoints()
                .await
                .unwrap()
                .into_iter()
                .find(|p| p["source_name"] == "Debian Security Tracker")
                .unwrap()["cursor"],
            "committed"
        );
        std::fs::remove_file(path).unwrap();
    }
    #[tokio::test]
    async fn taxonomy_refresh_replaces_only_its_source_and_retains_last_good_snapshot() {
        let path =
            std::env::temp_dir().join(format!("sentinel-knowledge-{}.json", uuid::Uuid::new_v4()));
        let db = Database {
            path: path.clone(),
            url: None,
            ..Database::new()
        };
        let entry = |source: &str, id: &str| {
            (
                "categories".into(),
                id.into(),
                json!({"id":id,"source":source}),
            )
        };
        db.apply(
            "other",
            Batch {
                entities: vec![entry("other", "other-category")],
                ..Default::default()
            },
            json!({}),
        )
        .await
        .unwrap();
        for id in ["old", "new"] {
            db.apply(
                "OWASP Top 10",
                Batch {
                    entities: vec![entry("OWASP Top 10", id)],
                    replace_entity_kinds: vec!["categories".into()],
                    ..Default::default()
                },
                json!({"source_name":"OWASP Top 10","edition":id}),
            )
            .await
            .unwrap();
        }
        assert!(db.knowledge("old").await.unwrap().is_none());
        assert!(db.knowledge("new").await.unwrap().is_some());
        assert!(db.knowledge("other-category").await.unwrap().is_some());
        let error = db
            .apply(
                "OWASP Top 10",
                Batch {
                    entities: vec![("invalid-kind".into(), "bad".into(), json!({}))],
                    replace_entity_kinds: vec!["categories".into()],
                    ..Default::default()
                },
                json!({}),
            )
            .await;
        assert!(error.is_err());
        assert!(db.knowledge("new").await.unwrap().is_some());
        assert_eq!(
            db.checkpoints()
                .await
                .unwrap()
                .iter()
                .find(|v| v["source_name"] == "OWASP Top 10")
                .unwrap()["edition"],
            "new"
        );
        std::fs::remove_file(path).unwrap();
    }
}

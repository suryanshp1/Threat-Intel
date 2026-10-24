use super::*;
impl Database {
    pub async fn audit(&self, action: &str, subject: &str, detail: Value) -> Result<(), String> {
        if !self.persistent() {
            return Ok(());
        }
        self.client()
            .await?
            .execute(
                "INSERT INTO audit_events(action,subject,detail) VALUES($1,$2,$3)",
                &[&action, &subject, &detail],
            )
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }
    pub async fn identity_login(
        &self,
        id: &str,
        issuer: &str,
        provider_subject: &str,
        label: &str,
    ) -> Result<Value, String> {
        let mut c = self.client().await?;
        let tx = c.transaction().await.map_err(|e| e.to_string())?;
        let row=tx.query_one("INSERT INTO identity_users(id,issuer,provider_subject,label) VALUES($1,$2,$3,$4) ON CONFLICT(id) DO UPDATE SET label=excluded.label,last_login_at=now() RETURNING to_jsonb(identity_users)",&[&id,&issuer,&provider_subject,&label]).await.map_err(|e|e.to_string())?;
        let user: Value = row.get(0);
        tx.execute(
            "INSERT INTO audit_events(action,subject,detail) VALUES('sso.verified',$1,$2)",
            &[
                &id,
                &json!({"role":user["role"],"disabled":user["disabled"]}),
            ],
        )
        .await
        .map_err(|e| e.to_string())?;
        tx.commit().await.map_err(|e| e.to_string())?;
        Ok(user)
    }
    pub async fn bind_identity_session(
        &self,
        hash: &str,
        id: &str,
        ttl: i64,
    ) -> Result<(), String> {
        let mut c = self.client().await?;
        let tx = c.transaction().await.map_err(|e| e.to_string())?;
        // Serialize session creation with account disable/pending transitions.
        if tx.query_opt("SELECT id FROM identity_users WHERE id=$1 AND NOT disabled AND role<>'pending' FOR SHARE",&[&id]).await.map_err(|e|e.to_string())?.is_none(){return Err("Identity access is not approved".into())}
        tx.execute("DELETE FROM identity_sessions WHERE expires_at<=now()", &[])
            .await
            .map_err(|e| e.to_string())?;
        tx.execute("INSERT INTO identity_sessions(session_hash,user_id,expires_at) VALUES($1,$2,now()+($3::bigint)*interval '1 second')",&[&hash,&id,&ttl]).await.map_err(|e|e.to_string())?;
        tx.commit().await.map_err(|e| e.to_string())
    }
    pub async fn identity_session(&self, hash: &str) -> Result<Option<Value>, String> {
        Ok(self.client().await?.query_opt("SELECT to_jsonb(u) FROM identity_users u JOIN identity_sessions s ON s.user_id=u.id WHERE s.session_hash=$1 AND s.expires_at>now()",&[&hash]).await.map_err(|e|e.to_string())?.map(|r|r.get(0)))
    }
    pub async fn identity_users(
        &self,
        limit: i64,
        before: Option<String>,
    ) -> Result<Value, String> {
        if !self.persistent() {
            return Ok(json!({"data":[],"next":null}));
        }
        let rows=self.client().await?.query("SELECT to_jsonb(u) FROM identity_users u WHERE ($1::text IS NULL OR id>$1) ORDER BY id LIMIT $2",&[&before,&(limit+1)]).await.map_err(|e|e.to_string())?;
        let mut data: Vec<Value> = rows.iter().map(|r| r.get(0)).collect();
        let more = data.len() > limit as usize;
        data.truncate(limit as usize);
        Ok(json!({"next":if more {data.last().map(|r|r["id"].clone())}else{None},"data":data}))
    }
    pub async fn set_identity_role(
        &self,
        id: &str,
        role: &str,
        disabled: bool,
        version: i64,
        subject: &str,
    ) -> Result<bool, String> {
        if !["pending", "reader", "analyst", "auditor", "admin"].contains(&role) {
            return Err("Unknown role".into());
        }
        let mut c = self.client().await?;
        let tx = c.transaction().await.map_err(|e| e.to_string())?;
        let before: Option<Value> = tx
            .query_opt(
                "SELECT to_jsonb(u) FROM identity_users u WHERE id=$1 AND version=$2 FOR UPDATE",
                &[&id, &version],
            )
            .await
            .map_err(|e| e.to_string())?
            .map(|r| r.get(0));
        let Some(before) = before else {
            return Ok(false);
        };
        tx.execute(
            "UPDATE identity_users SET role=$2,disabled=$3,version=version+1 WHERE id=$1",
            &[&id, &role, &disabled],
        )
        .await
        .map_err(|e| e.to_string())?;
        if disabled || role == "pending" {
            tx.execute("INSERT INTO session_revocations(session_hash,expires_at) SELECT session_hash,expires_at FROM identity_sessions WHERE user_id=$1 AND expires_at>now() ON CONFLICT(session_hash) DO UPDATE SET expires_at=GREATEST(session_revocations.expires_at,excluded.expires_at)",&[&id]).await.map_err(|e|e.to_string())?;
            tx.execute("DELETE FROM identity_sessions WHERE user_id=$1", &[&id])
                .await
                .map_err(|e| e.to_string())?;
        }
        tx.execute("INSERT INTO audit_events(action,subject,detail) VALUES('user.access',$1,$2)",&[&subject,&json!({"user_id":id,"before":{"role":before["role"],"disabled":before["disabled"],"version":before["version"]},"after":{"role":role,"disabled":disabled,"version":version+1}})]).await.map_err(|e|e.to_string())?;
        tx.commit().await.map_err(|e| e.to_string())?;
        Ok(true)
    }
    pub async fn identity_sessions(&self, id: &str) -> Result<Value, String> {
        let rows=self.client().await?.query("SELECT jsonb_build_object('id',session_hash,'created_at',created_at,'expires_at',expires_at) FROM identity_sessions WHERE user_id=$1 AND expires_at>now() AND NOT EXISTS(SELECT 1 FROM session_revocations r WHERE r.session_hash=identity_sessions.session_hash AND r.expires_at>now()) ORDER BY created_at DESC LIMIT 101",&[&id]).await.map_err(|e|e.to_string())?;
        let mut data: Vec<Value> = rows.iter().map(|r| r.get(0)).collect();
        let truncated = data.len() > 100;
        data.truncate(100);
        Ok(json!({"data":data,"truncated":truncated}))
    }
    pub async fn revoke_identity_session(&self, hash: &str, subject: &str) -> Result<bool, String> {
        let mut c = self.client().await?;
        let tx = c.transaction().await.map_err(|e| e.to_string())?;
        let row = tx
            .query_opt(
                "DELETE FROM identity_sessions WHERE session_hash=$1 RETURNING user_id",
                &[&hash],
            )
            .await
            .map_err(|e| e.to_string())?;
        if let Some(row) = row {
            let id: String = row.get(0);
            tx.execute("INSERT INTO session_revocations(session_hash,expires_at) VALUES($1,now()+interval '8 hours') ON CONFLICT DO NOTHING",&[&hash]).await.map_err(|e|e.to_string())?;
            tx.execute(
                "INSERT INTO audit_events(action,subject,detail) VALUES('session.revoke',$1,$2)",
                &[&subject, &json!({"user_id":id,"session_id":hash})],
            )
            .await
            .map_err(|e| e.to_string())?;
            tx.commit().await.map_err(|e| e.to_string())?;
            return Ok(true);
        }
        Ok(false)
    }
    pub async fn audit_page(
        &self,
        limit: i64,
        before: Option<i64>,
        action: Option<String>,
        subject: Option<String>,
    ) -> Result<Value, String> {
        if !self.persistent() {
            return Ok(json!({"data":[],"next":null}));
        }
        let rows=self.client().await?.query("SELECT to_jsonb(a) FROM audit_events a WHERE ($1::bigint IS NULL OR id<$1) AND ($2::text IS NULL OR action=$2) AND ($3::text IS NULL OR subject=$3) ORDER BY id DESC LIMIT $4",&[&before,&action,&subject,&(limit+1)]).await.map_err(|e|e.to_string())?;
        let mut data: Vec<Value> = rows.iter().map(|r| r.get(0)).collect();
        let more = data.len() > limit as usize;
        data.truncate(limit as usize);
        Ok(json!({"next":if more{data.last().map(|r|r["id"].clone())}else{None},"data":data}))
    }
    pub async fn vex_history(
        &self,
        id: &str,
        limit: i64,
        before: Option<i64>,
    ) -> Result<Value, String> {
        if !self.persistent() {
            return Ok(json!({"data":[],"next":null}));
        }
        let rows=self.client().await?.query("SELECT to_jsonb(v) FROM vex_revisions v WHERE document_id=$1 AND ($2::bigint IS NULL OR revision<$2) ORDER BY revision DESC LIMIT $3",&[&id,&before,&(limit+1)]).await.map_err(|e|e.to_string())?;
        let mut data: Vec<Value> = rows.iter().map(|r| r.get(0)).collect();
        let more = data.len() > limit as usize;
        data.truncate(limit as usize);
        Ok(json!({"next":if more{data.last().map(|r|r["revision"].clone())}else{None},"data":data}))
    }
}

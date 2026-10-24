use tantivy::{collector::TopDocs, query::QueryParser, schema::*, Index, TantivyDocument};
use vi_core::Vulnerability;
pub struct Search {
    index: Index,
    id: Field,
    text: Field,
    coordinates: Vec<(String, String)>,
}
impl Search {
    pub fn new(records: &[Vulnerability]) -> tantivy::Result<Self> {
        let mut schema = Schema::builder();
        let id = schema.add_text_field("id", STRING | STORED);
        let text = schema.add_text_field("text", TEXT);
        let index = Index::create_in_ram(schema.build());
        let mut writer = index.writer(15_000_000)?;
        for v in records {
            writer.add_document(tantivy::doc!(id=>v.id.clone(),text=>format!("{} {} {} {} {} {}",v.id,v.title,v.description,v.vendor,v.product,v.purl)))?;
        }
        writer.commit()?;
        Ok(Self {
            index,
            id,
            text,
            coordinates: records
                .iter()
                .map(|v| (v.id.clone(), v.purl.to_lowercase()))
                .collect(),
        })
    }
    pub fn find(&self, q: &str) -> tantivy::Result<Vec<String>> {
        let normalized = q.trim().to_lowercase();
        if normalized.starts_with("cve-") || normalized.starts_with("pkg:") {
            return Ok(self
                .coordinates
                .iter()
                .filter(|(id, purl)| {
                    id.to_lowercase().starts_with(&normalized) || purl.contains(&normalized)
                })
                .map(|(id, _)| id.clone())
                .collect());
        }
        let reader = self.index.reader()?;
        let searcher = reader.searcher();
        let mut parser = QueryParser::for_index(&self.index, vec![self.text]);
        parser.set_conjunction_by_default();
        let (query, _) = parser.parse_query_lenient(q);
        let docs = searcher.search(&query, &TopDocs::with_limit(100_000).order_by_score())?;
        let mut ids = Vec::new();
        for (_, addr) in docs {
            let doc: TantivyDocument = searcher.doc(addr)?;
            if let Some(id) = doc.get_first(self.id).and_then(|v| v.as_str()) {
                ids.push(id.to_string());
            }
        }
        Ok(ids)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn upgraded_search_collector_retains_text_and_id_lookup() {
        let records = vec![Vulnerability {
            id: "CVE-2099-1000".into(),
            title: "Parser fixture".into(),
            ..Default::default()
        }];
        let search = Search::new(&records).unwrap();
        assert_eq!(search.find("parser").unwrap(), vec!["CVE-2099-1000"]);
        assert_eq!(search.find("CVE-2099").unwrap(), vec!["CVE-2099-1000"]);
    }
}

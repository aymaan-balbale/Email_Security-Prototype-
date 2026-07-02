use crate::models::{QueryMeta, DkimKey};
use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::*;
use std::sync::Arc;
use std::time::Instant;
use tokio::time::{timeout, Duration};
use futures::future::join_all;

const DNS_TIMEOUT: Duration = Duration::from_secs(5);

const DKIM_SELECTORS: &[&str] = &[
    "default", "mail", "google", "selector1", "selector2",
    "amazon", "microsoft", "k1", "k2", "smtp", "dkim",
    "mta", "sendgrid", "s1", "s2",
];

pub struct DnsScanner {
    resolver: Arc<TokioAsyncResolver>,
}

impl DnsScanner {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let resolver = TokioAsyncResolver::tokio(
            ResolverConfig::default(),
            ResolverOpts::default(),
        );
        Ok(Self {
            resolver: Arc::new(resolver),
        })
    }

    /// Core TXT fetch with timeout and timing metadata.
    /// Returns all TXT records as a Vec so callers can filter for the one they need.
    async fn fetch_txt_all(&self, query: &str) -> (Vec<String>, QueryMeta) {
        let start = Instant::now();
        let result = timeout(DNS_TIMEOUT, self.resolver.txt_lookup(query)).await;
        let elapsed = start.elapsed().as_millis() as u64;

        match result {
            Ok(Ok(lookup)) => {
                let mut all_records: Vec<String> = Vec::new();
                for record in lookup.iter() {
                    let txt: String = record
                        .txt_data()
                        .iter()
                        .map(|b| String::from_utf8_lossy(b).to_string())
                        .collect();
                    if !txt.is_empty() {
                        all_records.push(txt);
                    }
                }
                let combined = all_records.join(" | ");
                let meta = QueryMeta {
                    query: query.to_string(),
                    latency_ms: elapsed,
                    raw_response: Some(combined),
                    status: "OK".to_string(),
                };
                (all_records, meta)
            }
            Ok(Err(e)) => {
                let meta = QueryMeta {
                    query: query.to_string(),
                    latency_ms: elapsed,
                    raw_response: None,
                    status: format!("DNS_ERROR: {}", e),
                };
                (Vec::new(), meta)
            }
            Err(_) => {
                let meta = QueryMeta {
                    query: query.to_string(),
                    latency_ms: elapsed,
                    raw_response: None,
                    status: "TIMEOUT".to_string(),
                };
                (Vec::new(), meta)
            }
        }
    }

    /// Fetch SPF record (v=spf1...) from root domain TXT records.
    pub async fn get_spf(&self, domain: &str) -> (Option<String>, QueryMeta) {
        let (records, mut meta) = self.fetch_txt_all(domain).await;
        // Search all TXT records for the one starting with v=spf1
        let spf = records.iter().find(|r| r.starts_with("v=spf1")).cloned();
        if spf.is_none() && meta.status == "OK" {
            meta.status = "NO_SPF_RECORD".to_string();
        }
        (spf, meta)
    }

    /// Fetch DMARC record from _dmarc.<domain>.
    pub async fn get_dmarc(&self, domain: &str) -> (Option<String>, QueryMeta) {
        let query = format!("_dmarc.{}", domain);
        let (records, mut meta) = self.fetch_txt_all(&query).await;
        let dmarc = records.iter().find(|r| r.starts_with("v=DMARC1")).cloned();
        if dmarc.is_none() && meta.status == "OK" {
            meta.status = "NO_DMARC_RECORD".to_string();
        }
        (dmarc, meta)
    }

    /// Concurrently brute-force DKIM selectors.
    pub async fn discover_dkim(&self, domain: &str) -> (Vec<DkimKey>, Vec<QueryMeta>) {
        let resolver = Arc::clone(&self.resolver);
        let domain_owned = domain.to_string();

        let handles: Vec<_> = DKIM_SELECTORS
            .iter()
            .map(|selector| {
                let r = Arc::clone(&resolver);
                let d = domain_owned.clone();
                let sel = selector.to_string();
                tokio::spawn(async move {
                    let query = format!("{}._domainkey.{}", sel, d);
                    let start = Instant::now();
                    let result = timeout(DNS_TIMEOUT, r.txt_lookup(&query)).await;
                    let elapsed = start.elapsed().as_millis() as u64;

                    match result {
                        Ok(Ok(lookup)) => {
                            let mut txt_data = String::new();
                            for record in lookup.iter() {
                                for chunk in record.txt_data() {
                                    txt_data.push_str(&String::from_utf8_lossy(chunk));
                                }
                            }
                            let meta = QueryMeta {
                                query,
                                latency_ms: elapsed,
                                raw_response: Some(txt_data.clone()),
                                status: "OK".to_string(),
                            };
                            (sel, Some(txt_data), meta)
                        }
                        Ok(Err(e)) => {
                            let meta = QueryMeta {
                                query,
                                latency_ms: elapsed,
                                raw_response: None,
                                status: format!("DNS_ERROR: {}", e),
                            };
                            (sel, None, meta)
                        }
                        Err(_) => {
                            let meta = QueryMeta {
                                query,
                                latency_ms: elapsed,
                                raw_response: None,
                                status: "TIMEOUT".to_string(),
                            };
                            (sel, None, meta)
                        }
                    }
                })
            })
            .collect();

        let results = join_all(handles).await;
        let mut keys = Vec::new();
        let mut metas = Vec::new();

        for result in results {
            if let Ok((selector, txt_opt, meta)) = result {
                metas.push(meta);
                if let Some(txt) = txt_opt {
                    let parsed = crate::parser::parse_dkim_record(&selector, &txt);
                    if parsed.valid_syntax {
                        keys.push(parsed);
                    }
                }
            }
        }

        (keys, metas)
    }
}

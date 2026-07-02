use crate::models::*;

// ─── SPF Parsing ────────────────────────────────────────────────────

pub fn parse_spf(raw: &str) -> SpfRecord {
    let qualifier = if raw.contains(" -all") || raw.ends_with("-all") {
        SpfQualifier::Fail
    } else if raw.contains(" ~all") || raw.ends_with("~all") {
        SpfQualifier::SoftFail
    } else if raw.contains(" ?all") || raw.ends_with("?all") {
        SpfQualifier::Neutral
    } else if raw.contains(" +all") || raw.ends_with("+all") || raw.ends_with(" all") {
        SpfQualifier::Pass
    } else {
        SpfQualifier::Missing
    };

    let mechanisms: Vec<String> = raw
        .split_whitespace()
        .filter(|t| {
            *t != "v=spf1"
                && !t.ends_with("all")
                && *t != "-all"
                && *t != "~all"
                && *t != "?all"
                && *t != "+all"
        })
        .map(|s| s.to_string())
        .collect();

    SpfRecord {
        raw: raw.to_string(),
        qualifier,
        mechanisms,
    }
}

// ─── DMARC Parsing ──────────────────────────────────────────────────

pub fn parse_dmarc(raw: &str) -> DmarcRecord {
    let tags: Vec<(&str, &str)> = raw
        .split(';')
        .filter_map(|segment| {
            let trimmed = segment.trim();
            let mut parts = trimmed.splitn(2, '=');
            let key = parts.next()?.trim();
            let val = parts.next()?.trim();
            Some((key, val))
        })
        .collect();

    let get = |key: &str| -> Option<String> {
        tags.iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v.to_string())
    };

    let policy = match get("p").as_deref() {
        Some("reject") => DmarcPolicy::Reject,
        Some("quarantine") => DmarcPolicy::Quarantine,
        Some("none") => DmarcPolicy::None,
        _ => DmarcPolicy::Missing,
    };

    let subdomain_policy = get("sp").map(|v| match v.as_str() {
        "reject" => DmarcPolicy::Reject,
        "quarantine" => DmarcPolicy::Quarantine,
        "none" => DmarcPolicy::None,
        _ => DmarcPolicy::None,
    });

    let pct: u8 = get("pct")
        .and_then(|v| v.parse().ok())
        .unwrap_or(100);

    let adkim = match get("adkim").as_deref() {
        Some("s") => AlignmentMode::Strict,
        Some("r") => AlignmentMode::Relaxed,
        _ => AlignmentMode::Unset,
    };

    let aspf = match get("aspf").as_deref() {
        Some("s") => AlignmentMode::Strict,
        Some("r") => AlignmentMode::Relaxed,
        _ => AlignmentMode::Unset,
    };

    DmarcRecord {
        raw: raw.to_string(),
        policy,
        subdomain_policy,
        rua: get("rua"),
        ruf: get("ruf"),
        pct,
        adkim,
        aspf,
    }
}

// ─── DKIM Parsing ───────────────────────────────────────────────────

pub fn parse_dkim_record(selector: &str, raw: &str) -> DkimKey {
    let tags: Vec<(&str, &str)> = raw
        .split(';')
        .filter_map(|segment| {
            let trimmed = segment.trim();
            let mut parts = trimmed.splitn(2, '=');
            let key = parts.next()?.trim();
            let val = parts.next()?.trim();
            Some((key, val))
        })
        .collect();

    let get = |key: &str| -> Option<String> {
        tags.iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v.to_string())
    };

    let key_type = get("k").unwrap_or_else(|| "rsa".to_string());
    let public_key = get("p").unwrap_or_default();

    // Approximate key bits from base64 length: base64 encodes 3 bytes -> 4 chars
    // So decoded bytes ≈ len * 3/4; bits = bytes * 8
    let key_bits_approx = if !public_key.is_empty() {
        (public_key.len() * 3 / 4) * 8
    } else {
        0
    };

    let has_version = raw.contains("v=DKIM1") || raw.contains("v=dkim1");
    let has_key = !public_key.is_empty();

    DkimKey {
        selector: selector.to_string(),
        raw: raw.to_string(),
        key_type,
        public_key,
        key_bits_approx,
        valid_syntax: has_version && has_key,
    }
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── SPF ────

    #[test]
    fn spf_hard_fail() {
        let r = parse_spf("v=spf1 include:_spf.google.com ip4:203.0.113.0/24 -all");
        assert_eq!(r.qualifier, SpfQualifier::Fail);
        assert!(r.mechanisms.contains(&"include:_spf.google.com".to_string()));
        assert!(r.mechanisms.contains(&"ip4:203.0.113.0/24".to_string()));
    }

    #[test]
    fn spf_soft_fail() {
        let r = parse_spf("v=spf1 include:sendgrid.net ~all");
        assert_eq!(r.qualifier, SpfQualifier::SoftFail);
    }

    #[test]
    fn spf_neutral() {
        let r = parse_spf("v=spf1 ?all");
        assert_eq!(r.qualifier, SpfQualifier::Neutral);
        assert!(r.mechanisms.is_empty());
    }

    #[test]
    fn spf_pass_all() {
        let r = parse_spf("v=spf1 +all");
        assert_eq!(r.qualifier, SpfQualifier::Pass);
    }

    // ── DMARC ──

    #[test]
    fn dmarc_full_parse() {
        let r = parse_dmarc(
            "v=DMARC1; p=reject; rua=mailto:d@example.com; ruf=mailto:f@example.com; pct=100; adkim=s; aspf=s",
        );
        assert_eq!(r.policy, DmarcPolicy::Reject);
        assert_eq!(r.rua, Some("mailto:d@example.com".to_string()));
        assert_eq!(r.ruf, Some("mailto:f@example.com".to_string()));
        assert_eq!(r.pct, 100);
        assert_eq!(r.adkim, AlignmentMode::Strict);
        assert_eq!(r.aspf, AlignmentMode::Strict);
    }

    #[test]
    fn dmarc_minimal() {
        let r = parse_dmarc("v=DMARC1; p=none");
        assert_eq!(r.policy, DmarcPolicy::None);
        assert!(r.rua.is_none());
        assert!(r.ruf.is_none());
        assert_eq!(r.pct, 100); // default
        assert_eq!(r.adkim, AlignmentMode::Unset);
    }

    #[test]
    fn dmarc_quarantine_with_pct() {
        let r = parse_dmarc("v=DMARC1; p=quarantine; pct=50");
        assert_eq!(r.policy, DmarcPolicy::Quarantine);
        assert_eq!(r.pct, 50);
    }

    // ── DKIM ──

    #[test]
    fn dkim_valid_rsa() {
        let raw = "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQ";
        let k = parse_dkim_record("google", raw);
        assert!(k.valid_syntax);
        assert_eq!(k.key_type, "rsa");
        assert!(k.key_bits_approx > 0);
    }

    #[test]
    fn dkim_empty_key_revoked() {
        let raw = "v=DKIM1; k=rsa; p=";
        let k = parse_dkim_record("old", raw);
        assert!(!k.valid_syntax);
    }

    #[test]
    fn dkim_no_version() {
        let raw = "k=rsa; p=MIIBIjANBgkq";
        let k = parse_dkim_record("test", raw);
        assert!(!k.valid_syntax);
    }
}

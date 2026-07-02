use crate::models::*;

/// Advanced risk scoring engine.
///
/// Scoring matrix (additive, capped at 100):
///
/// | Condition                                              | Points |
/// |--------------------------------------------------------|--------|
/// | DMARC missing                                          | +45    |
/// | DMARC p=none                                           | +35    |
/// | DMARC p=quarantine with pct < 100                      | +10    |
/// | DMARC missing rua AND ruf (blind to abuse)             | +10    |
/// | DMARC relaxed alignment (adkim=r or aspf=r) + weak SPF | +8     |
/// | SPF +all                                               | +35    |
/// | SPF ?all                                               | +25    |
/// | SPF ~all                                               | +15    |
/// | SPF missing                                            | +30    |
/// | No DKIM keys found at all                              | +15    |
/// | DKIM keys found but all <1024 bits                     | +5     |

pub fn score(posture: &DomainPosture) -> (u8, RiskLevel, Vec<Remediation>) {
    let mut pts: u16 = 0;
    let mut remediations: Vec<Remediation> = Vec::new();
    let domain = &posture.domain;

    // ── DMARC ──────────────────────────────────────────────────────

    match &posture.dmarc {
        None => {
            pts += 45;
            remediations.push(Remediation {
                severity: RiskLevel::Critical,
                description: "No DMARC record found. The domain has zero spoofing protection at the policy level.".into(),
                dns_fix: format!("v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@{}; pct=100; adkim=s; aspf=s", domain),
                bind_command: format!("_dmarc.{}. IN TXT \"v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@{}; pct=100; adkim=s; aspf=s\"", domain, domain),
                ps_command: format!(
                    "Add-DnsServerResourceRecord -ZoneName \"{}\" -Name \"_dmarc\" -Txt -DescriptiveText \"v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@{}; pct=100; adkim=s; aspf=s\"",
                    domain, domain
                ),
            });
        }
        Some(dmarc) => {
            match dmarc.policy {
                DmarcPolicy::None => {
                    pts += 35;
                    remediations.push(Remediation {
                        severity: RiskLevel::High,
                        description: "DMARC policy is 'none'. Mail servers will not reject or quarantine spoofed messages.".into(),
                        dns_fix: format!("v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@{}", domain),
                        bind_command: format!("_dmarc.{}. IN TXT \"v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@{}\"", domain, domain),
                        ps_command: format!(
                            "Set-DnsServerResourceRecord -ZoneName \"{}\" -Name \"_dmarc\" -Txt -DescriptiveText \"v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@{}\"",
                            domain, domain
                        ),
                    });
                }
                DmarcPolicy::Quarantine if dmarc.pct < 100 => {
                    pts += 10;
                    remediations.push(Remediation {
                        severity: RiskLevel::Medium,
                        description: format!("DMARC pct={} means only {}% of failing mail is quarantined. Increase to 100.", dmarc.pct, dmarc.pct),
                        dns_fix: "Amend pct=100 in existing DMARC record.".into(),
                        bind_command: "Update the pct tag in your existing _dmarc TXT record to pct=100.".into(),
                        ps_command: "Update the pct tag in your existing _dmarc TXT record to pct=100.".into(),
                    });
                }
                _ => {}
            }

            // Blind to abuse: no reporting URIs
            if dmarc.rua.is_none() && dmarc.ruf.is_none() {
                pts += 10;
                remediations.push(Remediation {
                    severity: RiskLevel::Medium,
                    description: "DMARC record has no rua or ruf reporting URIs. You cannot see who is spoofing your domain.".into(),
                    dns_fix: format!("Add rua=mailto:dmarc-agg@{}; ruf=mailto:dmarc-forensic@{}", domain, domain),
                    bind_command: "Add rua= and ruf= tags to existing DMARC TXT record.".into(),
                    ps_command: "Add rua= and ruf= tags to existing DMARC TXT record.".into(),
                });
            }

            // Relaxed alignment + weak SPF = elevated risk
            let spf_weak = match &posture.spf {
                Some(spf) => matches!(spf.qualifier, SpfQualifier::SoftFail | SpfQualifier::Neutral | SpfQualifier::Pass),
                None => true,
            };
            let alignment_relaxed =
                dmarc.adkim == AlignmentMode::Relaxed
                    || dmarc.adkim == AlignmentMode::Unset
                    || dmarc.aspf == AlignmentMode::Relaxed
                    || dmarc.aspf == AlignmentMode::Unset;

            if alignment_relaxed && spf_weak {
                pts += 8;
                remediations.push(Remediation {
                    severity: RiskLevel::Medium,
                    description: "Relaxed DKIM/SPF alignment combined with a weak SPF policy allows cousin-domain spoofing.".into(),
                    dns_fix: "Set adkim=s; aspf=s in DMARC record for strict alignment.".into(),
                    bind_command: "Update adkim and aspf tags to 's' in existing DMARC TXT record.".into(),
                    ps_command: "Update adkim and aspf tags to 's' in existing DMARC TXT record.".into(),
                });
            }
        }
    }

    // ── SPF ────────────────────────────────────────────────────────

    match &posture.spf {
        None => {
            pts += 30;
            remediations.push(Remediation {
                severity: RiskLevel::High,
                description: "No SPF record. Any IP can claim to send mail for this domain.".into(),
                dns_fix: "v=spf1 -all".into(),
                bind_command: format!("{}. IN TXT \"v=spf1 -all\"", domain),
                ps_command: format!(
                    "Add-DnsServerResourceRecord -ZoneName \"{}\" -Name \"@\" -Txt -DescriptiveText \"v=spf1 -all\"",
                    domain
                ),
            });
        }
        Some(spf) => match spf.qualifier {
            SpfQualifier::Pass => {
                pts += 35;
                remediations.push(Remediation {
                    severity: RiskLevel::Critical,
                    description: "SPF +all authorizes every IP on the internet to send as this domain.".into(),
                    dns_fix: "v=spf1 <your-mechanisms> -all".into(),
                    bind_command: format!("{}. IN TXT \"v=spf1 <your-mechanisms> -all\"", domain),
                    ps_command: format!(
                        "Set-DnsServerResourceRecord -ZoneName \"{}\" -Name \"@\" -Txt -DescriptiveText \"v=spf1 <your-mechanisms> -all\"",
                        domain
                    ),
                });
            }
            SpfQualifier::Neutral => {
                pts += 25;
                remediations.push(Remediation {
                    severity: RiskLevel::High,
                    description: "SPF ?all treats unauthorized senders as neutral — most filters will not block spoofed mail.".into(),
                    dns_fix: "Change ?all to -all in SPF record.".into(),
                    bind_command: "Change ?all to -all in existing SPF TXT record.".into(),
                    ps_command: "Change ?all to -all in existing SPF TXT record.".into(),
                });
            }
            SpfQualifier::SoftFail => {
                pts += 15;
                remediations.push(Remediation {
                    severity: RiskLevel::Medium,
                    description: "SPF ~all (softfail) tags unauthorized mail but does not reject it. Upgrade to -all when ready.".into(),
                    dns_fix: "Change ~all to -all in SPF record.".into(),
                    bind_command: "Change ~all to -all in existing SPF TXT record.".into(),
                    ps_command: "Change ~all to -all in existing SPF TXT record.".into(),
                });
            }
            _ => {}
        },
    }

    // ── DKIM ───────────────────────────────────────────────────────

    if posture.dkim_keys.is_empty() {
        pts += 15;
        remediations.push(Remediation {
            severity: RiskLevel::High,
            description: "No DKIM keys discovered across 15 common selectors. DKIM signing may not be configured.".into(),
            dns_fix: "Generate a DKIM keypair and publish the public key at <selector>._domainkey.<domain>.".into(),
            bind_command: format!("default._domainkey.{}. IN TXT \"v=DKIM1; k=rsa; p=<base64-public-key>\"", domain),
            ps_command: format!(
                "Add-DnsServerResourceRecord -ZoneName \"{}\" -Name \"default._domainkey\" -Txt -DescriptiveText \"v=DKIM1; k=rsa; p=<base64-public-key>\"",
                domain
            ),
        });
    } else {
        let all_weak = posture.dkim_keys.iter().all(|k| k.key_bits_approx < 1024);
        if all_weak {
            pts += 5;
            remediations.push(Remediation {
                severity: RiskLevel::Medium,
                description: "All discovered DKIM keys appear to be under 1024 bits. Use 2048-bit RSA minimum.".into(),
                dns_fix: "Regenerate DKIM keypair with 2048-bit RSA.".into(),
                bind_command: "Regenerate DKIM keypair and update TXT record.".into(),
                ps_command: "Regenerate DKIM keypair and update TXT record.".into(),
            });
        }
    }

    // ── Final ──────────────────────────────────────────────────────

    let capped = (pts as u8).min(100);
    let level = match capped {
        0..=29 => RiskLevel::Low,
        30..=59 => RiskLevel::Medium,
        60..=79 => RiskLevel::High,
        _ => RiskLevel::Critical,
    };

    (capped, level, remediations)
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_posture(
        spf: Option<SpfRecord>,
        dmarc: Option<DmarcRecord>,
        dkim: Vec<DkimKey>,
    ) -> DomainPosture {
        DomainPosture {
            domain: "test.com".into(),
            timestamp: String::new(),
            raw_spf: spf.as_ref().map(|s| s.raw.clone()),
            raw_dmarc: dmarc.as_ref().map(|d| d.raw.clone()),
            spf,
            dmarc,
            dkim_keys: dkim,
            risk_score: 0,
            risk_level: RiskLevel::Low,
            remediations: Vec::new(),
            query_log: Vec::new(),
            spoof_results: Vec::new(),
            smtp_handshake: None,
        }
    }

    #[test]
    fn critical_no_dmarc_plus_all_spf() {
        let spf = SpfRecord { raw: "v=spf1 +all".into(), qualifier: SpfQualifier::Pass, mechanisms: vec![] };
        let p = make_posture(Some(spf), None, vec![]);
        let (score, level, _) = score(&p);
        assert!(score >= 80, "expected critical, got {}", score);
        assert!(matches!(level, RiskLevel::Critical));
    }

    #[test]
    fn high_risk_none_policy_softfail() {
        let spf = SpfRecord { raw: "v=spf1 ~all".into(), qualifier: SpfQualifier::SoftFail, mechanisms: vec![] };
        let dmarc = DmarcRecord {
            raw: "v=DMARC1; p=none".into(), policy: DmarcPolicy::None,
            subdomain_policy: None, rua: None, ruf: None, pct: 100,
            adkim: AlignmentMode::Unset, aspf: AlignmentMode::Unset,
        };
        let p = make_posture(Some(spf), Some(dmarc), vec![]);
        let (s, level, _) = score(&p);
        assert!(s >= 60 && s <= 100, "expected high/critical, got {}", s);
        assert!(matches!(level, RiskLevel::High | RiskLevel::Critical));
    }

    #[test]
    fn low_risk_reject_strict() {
        let spf = SpfRecord { raw: "v=spf1 -all".into(), qualifier: SpfQualifier::Fail, mechanisms: vec![] };
        let dmarc = DmarcRecord {
            raw: "v=DMARC1; p=reject; rua=mailto:x@test.com; adkim=s; aspf=s".into(),
            policy: DmarcPolicy::Reject,
            subdomain_policy: None, rua: Some("mailto:x@test.com".into()), ruf: None,
            pct: 100, adkim: AlignmentMode::Strict, aspf: AlignmentMode::Strict,
        };
        let dkim = vec![DkimKey {
            selector: "google".into(), raw: "v=DKIM1; k=rsa; p=LONGKEY".into(),
            key_type: "rsa".into(), public_key: "A".repeat(400), key_bits_approx: 2400,
            valid_syntax: true,
        }];
        let p = make_posture(Some(spf), Some(dmarc), dkim);
        let (s, level, _) = score(&p);
        assert!(s <= 29, "expected low, got {}", s);
        assert!(matches!(level, RiskLevel::Low));
    }

    #[test]
    fn medium_risk_no_reporting() {
        let spf = SpfRecord { raw: "v=spf1 -all".into(), qualifier: SpfQualifier::Fail, mechanisms: vec![] };
        let dmarc = DmarcRecord {
            raw: "v=DMARC1; p=quarantine".into(), policy: DmarcPolicy::Quarantine,
            subdomain_policy: None, rua: None, ruf: None, pct: 100,
            adkim: AlignmentMode::Unset, aspf: AlignmentMode::Unset,
        };
        let dkim = vec![DkimKey {
            selector: "s1".into(), raw: "v=DKIM1; k=rsa; p=LONGKEY".into(),
            key_type: "rsa".into(), public_key: "A".repeat(400), key_bits_approx: 2400,
            valid_syntax: true,
        }];
        let p = make_posture(Some(spf), Some(dmarc), dkim);
        let (s, level, _) = score(&p);
        assert!(s >= 10 && s <= 59, "expected medium, got {}", s);
        assert!(matches!(level, RiskLevel::Low | RiskLevel::Medium));
    }
}

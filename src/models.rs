use serde::{Deserialize, Serialize};
use std::fmt;

// ─── Policy & Risk Enums ────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum SpfQualifier {
    Pass,     // +all
    Neutral,  // ?all
    SoftFail, // ~all
    Fail,     // -all
    Missing,
}

impl fmt::Display for SpfQualifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SpfQualifier::Pass => write!(f, "+all (Pass)"),
            SpfQualifier::Neutral => write!(f, "?all (Neutral)"),
            SpfQualifier::SoftFail => write!(f, "~all (SoftFail)"),
            SpfQualifier::Fail => write!(f, "-all (Fail)"),
            SpfQualifier::Missing => write!(f, "Missing"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum DmarcPolicy {
    Reject,
    Quarantine,
    None,
    Missing,
}

impl fmt::Display for DmarcPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DmarcPolicy::Reject => write!(f, "reject"),
            DmarcPolicy::Quarantine => write!(f, "quarantine"),
            DmarcPolicy::None => write!(f, "none"),
            DmarcPolicy::Missing => write!(f, "Missing"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum AlignmentMode {
    Strict,
    Relaxed,
    Unset,
}

impl fmt::Display for AlignmentMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AlignmentMode::Strict => write!(f, "strict (s)"),
            AlignmentMode::Relaxed => write!(f, "relaxed (r)"),
            AlignmentMode::Unset => write!(f, "unset (defaults to relaxed)"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RiskLevel::Low => write!(f, "LOW"),
            RiskLevel::Medium => write!(f, "MEDIUM"),
            RiskLevel::High => write!(f, "HIGH"),
            RiskLevel::Critical => write!(f, "CRITICAL"),
        }
    }
}

// ─── SPF Parsed Record ──────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SpfRecord {
    pub raw: String,
    pub qualifier: SpfQualifier,
    pub mechanisms: Vec<String>,
}

// ─── DKIM Parsed Key ────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DkimKey {
    pub selector: String,
    pub raw: String,
    pub key_type: String,      // rsa, ed25519
    pub public_key: String,    // base64 p= value
    pub key_bits_approx: usize,
    pub valid_syntax: bool,
}

// ─── DMARC Parsed Record ───────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DmarcRecord {
    pub raw: String,
    pub policy: DmarcPolicy,
    pub subdomain_policy: Option<DmarcPolicy>,
    pub rua: Option<String>,
    pub ruf: Option<String>,
    pub pct: u8,
    pub adkim: AlignmentMode,
    pub aspf: AlignmentMode,
}

// ─── DNS Query Metadata ────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct QueryMeta {
    pub query: String,
    pub latency_ms: u64,
    pub raw_response: Option<String>,
    pub status: String,
}

// ─── Remediation ────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Remediation {
    pub severity: RiskLevel,
    pub description: String,
    pub dns_fix: String,
    pub bind_command: String,
    pub ps_command: String,
}

// ─── Spoof Test Result ──────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SpoofTestResult {
    pub stage: String,
    pub verdict: String,
    pub detail: String,
}

// ─── SMTP Handshake State Machine ───────────────────────────────────

/// Tracks the exact phase of the SMTP transaction.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum SmtpPhase {
    Connect,
    Ehlo,
    MailFrom,
    RcptTo,
    Data,
    Body,
    Quit,
    Complete,
}

impl fmt::Display for SmtpPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SmtpPhase::Connect => write!(f, "TCP_CONNECT"),
            SmtpPhase::Ehlo => write!(f, "EHLO"),
            SmtpPhase::MailFrom => write!(f, "MAIL_FROM"),
            SmtpPhase::RcptTo => write!(f, "RCPT_TO"),
            SmtpPhase::Data => write!(f, "DATA"),
            SmtpPhase::Body => write!(f, "BODY_END"),
            SmtpPhase::Quit => write!(f, "QUIT"),
            SmtpPhase::Complete => write!(f, "COMPLETE"),
        }
    }
}

/// A single step in the live SMTP handshake log.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SmtpStep {
    pub phase: SmtpPhase,
    pub command_sent: Option<String>,
    pub response_code: u16,
    pub response_text: String,
    pub success: bool,
}

/// The full result of a live SMTP spoof attempt.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SmtpHandshakeResult {
    pub target_host: String,
    pub target_port: u16,
    pub spoofed_domain: String,
    pub steps: Vec<SmtpStep>,
    pub dropped_at: Option<SmtpPhase>,
    pub delivered: bool,
    pub theory_match: Option<String>,
}

// ─── Top-Level Posture ──────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DomainPosture {
    pub domain: String,
    pub timestamp: String,

    // Raw DNS
    pub raw_spf: Option<String>,
    pub raw_dmarc: Option<String>,

    // Parsed
    pub spf: Option<SpfRecord>,
    pub dmarc: Option<DmarcRecord>,
    pub dkim_keys: Vec<DkimKey>,

    // Scoring
    pub risk_score: u8,
    pub risk_level: RiskLevel,

    // Remediations
    pub remediations: Vec<Remediation>,

    // Verbose metadata
    pub query_log: Vec<QueryMeta>,

    // Passive spoof analysis
    pub spoof_results: Vec<SpoofTestResult>,

    // Live SMTP handshake results
    pub smtp_handshake: Option<SmtpHandshakeResult>,
}

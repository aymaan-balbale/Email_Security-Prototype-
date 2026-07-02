use crate::models::*;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{timeout, Duration};

const SMTP_TIMEOUT: Duration = Duration::from_secs(10);
const READ_BUF_SIZE: usize = 4096;

// ─── Passive Analysis (unchanged from v0.2) ─────────────────────────

/// Simulate where an SMTP filter would reject a spoofed email based on
/// the parsed SPF, DKIM, and DMARC configurations.
///
/// This does NOT connect to any external servers. It is a deterministic
/// analysis of the policy chain to predict filter behavior.
pub fn simulate_spoof(posture: &DomainPosture) -> Vec<SpoofTestResult> {
    let mut results = Vec::new();

    // ── Stage 1: SMTP Envelope (MAIL FROM) ──────────────────────

    let spf_verdict = match &posture.spf {
        None => {
            results.push(SpoofTestResult {
                stage: "MAIL FROM (SPF Check)".into(),
                verdict: "PASS (no record)".into(),
                detail: "No SPF record exists. The receiving MTA has no basis to reject the envelope sender. A spoofed MAIL FROM will be accepted.".into(),
            });
            "none"
        }
        Some(spf) => match spf.qualifier {
            SpfQualifier::Fail => {
                results.push(SpoofTestResult {
                    stage: "MAIL FROM (SPF Check)".into(),
                    verdict: "FAIL → REJECTED".into(),
                    detail: format!(
                        "SPF -all means the receiving MTA should reject mail from IPs not listed in: {:?}. A spoofed envelope from an unauthorized IP will be dropped here.",
                        spf.mechanisms
                    ),
                });
                "fail"
            }
            SpfQualifier::SoftFail => {
                results.push(SpoofTestResult {
                    stage: "MAIL FROM (SPF Check)".into(),
                    verdict: "SOFTFAIL → TAGGED".into(),
                    detail: "SPF ~all tags unauthorized senders but does not reject. The message will likely land in spam, not be dropped.".into(),
                });
                "softfail"
            }
            SpfQualifier::Neutral | SpfQualifier::Pass => {
                results.push(SpoofTestResult {
                    stage: "MAIL FROM (SPF Check)".into(),
                    verdict: "PASS → ACCEPTED".into(),
                    detail: "SPF policy is permissive (?all or +all). Spoofed envelope sender will pass SPF.".into(),
                });
                "pass"
            }
            SpfQualifier::Missing => {
                results.push(SpoofTestResult {
                    stage: "MAIL FROM (SPF Check)".into(),
                    verdict: "PASS (no terminator)".into(),
                    detail: "SPF record exists but has no valid all-mechanism terminator. Most MTAs treat this as neutral.".into(),
                });
                "none"
            }
        },
    };

    // ── Stage 2: DATA (DKIM Signature Verification) ─────────────

    if posture.dkim_keys.is_empty() {
        results.push(SpoofTestResult {
            stage: "DATA (DKIM Verification)".into(),
            verdict: "SKIP → NO KEYS".into(),
            detail: "No DKIM keys were discovered. The receiving MTA cannot verify a DKIM signature, so this check is effectively skipped for spoofed mail.".into(),
        });
    } else {
        results.push(SpoofTestResult {
            stage: "DATA (DKIM Verification)".into(),
            verdict: "FAIL → SIGNATURE MISMATCH".into(),
            detail: format!(
                "DKIM keys exist for selectors {:?}. A spoofed message won't have a valid signature, so DKIM verification will fail.",
                posture.dkim_keys.iter().map(|k| k.selector.as_str()).collect::<Vec<_>>()
            ),
        });
    }

    // ── Stage 3: Post-DATA (DMARC Policy Enforcement) ───────────

    match &posture.dmarc {
        None => {
            results.push(SpoofTestResult {
                stage: "Post-DATA (DMARC Policy)".into(),
                verdict: "NO POLICY → DELIVERED".into(),
                detail: "No DMARC record. Even if SPF or DKIM failed, there is no policy instructing the MTA to reject or quarantine. Spoofed mail will be delivered to the inbox.".into(),
            });
        }
        Some(dmarc) => {
            let dmarc_action = match dmarc.policy {
                DmarcPolicy::Reject => {
                    results.push(SpoofTestResult {
                        stage: "Post-DATA (DMARC Policy)".into(),
                        verdict: "REJECT → DROPPED".into(),
                        detail: format!(
                            "DMARC p=reject at pct={}. If both SPF and DKIM fail alignment, the message will be rejected outright.",
                            dmarc.pct
                        ),
                    });
                    "reject"
                }
                DmarcPolicy::Quarantine => {
                    results.push(SpoofTestResult {
                        stage: "Post-DATA (DMARC Policy)".into(),
                        verdict: "QUARANTINE → SPAM".into(),
                        detail: format!(
                            "DMARC p=quarantine at pct={}. Failing messages will be routed to spam/junk.",
                            dmarc.pct
                        ),
                    });
                    "quarantine"
                }
                DmarcPolicy::None | DmarcPolicy::Missing => {
                    results.push(SpoofTestResult {
                        stage: "Post-DATA (DMARC Policy)".into(),
                        verdict: "NONE → DELIVERED".into(),
                        detail: "DMARC p=none provides monitoring only. Spoofed mail that fails SPF/DKIM will still be delivered.".into(),
                    });
                    "none"
                }
            };

            let final_verdict = if dmarc_action == "reject" {
                "Spoofed email would be REJECTED by a compliant MTA."
            } else if dmarc_action == "quarantine" {
                "Spoofed email would land in SPAM/JUNK on a compliant MTA."
            } else if spf_verdict == "fail" {
                "SPF would fail, but without a restrictive DMARC policy the message may still be delivered depending on the receiving MTA's local policy."
            } else {
                "Spoofed email would likely be DELIVERED to the inbox."
            };

            results.push(SpoofTestResult {
                stage: "Final Verdict".into(),
                verdict: final_verdict.into(),
                detail: "This is a prediction based on published DNS records. Actual delivery depends on the receiving MTA's implementation and local overrides.".into(),
            });
        }
    }

    if posture.dmarc.is_none() {
        results.push(SpoofTestResult {
            stage: "Final Verdict".into(),
            verdict: "Spoofed email would likely be DELIVERED to the inbox.".into(),
            detail: "Without a DMARC record, there is no enforcement policy. The domain is vulnerable to direct spoofing.".into(),
        });
    }

    results
}

// ─── Active SMTP Handshake Simulator ────────────────────────────────

/// Parse the SMTP numeric response code from a response line.
/// Returns (code, full_text). Handles multi-line responses (250-...).
fn parse_smtp_response(raw: &str) -> (u16, String) {
    let text = raw.trim().to_string();
    // Grab the last line's code (for multi-line responses like EHLO)
    let last_line = text.lines().last().unwrap_or("");
    let code: u16 = last_line
        .chars()
        .take(3)
        .collect::<String>()
        .parse()
        .unwrap_or(0);
    (code, text)
}

/// Returns true if the SMTP code indicates success (2xx or 3xx for DATA).
fn is_success(code: u16) -> bool {
    (200..400).contains(&code)
}

/// Send a command, read the response, and log the step.
async fn smtp_exchange(
    stream: &mut TcpStream,
    phase: SmtpPhase,
    command: &str,
) -> Result<SmtpStep, SmtpStep> {
    // Send command
    let write_result = timeout(
        SMTP_TIMEOUT,
        stream.write_all(format!("{}\r\n", command).as_bytes()),
    )
    .await;

    match write_result {
        Err(_) => {
            return Err(SmtpStep {
                phase,
                command_sent: Some(command.to_string()),
                response_code: 0,
                response_text: "TIMEOUT: Write timed out".into(),
                success: false,
            });
        }
        Ok(Err(e)) => {
            return Err(SmtpStep {
                phase,
                command_sent: Some(command.to_string()),
                response_code: 0,
                response_text: format!("IO_ERROR: {}", e),
                success: false,
            });
        }
        Ok(Ok(())) => {}
    }

    // Read response
    read_response(stream, phase, Some(command)).await
}

/// Read a server response without sending a command (used for banner).
async fn read_response(
    stream: &mut TcpStream,
    phase: SmtpPhase,
    command: Option<&str>,
) -> Result<SmtpStep, SmtpStep> {
    let mut buf = vec![0u8; READ_BUF_SIZE];

    let read_result = timeout(SMTP_TIMEOUT, stream.read(&mut buf)).await;

    match read_result {
        Err(_) => Err(SmtpStep {
            phase,
            command_sent: command.map(|s| s.to_string()),
            response_code: 0,
            response_text: "TIMEOUT: Read timed out".into(),
            success: false,
        }),
        Ok(Err(e)) => Err(SmtpStep {
            phase,
            command_sent: command.map(|s| s.to_string()),
            response_code: 0,
            response_text: format!("IO_ERROR: {}", e),
            success: false,
        }),
        Ok(Ok(0)) => Err(SmtpStep {
            phase,
            command_sent: command.map(|s| s.to_string()),
            response_code: 0,
            response_text: "CONNECTION_CLOSED: Server closed the connection".into(),
            success: false,
        }),
        Ok(Ok(n)) => {
            let raw = String::from_utf8_lossy(&buf[..n]).to_string();
            let (code, text) = parse_smtp_response(&raw);
            let success = is_success(code);

            let step = SmtpStep {
                phase: phase.clone(),
                command_sent: command.map(|s| s.to_string()),
                response_code: code,
                response_text: text,
                success,
            };

            if success {
                Ok(step)
            } else {
                Err(step)
            }
        }
    }
}

/// Execute the full SMTP spoof handshake against a target server.
///
/// Sends a spoofed MAIL FROM / header From using the assessed domain,
/// logging every server response. Halts immediately on any 4XX/5XX.
pub async fn smtp_handshake(
    target_host: &str,
    target_port: u16,
    spoofed_domain: &str,
) -> SmtpHandshakeResult {
    let addr = format!("{}:{}", target_host, target_port);
    let mut steps: Vec<SmtpStep> = Vec::new();
    #[allow(unused_assignments)]
    let mut dropped_at: Option<SmtpPhase> = None;

    // ── Macro: log step or halt ──

    macro_rules! step_or_halt {
        ($result:expr) => {
            match $result {
                Ok(step) => {
                    steps.push(step);
                }
                Err(step) => {
                    let phase = step.phase.clone();
                    steps.push(step);
                    dropped_at = Some(phase);
                    return SmtpHandshakeResult {
                        target_host: target_host.into(),
                        target_port,
                        spoofed_domain: spoofed_domain.into(),
                        steps,
                        dropped_at,
                        delivered: false,
                        theory_match: None,
                    };
                }
            }
        };
    }

    // ── Phase 1: TCP Connect ────────────────────────────────────

    let connect_result = timeout(SMTP_TIMEOUT, TcpStream::connect(&addr)).await;
    let mut stream = match connect_result {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            steps.push(SmtpStep {
                phase: SmtpPhase::Connect,
                command_sent: None,
                response_code: 0,
                response_text: format!("CONNECTION_REFUSED: {}", e),
                success: false,
            });
            return SmtpHandshakeResult {
                target_host: target_host.into(),
                target_port,
                spoofed_domain: spoofed_domain.into(),
                steps,
                dropped_at: Some(SmtpPhase::Connect),
                delivered: false,
                theory_match: None,
            };
        }
        Err(_) => {
            steps.push(SmtpStep {
                phase: SmtpPhase::Connect,
                command_sent: None,
                response_code: 0,
                response_text: "TIMEOUT: TCP connection timed out".into(),
                success: false,
            });
            return SmtpHandshakeResult {
                target_host: target_host.into(),
                target_port,
                spoofed_domain: spoofed_domain.into(),
                steps,
                dropped_at: Some(SmtpPhase::Connect),
                delivered: false,
                theory_match: None,
            };
        }
    };

    // ── Phase 2: Read Banner ────────────────────────────────────

    step_or_halt!(read_response(&mut stream, SmtpPhase::Connect, None).await);

    // ── Phase 3: EHLO ───────────────────────────────────────────

    step_or_halt!(smtp_exchange(&mut stream, SmtpPhase::Ehlo, "EHLO attacker.local").await);

    // ── Phase 4: MAIL FROM ──────────────────────────────────────

    let mail_from = format!("MAIL FROM:<admin@{}>", spoofed_domain);
    step_or_halt!(smtp_exchange(&mut stream, SmtpPhase::MailFrom, &mail_from).await);

    // ── Phase 5: RCPT TO ────────────────────────────────────────

    step_or_halt!(smtp_exchange(&mut stream, SmtpPhase::RcptTo, "RCPT TO:<victim@example.com>").await);

    // ── Phase 6: DATA ───────────────────────────────────────────

    step_or_halt!(smtp_exchange(&mut stream, SmtpPhase::Data, "DATA").await);

    // ── Phase 7: Message Body + Headers ─────────────────────────

    let body = format!(
        "From: \"CEO\" <ceo@{}>\r\n\
         To: victim@example.com\r\n\
         Subject: [SPOOF TEST] Email Security Assessment\r\n\
         Date: {}\r\n\
         X-Spoof-Test: email-sec-cli/0.3.0\r\n\
         MIME-Version: 1.0\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         \r\n\
         This is an automated spoof test from the email-sec CLI.\r\n\
         If you received this, the domain {} may be vulnerable to spoofing.\r\n\
         .\r\n",
        spoofed_domain,
        chrono::Utc::now().to_rfc2822(),
        spoofed_domain,
    );

    // Send body (the DATA content including trailing ".\r\n")
    let write_result = timeout(
        SMTP_TIMEOUT,
        stream.write_all(body.as_bytes()),
    )
    .await;

    match write_result {
        Err(_) => {
            steps.push(SmtpStep {
                phase: SmtpPhase::Body,
                command_sent: Some("[message body]".into()),
                response_code: 0,
                response_text: "TIMEOUT: Body write timed out".into(),
                success: false,
            });
            dropped_at = Some(SmtpPhase::Body);
            return SmtpHandshakeResult {
                target_host: target_host.into(),
                target_port,
                spoofed_domain: spoofed_domain.into(),
                steps,
                dropped_at,
                delivered: false,
                theory_match: None,
            };
        }
        Ok(Err(e)) => {
            steps.push(SmtpStep {
                phase: SmtpPhase::Body,
                command_sent: Some("[message body]".into()),
                response_code: 0,
                response_text: format!("IO_ERROR: {}", e),
                success: false,
            });
            dropped_at = Some(SmtpPhase::Body);
            return SmtpHandshakeResult {
                target_host: target_host.into(),
                target_port,
                spoofed_domain: spoofed_domain.into(),
                steps,
                dropped_at,
                delivered: false,
                theory_match: None,
            };
        }
        Ok(Ok(())) => {}
    }

    // Read server response to the body end-of-data marker
    step_or_halt!(read_response(&mut stream, SmtpPhase::Body, Some("[message body + .]")).await);

    // ── Phase 8: QUIT ───────────────────────────────────────────

    // QUIT is best-effort; we don't halt on failure here
    let quit_result = smtp_exchange(&mut stream, SmtpPhase::Quit, "QUIT").await;
    match quit_result {
        Ok(step) | Err(step) => steps.push(step),
    }

    SmtpHandshakeResult {
        target_host: target_host.into(),
        target_port,
        spoofed_domain: spoofed_domain.into(),
        steps,
        dropped_at: None,
        delivered: true,
        theory_match: None,
    }
}

/// Compare the live SMTP result with the passive theory prediction.
pub fn correlate_theory(
    posture: &DomainPosture,
    result: &mut SmtpHandshakeResult,
) {
    let theory_predicts_reject = posture.spoof_results.iter().any(|r| {
        r.stage == "Final Verdict"
            && (r.verdict.contains("REJECTED") || r.verdict.contains("DROPPED"))
    });

    let theory_predicts_spam = posture.spoof_results.iter().any(|r| {
        r.stage == "Final Verdict" && r.verdict.contains("SPAM")
    });

    if result.delivered && theory_predicts_reject {
        result.theory_match = Some(
            "MISMATCH: Theory predicted REJECT, but the SMTP server accepted the message. \
             The target MTA may not enforce DMARC/SPF, or this is a testing sink (Mailpit/MailHog)."
                .into(),
        );
    } else if result.delivered && theory_predicts_spam {
        result.theory_match = Some(
            "PARTIAL: Theory predicted QUARANTINE/SPAM, but the SMTP server accepted at the \
             transport layer. Content filtering may still quarantine post-acceptance."
                .into(),
        );
    } else if result.delivered && !theory_predicts_reject {
        result.theory_match = Some(
            "MATCH: Theory predicted delivery, and the SMTP server accepted the message."
                .into(),
        );
    } else if !result.delivered && theory_predicts_reject {
        result.theory_match = Some(format!(
            "MATCH: Theory predicted REJECT. Server dropped the connection at phase: {}.",
            result
                .dropped_at
                .as_ref()
                .map(|p| p.to_string())
                .unwrap_or_else(|| "UNKNOWN".into())
        ));
    } else if !result.delivered {
        result.theory_match = Some(format!(
            "UNEXPECTED: Server rejected at phase {} despite permissive DNS policy. \
             The MTA may have local override rules or reputation-based filtering.",
            result
                .dropped_at
                .as_ref()
                .map(|p| p.to_string())
                .unwrap_or_else(|| "UNKNOWN".into())
        ));
    }
}

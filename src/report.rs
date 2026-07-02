use crate::models::{DomainPosture, SpfQualifier, DmarcPolicy, RiskLevel};
use askama::Template;
use std::fs::File;
use std::io::Write;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ReportError {
    #[error("JSON serialization failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("HTML template render failed: {0}")]
    Html(#[from] askama::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Template)]
#[template(path = "report.html")]
pub struct ReportTemplate<'a> {
    pub posture: &'a DomainPosture,
}

pub fn export_json(posture: &DomainPosture, path: &str) -> Result<(), ReportError> {
    let json = serde_json::to_string_pretty(posture)?;
    let mut f = File::create(path)?;
    f.write_all(json.as_bytes())?;
    Ok(())
}

pub fn export_html(posture: &DomainPosture, path: &str) -> Result<(), ReportError> {
    let tmpl = ReportTemplate { posture };
    let html = tmpl.render()?;
    let mut f = File::create(path)?;
    f.write_all(html.as_bytes())?;
    Ok(())
}

pub fn print_console(posture: &DomainPosture, verbose: bool) {
    use console::style;

    let bar = "═".repeat(60);
    println!("\n{}", style(&bar).cyan());
    println!("{}", style(format!("  EMAIL SECURITY POSTURE: {}", posture.domain.to_uppercase())).bold().cyan());
    println!("{}", style(&bar).cyan());

    // ── Risk Score ──
    let score_color = match posture.risk_score {
        0..=29 => style(format!("{}%", posture.risk_score)).green().bold(),
        30..=59 => style(format!("{}%", posture.risk_score)).yellow().bold(),
        60..=79 => style(format!("{}%", posture.risk_score)).red().bold(),
        _ => style(format!("{}%", posture.risk_score)).red().bold(),
    };
    println!("\n  {} {}", style("Risk Score:").bold(), score_color);
    println!("  {} {}", style("Risk Level:").bold(), style(&posture.risk_level).bold());

    // ── SPF ──
    println!("\n{}", style("── SPF ──────────────────────────────────").dim());
    match &posture.spf {
        Some(spf) => {
            println!("  Policy:     {}", spf.qualifier);
            println!("  Mechanisms: {:?}", spf.mechanisms);
            if verbose {
                println!("  Raw:        {}", style(&spf.raw).dim());
            }
        }
        None => println!("  {}", style("NOT FOUND").red().bold()),
    }

    // ── DMARC ──
    println!("\n{}", style("── DMARC ────────────────────────────────").dim());
    match &posture.dmarc {
        Some(d) => {
            println!("  Policy:     {}", d.policy);
            println!("  PCT:        {}%", d.pct);
            println!("  DKIM Align: {}", d.adkim);
            println!("  SPF Align:  {}", d.aspf);
            println!("  RUA:        {}", d.rua.as_deref().unwrap_or("(not set)"));
            println!("  RUF:        {}", d.ruf.as_deref().unwrap_or("(not set)"));
            if verbose {
                println!("  Raw:        {}", style(&d.raw).dim());
            }
        }
        None => println!("  {}", style("NOT FOUND").red().bold()),
    }

    // ── DKIM ──
    println!("\n{}", style("── DKIM ─────────────────────────────────").dim());
    if posture.dkim_keys.is_empty() {
        println!("  {}", style("No valid DKIM keys discovered.").red().bold());
    } else {
        for k in &posture.dkim_keys {
            println!("  [{}] type={}, ~{} bits {}",
                style(&k.selector).green(),
                k.key_type,
                k.key_bits_approx,
                if k.valid_syntax { "✓" } else { "✗" },
            );
        }
    }

    // ── Spoof Test Results ──
    if !posture.spoof_results.is_empty() {
        println!("\n{}", style("── SPOOF SIMULATION (PASSIVE) ────────────").dim());
        for r in &posture.spoof_results {
            let v = if r.verdict.contains("REJECTED") || r.verdict.contains("DROPPED") || r.verdict.contains("FAIL") {
                style(&r.verdict).green()
            } else if r.verdict.contains("SPAM") || r.verdict.contains("TAGGED") || r.verdict.contains("QUARANTINE") {
                style(&r.verdict).yellow()
            } else {
                style(&r.verdict).red()
            };
            println!("  {} → {}", style(&r.stage).bold(), v);
            if verbose {
                println!("    {}", style(&r.detail).dim());
            }
        }
    }

    // ── Live SMTP Handshake Results ──
    if let Some(ref hs) = posture.smtp_handshake {
        println!("\n{}", style("── SMTP HANDSHAKE (ACTIVE) ───────────────").dim());
        println!("  Target: {}:{}", style(&hs.target_host).bold(), hs.target_port);
        println!("  Spoofed Domain: {}", style(&hs.spoofed_domain).bold());
        println!();

        for step in &hs.steps {
            let code_styled = if step.success {
                style(format!("{}", step.response_code)).green()
            } else if step.response_code >= 500 {
                style(format!("{}", step.response_code)).red().bold()
            } else if step.response_code >= 400 {
                style(format!("{}", step.response_code)).yellow().bold()
            } else {
                style(format!("{}", step.response_code)).red()
            };

            let phase_label = format!("[{}]", step.phase);
            println!("  {} {} {}",
                style(phase_label).bold(),
                code_styled,
                if step.success { "✓" } else { "✗" },
            );

            if let Some(ref cmd) = step.command_sent {
                println!("    C: {}", style(cmd).cyan());
            }

            // Show first line of response (or full if verbose)
            let resp_lines: Vec<&str> = step.response_text.lines().collect();
            if verbose {
                for line in &resp_lines {
                    println!("    S: {}", style(line).dim());
                }
            } else if let Some(first) = resp_lines.first() {
                let truncated: String = first.chars().take(100).collect();
                println!("    S: {}", style(truncated).dim());
            }
        }

        // Delivery verdict
        println!();
        if hs.delivered {
            println!("  Result: {}", style("MESSAGE ACCEPTED BY SERVER").red().bold());
        } else {
            let phase = hs.dropped_at.as_ref()
                .map(|p| p.to_string())
                .unwrap_or_else(|| "UNKNOWN".into());
            println!("  Result: {} at phase {}",
                style("CONNECTION DROPPED").green().bold(),
                style(phase).bold(),
            );
        }

        // Theory correlation
        if let Some(ref theory) = hs.theory_match {
            let theory_styled = if theory.starts_with("MATCH") {
                style(theory.as_str()).green()
            } else if theory.starts_with("PARTIAL") {
                style(theory.as_str()).yellow()
            } else {
                style(theory.as_str()).red()
            };
            println!("  Theory: {}", theory_styled);
        }
    }

    // ── Remediations ──
    if !posture.remediations.is_empty() {
        println!("\n{}", style("── REMEDIATIONS ─────────────────────────").dim());
        for (i, rem) in posture.remediations.iter().enumerate() {
            let sev = match rem.severity {
                crate::models::RiskLevel::Critical => style("CRITICAL").red().bold(),
                crate::models::RiskLevel::High => style("HIGH").red(),
                crate::models::RiskLevel::Medium => style("MEDIUM").yellow(),
                crate::models::RiskLevel::Low => style("LOW").green(),
            };
            println!("  {}. [{}] {}", i + 1, sev, rem.description);
            println!("     DNS Fix: {}", style(&rem.dns_fix).cyan());
            if verbose {
                println!("     BIND:    {}", style(&rem.bind_command).dim());
                println!("     PS:      {}", style(&rem.ps_command).dim());
            }
        }
    }

    // ── Verbose: Query Log ──
    if verbose && !posture.query_log.is_empty() {
        println!("\n{}", style("── DNS QUERY LOG ────────────────────────").dim());
        for q in &posture.query_log {
            let status_styled = if q.status == "OK" {
                style(&q.status).green()
            } else {
                style(&q.status).red()
            };
            println!("  {} [{}] {}ms",
                style(&q.query).bold(),
                status_styled,
                q.latency_ms,
            );
            if let Some(raw) = &q.raw_response {
                let truncated: String = raw.chars().take(120).collect();
                println!("    → {}", style(truncated).dim());
            }
        }
    }

    println!("\n{}", style(&bar).cyan());
}

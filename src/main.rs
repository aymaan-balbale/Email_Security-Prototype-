mod analyzer;
mod dns;
mod models;
mod parser;
mod report;
mod spoof;

use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use models::DomainPosture;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(
    name = "email-sec",
    version = "0.3.0",
    about = "Email Security Assessment CLI — SPF, DKIM, DMARC evaluation & spoofing risk analysis"
)]
struct Args {
    /// Target domain to evaluate (e.g. example.com)
    #[arg(short, long)]
    domain: String,

    /// Export findings to JSON
    #[arg(long)]
    export_json: Option<String>,

    /// Export findings to standalone HTML dashboard
    #[arg(long)]
    export_html: Option<String>,

    /// Print raw DNS responses, query latency, and full resolution chain
    #[arg(short, long, default_value_t = false)]
    verbose: bool,

    /// Run passive spoof simulation (DNS policy analysis only)
    #[arg(long, default_value_t = false)]
    spoof_test: bool,

    /// Target SMTP server IP/hostname for live handshake test (default: 127.0.0.1)
    #[arg(long, default_value = "127.0.0.1")]
    smtp_target: String,

    /// Target SMTP server port for live handshake test (default: 1025)
    #[arg(long, default_value_t = 1025)]
    smtp_port: u16,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let domain = args.domain.trim().to_lowercase();

    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈ ")
            .template("{spinner:.cyan} {msg}")?,
    );
    pb.enable_steady_tick(Duration::from_millis(80));
    pb.set_message(format!("Targeting {}...", domain));

    let scanner = dns::DnsScanner::new()?;
    let mut query_log = Vec::new();

    // ── SPF ──
    pb.set_message("Resolving SPF records...");
    let (raw_spf, spf_meta) = scanner.get_spf(&domain).await;
    query_log.push(spf_meta);
    let spf = raw_spf.as_ref().map(|r| parser::parse_spf(r));

    // ── DMARC ──
    pb.set_message("Resolving DMARC records...");
    let (raw_dmarc, dmarc_meta) = scanner.get_dmarc(&domain).await;
    query_log.push(dmarc_meta);
    let dmarc = raw_dmarc.as_ref().map(|r| parser::parse_dmarc(r));

    // ── DKIM (concurrent brute-force) ──
    pb.set_message("Brute-forcing DKIM selectors (15 concurrent queries)...");
    let (dkim_keys, dkim_metas) = scanner.discover_dkim(&domain).await;
    query_log.extend(dkim_metas);

    pb.finish_and_clear();

    // ── Build posture ──
    let timestamp = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string();

    let mut posture = DomainPosture {
        domain: domain.clone(),
        timestamp,
        raw_spf,
        raw_dmarc,
        spf,
        dmarc,
        dkim_keys,
        risk_score: 0,
        risk_level: models::RiskLevel::Low,
        remediations: Vec::new(),
        query_log,
        spoof_results: Vec::new(),
        smtp_handshake: None,
    };

    // ── Score ──
    let (score, level, remediations) = analyzer::score(&posture);
    posture.risk_score = score;
    posture.risk_level = level;
    posture.remediations = remediations;

    // ── Passive spoof simulation ──
    if args.spoof_test {
        posture.spoof_results = spoof::simulate_spoof(&posture);
    }

    // ── Active SMTP handshake ──
    if args.spoof_test {
        let pb2 = ProgressBar::new_spinner();
        pb2.set_style(
            ProgressStyle::default_spinner()
                .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈ ")
                .template("{spinner:.red} {msg}")?,
        );
        pb2.enable_steady_tick(Duration::from_millis(80));
        pb2.set_message(format!(
            "Executing SMTP handshake against {}:{}...",
            args.smtp_target, args.smtp_port
        ));

        let mut handshake = spoof::smtp_handshake(
            &args.smtp_target,
            args.smtp_port,
            &domain,
        )
        .await;

        // Correlate theory vs reality
        spoof::correlate_theory(&posture, &mut handshake);

        pb2.finish_and_clear();
        posture.smtp_handshake = Some(handshake);
    }

    // ── Output ──
    report::print_console(&posture, args.verbose);

    if let Some(path) = args.export_json {
        report::export_json(&posture, &path)?;
        println!("\n  JSON exported → {}", path);
    }

    if let Some(path) = args.export_html {
        report::export_html(&posture, &path)?;
        println!("  HTML exported → {}", path);
    }

    Ok(())
}

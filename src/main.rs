mod analyzer;
mod dns;
mod models;
mod parser;
mod report;
mod spoof;
mod email_parser;

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
    domain: Option<String>,

    /// Parse a raw email (.eml) file for header analysis
    #[arg(short, long)]
    file: Option<String>,

    /// Parse a raw email header string for header analysis
    #[arg(long)]
    header: Option<String>,

    /// Output findings as formatted JSON instead of human-readable text
    #[arg(short, long)]
    json: bool,

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
async fn main() {
    let args = Args::parse();

    if let Some(file_path) = &args.file {
        match std::fs::read_to_string(file_path) {
            Ok(content) => email_parser::parse_and_print_headers(&content),
            Err(e) => eprintln!("Error reading file {}: {}", file_path, e),
        }
        return;
    }

    if let Some(header_str) = &args.header {
        email_parser::parse_and_print_headers(header_str);
        return;
    }

    let domain = match &args.domain {
        Some(d) => d.trim().to_lowercase(),
        None => {
            eprintln!("Error: --domain is required unless --file or --header is provided.");
            std::process::exit(1);
        }
    };

    match run_scan(&domain, &args).await {
        Ok(posture) => {
            if args.json {
                match serde_json::to_string_pretty(&posture) {
                    Ok(json_out) => println!("{}", json_out),
                    Err(e) => eprintln!("Error serializing JSON: {}", e),
                }
            } else {
                println!("EMAIL SECURITY POSTURE: {}", domain.to_uppercase());
                println!("Risk Score: {}% ({})", posture.risk_score, posture.risk_level);
                
                report::print_console(&posture, args.verbose);
            }

            if let Some(path) = &args.export_json {
                if let Err(e) = report::export_json(&posture, path) {
                    eprintln!("Error exporting JSON: {}", e);
                } else {
                    if !args.json {
                        println!("\n  JSON exported → {}", path);
                    }
                }
            }

            if let Some(path) = &args.export_html {
                if let Err(e) = report::export_html(&posture, path) {
                    eprintln!("Error exporting HTML: {}", e);
                } else {
                    if !args.json {
                        println!("  HTML exported → {}", path);
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

async fn run_scan(domain: &str, args: &Args) -> Result<DomainPosture, Box<dyn std::error::Error>> {
    let pb = if args.json {
        ProgressBar::hidden()
    } else {
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈ ")
                .template("{spinner:.cyan} {msg}")?,
        );
        pb.enable_steady_tick(Duration::from_millis(80));
        pb
    };
    
    pb.set_message(format!("Targeting {}...", domain));

    let scanner = dns::DnsScanner::new()?;
    let mut query_log = Vec::new();

    // ── SPF ──
    pb.set_message("Resolving SPF records...");
    let (raw_spf, spf_meta) = scanner.get_spf(domain).await;
    query_log.push(spf_meta);
    let spf = raw_spf.as_ref().map(|r| parser::parse_spf(r));

    // ── DMARC ──
    pb.set_message("Resolving DMARC records...");
    let (raw_dmarc, dmarc_meta) = scanner.get_dmarc(domain).await;
    query_log.push(dmarc_meta);
    let dmarc = raw_dmarc.as_ref().map(|r| parser::parse_dmarc(r));

    // ── DKIM (concurrent brute-force) ──
    pb.set_message("Brute-forcing DKIM selectors (15 concurrent queries)...");
    let (dkim_keys, dkim_metas) = scanner.discover_dkim(domain).await;
    query_log.extend(dkim_metas);

    pb.finish_and_clear();

    // ── Build posture ──
    let timestamp = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string();

    let mut posture = DomainPosture {
        domain: domain.to_string(),
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
        let pb2 = if args.json {
            ProgressBar::hidden()
        } else {
            let pb2 = ProgressBar::new_spinner();
            pb2.set_style(
                ProgressStyle::default_spinner()
                    .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈ ")
                    .template("{spinner:.red} {msg}")?,
            );
            pb2.enable_steady_tick(Duration::from_millis(80));
            pb2
        };

        pb2.set_message(format!(
            "Executing SMTP handshake against {}:{}...",
            args.smtp_target, args.smtp_port
        ));

        let mut handshake = spoof::smtp_handshake(
            &args.smtp_target,
            args.smtp_port,
            domain,
        )
        .await;

        // Correlate theory vs reality
        spoof::correlate_theory(&posture, &mut handshake);

        pb2.finish_and_clear();
        posture.smtp_handshake = Some(handshake);
    }

    Ok(posture)
}

use mailparse::*;
use console::style;

pub fn parse_and_print_headers(content: &str) {
    let parsed = match parse_mail(content.as_bytes()) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{} Failed to parse email: {}", style("Error:").red().bold(), e);
            return;
        }
    };

    println!("\n{}", style("── EMAIL HEADER ANALYSIS ────────────────").cyan().bold());

    let mut auth_results = Vec::new();
    let mut received_spf = Vec::new();

    for header in parsed.get_headers() {
        let name = header.get_key().to_lowercase();
        let value = header.get_value();

        match name.as_str() {
            "from" => println!("  {} {}", style("From:").bold(), value.trim()),
            "received" => {
                // To keep output clean, we just print the first line of each Received header
                let first_line = value.lines().next().unwrap_or("").trim();
                println!("  {} {}", style("Received:").bold(), first_line);
            }
            "dkim-signature" => {
                println!("  {} {}", style("DKIM-Signature:").bold(), "Present");
            }
            "received-spf" => received_spf.push(value.trim().to_string()),
            "authentication-results" => auth_results.push(value.trim().to_string()),
            _ => {}
        }
    }

    // Print specific authentication headers we aggregated
    if !received_spf.is_empty() {
        println!("\n{}", style("── RECEIVED-SPF ─────────────────────────").dim());
        for spf in received_spf {
            let status = if spf.to_lowercase().contains("pass") {
                style("PASS").green().bold()
            } else if spf.to_lowercase().contains("fail") {
                style("FAIL").red().bold()
            } else {
                style("NEUTRAL").yellow().bold()
            };
            println!("  [{}] {}", status, spf.lines().next().unwrap_or("").trim());
        }
    }

    if !auth_results.is_empty() {
        println!("\n{}", style("── AUTHENTICATION-RESULTS ───────────────").dim());
        for auth in auth_results {
            println!("  Raw: {}", style(&auth).dim());
            
            // Basic extraction logic for SPF, DKIM, DMARC verdicts
            let auth_lower = auth.to_lowercase();
            
            print!("  Verdicts: ");
            if auth_lower.contains("spf=pass") {
                print!("{} ", style("SPF=PASS").green().bold());
            } else if auth_lower.contains("spf=fail") {
                print!("{} ", style("SPF=FAIL").red().bold());
            } else if auth_lower.contains("spf=") {
                print!("{} ", style("SPF=OTHER").yellow().bold());
            }

            if auth_lower.contains("dkim=pass") {
                print!("{} ", style("DKIM=PASS").green().bold());
            } else if auth_lower.contains("dkim=fail") {
                print!("{} ", style("DKIM=FAIL").red().bold());
            } else if auth_lower.contains("dkim=") {
                print!("{} ", style("DKIM=OTHER").yellow().bold());
            }

            if auth_lower.contains("dmarc=pass") {
                print!("{} ", style("DMARC=PASS").green().bold());
            } else if auth_lower.contains("dmarc=fail") {
                print!("{} ", style("DMARC=FAIL").red().bold());
            } else if auth_lower.contains("dmarc=") {
                print!("{} ", style("DMARC=OTHER").yellow().bold());
            }
            println!();
        }
    }
    
    println!("{}\n", style("─────────────────────────────────────────").cyan().bold());
}

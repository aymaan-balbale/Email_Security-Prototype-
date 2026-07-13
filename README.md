# Email Security CLI

**Offensive & Defensive email spoofing auditor, written in Rust.**

Tests whether an attacker could successfully spoof a target organization's domain (e.g. sending a fake email as `admin@paypal.com`) by combining passive DNS reconnaissance with an active, live SMTP spoof simulation — then scores the result and generates a self-contained HTML report.

---

## How It Works

The tool operates in three modes:

### 1. Passive Recon — Defensive Check
Scans the target domain's public DNS records to evaluate how well it's protected against spoofing:

- **SPF** — parses the policy (`~all` softfail, `-all` hardfail, `+all`, `?all`) and all `include:` mechanisms
- **DMARC** — parses policy (`none` / `quarantine` / `reject`), `pct`, alignment mode (`adkim` / `aspf`), and reporting addresses (`rua` / `ruf`), with safe `unwrap_or` defaults for missing tags
- **DKIM** — concurrently brute-forces common selectors and parses `v=DKIM1` records, approximating key strength from the base64 public key length

All DNS lookups run through `hickory_resolver` with a hard 5-second timeout per query to prevent hangs on slow or malicious nameservers. DKIM selector probing fans out as concurrent `tokio::spawn` tasks joined with `futures::join_all`.

From this it calculates a **Phishing Risk Score** (0–100%, capped, Low/Medium/High) using an additive point system — e.g. missing DMARC (+45), `p=none` (+35), relaxed alignment (+8), permissive/missing SPF (+30–35) — and runs a **passive spoof simulation** that traces a forged email through SPF (envelope) → DKIM (DATA) → DMARC (post-DATA) to predict whether it would be `TAGGED`, `REJECTED`, or delivered.

### 2. Active Simulator — Offensive Test
Run with `--spoof-test`. This is a *real* attack, not a prediction:

- Opens a live `TcpStream` to a target SMTP server (`--smtp-target` / `--smtp-port`, defaults to `127.0.0.1:1025` for safe local testing)
- Performs a full ESMTP handshake: Banner → `EHLO attacker.local` → `MAIL FROM:<admin@spoofed_domain>` → `RCPT TO:<victim@example.com>` → `DATA` → raw MIME payload + terminating `.\r\n`
- Every read/write is wrapped in a 10-second `tokio::time::timeout` to defend against SMTP tarpitting (servers that stall responses to exhaust client sockets)
- Halts immediately on any 5XX response and records the exact phase the connection was dropped at, via a `step_or_halt!` state-machine macro
- **`correlate_theory`** cross-checks the live handshake outcome against the passive prediction and reports `MATCH`, `MISMATCH`, or `UNEXPECTED`

This proves, with real server behavior, whether the theoretical DNS misconfiguration is actually exploitable — direct exact-domain spoofing only (cousin-domain/lookalike spoofing is out of scope here, since it's a human visual-deception attack, not a technical SMTP bypass).

### 3. Offline Header Analysis
Run with `--file <email.eml>` or `--header` to skip DNS/SMTP entirely and analyze an existing message:

- Parses the file with `mailparse`
- Extracts and colorizes `From`, `Received`, `DKIM-Signature`, `Received-SPF`, and `Authentication-Results`
- Isolates individual `spf=` / `dkim=` / `dmarc=` verdicts out of the `Authentication-Results` header

---

## Features

- 🔍 Full SPF / DKIM / DMARC parsing and analysis
- 📊 Weighted, capped Phishing Risk Score with Low / Medium / High rating
- 🧪 Passive spoof outcome prediction (SPF → DKIM → DMARC pipeline)
- 📡 Active, live SMTP handshake spoof test against a real mail server, with tarpit-resistant timeouts
- 📧 Offline `.eml` / raw header parsing and auth-result verdict extraction
- 🛠️ Actionable remediation steps for every finding, with dynamically generated BIND/PowerShell fix commands
- 🖥️ Colorized CLI output (`console` crate) and `indicatif` progress spinner
- 📄 Self-contained HTML report via `askama` templating
- 📦 JSON export of the full scan result (`DomainPosture`) for pipeline/automation use

---

## Architecture

```text
src/
├── main.rs           Entrypoint, clap CLI parsing, orchestration
├── dns.rs            Async DNS querying (hickory_resolver) — SPF/DMARC lookups, concurrent DKIM selector brute-force
├── parser.rs         Raw TXT string parsing — SPF, DMARC, DKIM record parsing
├── analyzer.rs       Risk scoring engine — additive point system + remediation generation
├── spoof.rs          Passive spoof simulation + active raw-TCP SMTP handshake state machine
├── email_parser.rs   Offline .eml / header parsing (mailparse)
├── report.rs         Console, JSON, and HTML (askama) output formatting
└── models.rs         Shared structs/enums (DomainPosture, SpfRecord, DmarcRecord, RiskLevel, SmtpStep, ...)
```

`DomainPosture` is the central struct threaded through every stage — raw DNS strings, parsed records, risk score, remediations, query metadata, and (if run) the active handshake trace.

---

## Installation

```bash
git clone https://github.com/aymaan-balbale/<repo-name>.git
cd <repo-name>
cargo build --release
```

The compiled binary will be available at `target/release/<binary-name>`.

---

## Usage

**Passive scan only (defensive recon):**

```bash
email-security-cli --domain paypal.com
```

**Full offensive + defensive scan (live SMTP spoof test):**

```bash
email-security-cli --domain paypal.com --spoof-test --smtp-target 127.0.0.1 --smtp-port 1025
```

**Export a JSON or HTML report:**

```bash
email-security-cli --domain paypal.com --spoof-test --export-json report.json
email-security-cli --domain paypal.com --spoof-test --export-html report.html
```

**Offline: analyze a saved .eml file or raw header block:**

```bash
email-security-cli --file suspicious_email.eml
email-security-cli --header
```

### Example

```bash
email-security-cli --domain paypal.com --spoof-test --smtp-target 127.0.0.1 --smtp-port 1025
```

```
EMAIL SECURITY POSTURE: PAYPAL.COM

Risk Score: 38%
Risk Level: MEDIUM

── SPF ──
Policy:      ~all (SoftFail)
Mechanisms:  [...]

── DMARC ──
Policy:      reject
DKIM Align:  unset (defaults to relaxed)
SPF Align:   unset (defaults to relaxed)

── DKIM ──
No valid DKIM keys discovered.

── SPOOF SIMULATION (PASSIVE) ──
MAIL FROM (SPF Check)      → SOFTFAIL → TAGGED
DATA (DKIM Verification)   → SKIP → NO KEYS
Post-DATA (DMARC Policy)   → REJECT → DROPPED
Final Verdict               → Spoofed email would be REJECTED by a compliant MTA.

── SMTP HANDSHAKE (ACTIVE) ──
Target: 127.0.0.1:1025
Spoofed Domain: paypal.com

[TCP_CONNECT] 220 ✓
[EHLO]        250 ✓
[MAIL_FROM]   250 ✓   MAIL FROM:<admin@paypal.com>
[RCPT_TO]     250 ✓   RCPT TO:<victim@example.com>
[DATA]        354 ✓
[BODY_END]    TIMEOUT → CONNECTION DROPPED at phase BODY_END

Result: CONNECTION DROPPED at phase BODY_END
Theory: MATCH — Theory predicted REJECT. Server dropped the connection at phase: BODY_END.

── REMEDIATIONS ──
1. [MEDIUM] Relaxed DKIM/SPF alignment combined with a weak SPF policy allows cousin-domain spoofing.
   DNS Fix: Set adkim=s; aspf=s in DMARC record for strict alignment.

2. [MEDIUM] SPF ~all (softfail) tags unauthorized mail but does not reject it.
   DNS Fix: Change ~all to -all in SPF record.

3. [HIGH] No DKIM keys discovered across 15 common selectors.
   DNS Fix: Generate a DKIM keypair and publish the public key at <selector>._domainkey.<domain>.
```

---

## CLI Flags

| Flag | Description |
|---|---|
| `--domain <domain>` | Target domain to audit (DNS-based passive/active scan) |
| `--file <path>` | Path to a `.eml` file for offline header analysis (bypasses DNS/SMTP) |
| `--header` | Analyze a raw header block instead of a domain |
| `--spoof-test` | Enables the active SMTP handshake simulation |
| `--smtp-target <host>` | SMTP host to connect to for the active test (default `127.0.0.1`) |
| `--smtp-port <port>` | SMTP port to connect to for the active test (default `1025`) |
| `--json` | Print the full result as JSON to stdout |
| `--export-json <path>` | Write the full `DomainPosture` result to a JSON file |
| `--export-html <path>` | Generate a self-contained HTML report |
| `--verbose` | Include DNS query metadata (timing, raw responses) in output |

---

## HTML Report

Every scan can be exported as a single-file HTML report including:

- Phishing Risk Score with visual gauge
- SPF / DMARC status badges
- Raw DNS records (SPF & DMARC TXT values)
- DKIM key discovery results
- Severity-tagged remediation steps with copy-paste DNS/PowerShell commands

---

## Risk Scoring Methodology

The Phishing Risk Score is a capped, additive point system built from:

- **DMARC** — missing entirely (+45), `p=none` (+35), relaxed alignment (+8)
- **SPF** — permissive `+all` (+35) or missing (+30)
- **DKIM** — no valid keys discovered across common selectors

Each finding is tagged **LOW / MEDIUM / HIGH** and paired with a specific, dynamically generated DNS/PowerShell remediation command.

---

## Security & Networking Mechanics

- **Tarpit resistance** — every DNS query (`hickory_resolver`) and every SMTP socket read/write (`spoof.rs`) is wrapped in a hard timeout (5s DNS / 10s SMTP), so the CLI can't be hung indefinitely by a malicious or slow remote server.
- **State-machine halting** — the active SMTP handshake uses a `step_or_halt!` macro: any 5XX response aborts the attack immediately and records the exact `dropped_at` phase, rather than continuing blindly.
- **Direct spoofing only** — the active simulator tests exact-domain `MAIL FROM`/`From` spoofing. Cousin/lookalike domains are intentionally out of scope for the SMTP handshake, since that's a human-deception vector rather than a protocol-level bypass.
- **Known hardening opportunity** — DNS TXT record content is currently rendered via `String::from_utf8_lossy` without stripping ANSI escape sequences. A malicious TXT record could theoretically inject terminal control codes. Stripping non-printable characters before `print_console` is a recommended follow-up.

---

## Tech Stack

- **Rust** + `tokio` (async runtime, concurrent DKIM fan-out, TCP client)
- `clap` — CLI argument parsing
- `hickory_resolver` — async DNS resolution
- `mailparse` — offline `.eml`/header parsing
- `askama` — compile-time HTML templating for the report
- `serde_json` — JSON export
- `console` — ANSI terminal coloring
- `indicatif` — progress spinner
- `futures` — concurrent DKIM selector lookups (`join_all`)

---

## ⚠️ Disclaimer

This tool performs an **active SMTP handshake against a real mail server**, including a live spoofed `MAIL FROM`. Only run `--spoof-test` against:

- Domains you own or are explicitly authorized to test, or
- Local/mock SMTP servers set up for testing (e.g. `127.0.0.1:1025`, MailHog, etc.)

Running the active spoof test against third-party infrastructure without authorization may violate computer fraud laws and the target's responsible disclosure / bug bounty policy. Use only within an authorized scope.

---

## License

MIT LICENSE

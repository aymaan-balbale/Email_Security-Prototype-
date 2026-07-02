# Email Security CLI

**Offensive & Defensive email spoofing auditor, written in Rust.**

Tests whether an attacker could successfully spoof a target organization's domain (e.g. sending a fake email as `admin@paypal.com`) by combining passive DNS reconnaissance with an active, live SMTP spoof simulation — then scores the result and generates a self-contained HTML report.

---

## How It Works

The tool operates in two phases:

### 1. Passive Recon — Defensive Check
Scans the target domain's public DNS records to evaluate how well it's protected against spoofing:

- **SPF** — parses the policy (`~all` softfail, `-all` hardfail, etc.) and all `include:` mechanisms
- **DMARC** — parses policy (`none` / `quarantine` / `reject`), `pct`, alignment mode (`adkim` / `aspf`), and reporting addresses (`rua` / `ruf`)
- **DKIM** — probes common selectors to check for published/valid signing keys

From this it calculates a **Phishing Risk Score** (0–100%, Low/Medium/High) and runs a **passive spoof simulation** that predicts the fate of a forged email — `TAGGED`, `REJECTED`, or delivered — based on how the SPF/DKIM/DMARC checks would resolve at each stage of mail delivery.

### 2. Active Simulator — Offensive Test
Run with the `--spoof-test` flag. This is a *real* attack, not a prediction:

- Opens a live TCP connection to a target SMTP server
- Performs a full ESMTP handshake (`EHLO` → `MAIL FROM` → `RCPT TO` → `DATA` → message body)
- Sends a forged `MAIL FROM` using the target's domain (e.g. `admin@paypal.com`)
- Logs every step and the server's exact response code/text at each phase
- Reports the true outcome — connection dropped, message accepted, or rejected — and cross-checks it against the passive prediction (`MATCH` / `MISMATCH`)

This proves, with real server behavior, whether the theoretical DNS misconfiguration is actually exploitable.

---

## Features

- 🔍 Full SPF / DKIM / DMARC parsing and analysis
- 📊 Weighted Phishing Risk Score with Low / Medium / High rating
- 🧪 Passive spoof outcome prediction (SPF → DKIM → DMARC pipeline)
- 📡 Active, live SMTP handshake spoof test against a real mail server
- 🛠️ Actionable remediation steps for every finding, including copy-paste DNS/PowerShell fixes
- 🖥️ Colorized CLI output for interactive use
- 📄 Self-contained, single-file HTML report for sharing with stakeholders

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
email-security-cli <domain>
```

**Full offensive + defensive scan (live SMTP spoof test):**

```bash
email-security-cli <domain> --spoof-test --target <smtp-host>:<port>
```

**Generate HTML report:**

```bash
email-security-cli <domain> --spoof-test --report
```

### Example

```bash
email-security-cli paypal.com --spoof-test --target 127.0.0.1:1025
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
Final Verdict              → Spoofed email would be REJECTED by a compliant MTA.

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
| `<domain>` | Target domain to audit (positional argument) |
| `--spoof-test` | Enables the active SMTP handshake simulation |
| `--target <host:port>` | SMTP server to connect to for the active test |
| `--report` | Generates a self-contained HTML report (`report.html`) |

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

The Phishing Risk Score is a weighted composite of:

- **SPF strength** — presence, mechanism scope, and enforcement level (`softfail` vs `hardfail`)
- **DMARC strength** — policy (`none`/`quarantine`/`reject`), enforcement percentage, and alignment strictness (`relaxed` vs `strict`)
- **DKIM presence** — whether valid signing keys are published across common selectors

Each finding is tagged **LOW / MEDIUM / HIGH** and paired with a specific DNS-level remediation.

---

## Tech Stack

- **Rust** — core CLI and SMTP client
- Raw TCP/SMTP handshake implementation for the active spoof test
- DNS resolution for SPF/DMARC TXT records and DKIM selector probing
- HTML/CSS templating for the self-contained report output

---

## ⚠️ Disclaimer

This tool performs an **active SMTP handshake against a real mail server**, including a live spoofed `MAIL FROM`. Only run the `--spoof-test` mode against:

- Domains you own or are explicitly authorized to test, or
- Local/mock SMTP servers set up for testing (e.g. `127.0.0.1`)

Running the active spoof test against third-party infrastructure without authorization may violate computer fraud laws and the target's responsible disclosure / bug bounty policy. Use only within an authorized scope.

---

## License

MIT (or your license of choice)

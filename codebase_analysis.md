# Offensive & Defensive Email Security CLI - Codebase Analysis

This document provides a complete reverse-engineering and walkthrough of the Email Security CLI project, from highest-level architecture down to individual functions, strictly following the requested analysis order.

---

# Dependency Graph

```text
src/
├── main.rs                 (Entrypoint, CLI parsing, Orchestration)
│
├── dns.rs                  (Asynchronous DNS querying via hickory_resolver)
│   └── models.rs           (QueryMeta, DkimKey)
│   └── parser.rs           (DKIM syntax parsing)
│
├── parser.rs               (Raw string parsing for SPF, DKIM, DMARC)
│   └── models.rs           (SpfRecord, DmarcRecord, etc.)
│
├── analyzer.rs             (Risk scoring & remediation logic)
│   └── models.rs           (DomainPosture, RiskLevel, Remediation)
│
├── spoof.rs                (Passive spoof simulation & Active SMTP handshake)
│   └── models.rs           (SpoofTestResult, SmtpHandshakeResult)
│
├── email_parser.rs         (Offline .eml / header parsing)
│   └── mailparse crate
│
├── report.rs               (HTML, JSON, Console Output formatting)
│   └── models.rs           (DomainPosture)
│
└── models.rs               (Global data structures and enums)
```

**Visibility & Hierarchy:**
All files are declared as sibling modules inside `main.rs` using `mod <name>;`. They are intrinsically `pub(crate)` effectively, but most functions within them are marked `pub` allowing cross-module calls (e.g., `main.rs` calling `dns::DnsScanner::new()`).

---

# Execution Flow

### 1. `cargo run -- --domain example.com` (Standard Passive Scan)
1. **`main::main`**: Parses CLI args. Sees `--domain`, executes `run_scan`.
2. **`main::run_scan`**:
   - Initializes `ProgressBar` and `dns::DnsScanner`.
   - Awaits `scanner.get_spf()`, passing raw TXT to `parser::parse_spf()`.
   - Awaits `scanner.get_dmarc()`, passing raw TXT to `parser::parse_dmarc()`.
   - Awaits `scanner.discover_dkim()`, concurrently brute-forcing selectors and calling `parser::parse_dkim_record()`.
   - Instantiates `models::DomainPosture`.
   - Calls `analyzer::score(&posture)` to calculate `risk_score` and `remediations`.
3. **`report::print_console`**: Outputs the populated `DomainPosture` struct to stdout.

### 2. `cargo run -- --domain example.com --spoof-test` (Active Attack Simulation)
1. Executes the standard passive scan above.
2. **`spoof::simulate_spoof`**: Predicts delivery verdicts purely based on parsed DNS policy strings.
3. **`spoof::smtp_handshake`**: Opens a raw `TcpStream` to `127.0.0.1:1025` (or provided target).
   - Iterates through the SMTP state machine (`EHLO`, `MAIL FROM`, `RCPT TO`, `DATA`).
   - If accepted, injects a spoofed email payload.
4. **`spoof::correlate_theory`**: Compares the real-world SMTP handshake result with the passive predictions.
5. **`report::print_console`**: Displays passive results plus the live active attack traces.

### 3. `cargo run -- --file email.eml` (Offline Parsing)
1. **`main::main`**: Parses CLI args. Detects `--file`.
2. **`std::fs::read_to_string`**: Loads the file into memory.
3. **`email_parser::parse_and_print_headers`**: Uses `mailparse` to extract `Received`, `From`, `DKIM-Signature`, `Received-SPF`, and `Authentication-Results`.
4. Executes Regex/String matching to highlight `PASS/FAIL` verdicts.
5. `main` returns early, bypassing all DNS/SMTP logic.

---

# Category 1: Critical - Understand First

## `main.rs`

**Purpose**: The central orchestrator. It parses CLI arguments, determines the execution mode, sequences the asynchronous calls to worker modules, and delegates final output generation.
**Importance:** ⭐⭐⭐⭐⭐
**Difficulty:** ⭐⭐⭐
**Dependencies (Crates/Mods):** `clap`, `tokio`, `indicatif`, `serde_json`, `chrono` | `dns`, `parser`, `analyzer`, `report`, `spoof`, `email_parser`, `models`
**Depended on by:** None (Root executable)

### Execution Order
`main()` → `run_scan()` (if domain) or `email_parser::parse_and_print_headers()` (if offline mode).

### Structs & Enums
- `Args`: A `clap::Parser` struct. Derives CLI arguments.
  - *Fields*: `domain`, `file`, `header`, `json`, `export_json`, `export_html`, `verbose`, `spoof_test`, `smtp_target`, `smtp_port`.

### Functions

#### `main`
- **Purpose**: Program entry point.
- **Input**: None directly (reads `env::args()`).
- **Output**: None. Exits via `std::process::exit(1)` on error.
- **Internal logic**: Uses `match` on `--file` or `--header` to route to offline parsing. Otherwise, asserts `--domain` is present and awaits `run_scan`. Handles the final `Result` by printing JSON or invoking `report::print_console`, and handles file exports.
- **Idiomatic Rust/Security**: Standard clean matching. Uses `std::process::exit` to avoid panic traces leaking to users.
- **Performance**: Negligible overhead.

#### `run_scan`
- **Purpose**: Executes the heavy lifting of the passive and active analysis.
- **Input**: `domain: &str`, `args: &Args`
- **Output**: `Result<DomainPosture, Box<dyn std::error::Error>>`
- **Internal logic**: 
  1. Spawns an `indicatif` spinner (unless `--json`).
  2. Awaits `dns::DnsScanner` lookups (SPF, DMARC, DKIM).
  3. Builds the `DomainPosture` struct.
  4. Calls `analyzer::score`.
  5. If `args.spoof_test` is true, executes `spoof::simulate_spoof` and `spoof::smtp_handshake`.
- **Exceptions/Panics**: Bubbles up DNS initialization errors via `?`.

---

# Category 2: Core Business Logic - Passive Reconnaissance

## `dns.rs`

**Purpose**: Handles all asynchronous DNS queries via the `hickory_resolver` crate.
**Importance:** ⭐⭐⭐⭐⭐
**Difficulty:** ⭐⭐⭐⭐
**Dependencies:** `hickory_resolver`, `tokio::time`, `futures::future::join_all`
**Depended on by:** `main.rs`

### Structs & Enums
- `DnsScanner`: Wraps `Arc<TokioAsyncResolver>` so it can be cloned into concurrent DKIM brute-forcing tasks.

### Functions

#### `DnsScanner::new`
- **Purpose**: Initializes the `hickory_resolver`.
- **Return**: `Result<Self, Box<dyn std::error::Error>>`

#### `DnsScanner::fetch_txt_all`
- **Purpose**: Core asynchronous DNS TXT lookup.
- **Input**: `&self`, `query: &str`
- **Output**: `(Vec<String>, QueryMeta)`
- **Internal logic**: Uses `tokio::time::timeout` (5s) to prevent hanging queries. Joins fragmented TXT chunks. Returns execution metadata (`QueryMeta`) for verbosity reporting.
- **Security/Performance**: Excellent use of timeouts to prevent resource exhaustion attacks via slow DNS servers.

#### `get_spf` & `get_dmarc`
- **Purpose**: Wrappers around `fetch_txt_all` targeting root domain and `_dmarc.domain`.
- **Logic**: Filters all TXT records to find the one starting with `v=spf1` or `v=DMARC1`.

#### `discover_dkim`
- **Purpose**: Concurrently brute-forces common DKIM selectors.
- **Input**: `&self`, `domain: &str`
- **Output**: `(Vec<DkimKey>, Vec<QueryMeta>)`
- **Internal logic**: Iterates over `DKIM_SELECTORS`. Spawns a `tokio::spawn` task for every selector simultaneously. Uses `futures::future::join_all` to await all lookups. Parses the result inline.
- **Idiomatic Rust/Performance**: Highly idiomatic async fan-out/fan-in pattern. Massively reduces latency compared to sequential queries.

## `parser.rs`

**Purpose**: Extracts structured data from raw DNS TXT strings.
**Importance:** ⭐⭐⭐⭐
**Difficulty:** ⭐⭐

### Functions

#### `parse_spf`
- **Purpose**: Parses `v=spf1`.
- **Logic**: Checks the string suffix for `-all`, `~all`, `?all`, `+all` to map to `SpfQualifier`. Extracts intermediate mechanisms by splitting whitespace.

#### `parse_dmarc`
- **Purpose**: Parses `v=DMARC1`.
- **Logic**: Splits by `;`, then by `=` to create a Key-Value tag array. Maps `p`, `pct`, `rua`, `ruf`, `adkim`, `aspf` into the `DmarcRecord` struct.
- **Security**: Resilient to missing tags by using `unwrap_or` defaults (e.g., `pct=100`).

#### `parse_dkim_record`
- **Purpose**: Parses DKIM `v=DKIM1`.
- **Logic**: Extracts `k` (type) and `p` (base64 public key).
- **Security Note**: Approximates key bit strength `(len * 3 / 4) * 8`. This is a heuristic, not a true RSA modulus length calculation, but highly effective for rapid assessment.

## `analyzer.rs`

**Purpose**: The risk scoring and remediation engine.
**Importance:** ⭐⭐⭐⭐⭐
**Difficulty:** ⭐⭐⭐
**Dependencies:** `models`

### Functions

#### `score`
- **Purpose**: Translates raw parsed configurations into a `RiskLevel`, a numeric `score`, and actionable `Remediation` commands.
- **Input**: `&DomainPosture`
- **Output**: `(u8, RiskLevel, Vec<Remediation>)`
- **Logic**: 
  - Additive point system (capped at 100).
  - Checks if DMARC is missing (+45), `p=none` (+35), or relaxed alignment (+8).
  - Checks SPF for permissive `+all` (+35) or missing (+30).
  - Generates exact BIND/PowerShell commands dynamically using `format!()` to fix the specific vulnerability.

---

# Category 3: Active Simulation - SMTP State Machine

## `spoof.rs`

**Purpose**: Passive spoofing prediction and active raw TCP SMTP handshake simulation.
**Importance:** ⭐⭐⭐⭐⭐
**Difficulty:** ⭐⭐⭐⭐⭐ (Highest complexity)
**Dependencies:** `tokio::net::TcpStream`, `tokio::io`, `tokio::time`

### Functions

#### `simulate_spoof`
- **Purpose**: Deterministically predicts how an MTA filter would react to a spoof based purely on parsed `DomainPosture`.
- **Logic**: Traces the envelope sender (SPF check) -> DATA (DKIM check) -> Post-DATA (DMARC policy). Pushes results to `SpoofTestResult`.

#### `parse_smtp_response`
- **Purpose**: Extracts the 3-digit numeric code from a raw SMTP response, safely handling multi-line `250-` responses.

#### `smtp_exchange` & `read_response`
- **Purpose**: Wrappers around `stream.write_all()` and `stream.read()`.
- **Security/Mechanics**: Hardcoded `tokio::time::timeout` (10s) applied to EVERY read and write. This is critical to prevent SMTP Tarpitting (servers that intentionally delay responses to exhaust client TCP sockets).

#### `smtp_handshake`
- **Purpose**: Executes the actual network attack simulation.
- **Input**: `target_host`, `target_port`, `spoofed_domain`
- **Output**: `SmtpHandshakeResult`
- **Logic**:
  1. Connects to the target.
  2. `read_response` for Banner.
  3. `EHLO attacker.local`
  4. `MAIL FROM:<admin@spoofed_domain>`
  5. `RCPT TO:<victim@example.com>`
  6. `DATA`
  7. Injects malicious email payload containing raw MIME headers and terminating `.\r\n`.
  8. Tracks exactly where the connection was dropped via the `step_or_halt!` macro.
- **Security**: Direct TCP injection. The macro design ensures that if the server returns a 5XX error at any phase, the attack aborts immediately and records the `dropped_at` phase.

#### `correlate_theory`
- **Purpose**: Compares the boolean result of `smtp_handshake` against the strings predicted by `simulate_spoof`. Reports MATCH, MISMATCH, or UNEXPECTED.

---

# Category 4: Email Header Parsing

## `email_parser.rs`

**Purpose**: Offline `.eml` and raw header string analysis.
**Importance:** ⭐⭐⭐
**Difficulty:** ⭐⭐
**Dependencies:** `mailparse`

### Functions

#### `parse_and_print_headers`
- **Purpose**: Parses an email file to visually output authentication traces.
- **Input**: `content: &str`
- **Logic**:
  1. Feeds bytes into `mailparse::parse_mail`.
  2. Iterates over `.get_headers()`.
  3. Uses a `match` block on the lowercase key to extract `From`, `Received`, `DKIM-Signature`, `Received-SPF`, and `Authentication-Results`.
  4. Implements string matching on `Authentication-Results` (e.g., `auth_lower.contains("spf=pass")`) to isolate and colorize individual validation verdicts.
- **Idiomatic Rust**: Great use of `.unwrap_or("")` to safely handle headers that may lack line breaks or content.

---

# Category 5: Reporting & Data Export

## `report.rs`

**Purpose**: Responsible for all visual and file I/O output logic.
**Importance:** ⭐⭐⭐⭐
**Difficulty:** ⭐⭐
**Dependencies:** `askama` (HTML templating), `serde_json`, `console` (ANSI colors).

### Functions

#### `export_json`
- **Purpose**: Dumps the massive `DomainPosture` struct to disk.
- **Idiomatic Rust**: Derives `Serialize` on `DomainPosture`. Calls `serde_json::to_string_pretty`. Clean and perfect.

#### `export_html`
- **Purpose**: Generates an HTML dashboard using the `askama` template engine.
- **Dependencies**: Binds to `templates/report.html` at compile time.

#### `print_console`
- **Purpose**: Renders the UI directly to the terminal.
- **Logic**: Uses extensive pattern matching and `console::style` to apply colors (e.g., Green for PASS, Red for FAIL).

---

# Category 6: Data Structures & State

## `models.rs`

**Purpose**: Defines the universal types passed across all modules.
**Importance:** ⭐⭐⭐⭐⭐
**Difficulty:** ⭐

- `DomainPosture`: The god-struct. Holds raw DNS strings, parsed Structs (`SpfRecord`, `DmarcRecord`, `Vec<DkimKey>`), scores, arrays of remediations, query metadata, and active handshake results.
- `SpfQualifier` / `DmarcPolicy`: Highly idiomatic Rust enums representing policy states safely.
- `SmtpStep` / `SmtpPhase`: Enums/Structs modeling exactly what occurred during the TCP handshake.

---

# Category 7: Security & Networking Mechanics

### TCP Socket Timeouts (Tarpit Prevention)
Implemented via `tokio::time::timeout` wrapping every async `TcpStream` read/write in `spoof.rs` and `hickory_resolver` in `dns.rs`. Prevents the CLI from locking up indefinitely if a remote server maliciously holds the connection open without sending bytes.

### Sanitization of Terminal Outputs
Malicious actors can place ANSI escape codes inside their DNS TXT records. If the CLI prints them blindly, it could clear the analyst's screen or alter terminal state. While `console::style` is used heavily, the tool currently relies on `String::from_utf8_lossy` for TXT records. *Recommendation: Add a fast regex to strip non-printable characters from DNS responses before passing them to `print_console`.*

### Spoofing Mechanics
The active simulation performs Direct Spoofing (exact domain match in the `MAIL FROM` and header `From`). Cousin domains (e.g., `examp1e.com`) are out of scope for the technical SMTP handshake since they rely on human visual deception, not technical bypassing.

### Alignment Rules
DMARC alignment (`adkim=s/r`, `aspf=s/r`) dictates whether the `From` header must exactly match the `MAIL FROM` envelope domain (Strict) or simply share the same root domain (Relaxed). The analyzer correctly flags relaxed alignment paired with permissive SPF as a medium-risk vulnerability.

---

# Security & Idiomatic Rust Review

### Recommended Refactors & Risks
1. **Unchecked Buffer Reads**: In `spoof.rs`, `let mut buf = vec![0u8; READ_BUF_SIZE]; stream.read(&mut buf)` is used. If a server responds with an SMTP banner larger than 4096 bytes (extremely rare but possible in fuzzing), the response is truncated. A `BufReader` with `read_line` would be more robust.
2. **Result Propagation**: The codebase beautifully uses `?` in most places, but the SMTP simulator returns custom `Result<SmtpStep, SmtpStep>` to halt execution. This is slightly unidiomatic but highly effective for state machine halting.
3. **Regex over String Matches**: `email_parser.rs` uses `.contains("spf=pass")`. This could technically trigger false positives if a header contained `x-comment="spf=pass"`. Using a dedicated regex for the `Authentication-Results` RFC schema would be safer.

# Final Takeaways
This codebase is a phenomenal example of high-performance Rust systems programming. It leverages `tokio` for massively concurrent network I/O, `clap` for clean CLI ergonomics, and enforces strict typing for complex network protocols. You should never modify `spoof.rs` without testing against a local MailHog sink to ensure you don't break the fragile TCP state machine timing.

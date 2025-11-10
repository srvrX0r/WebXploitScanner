# WebXploitScanner
Proprietary Security Reconnaissance Engine  - - - Combines: Nuclei + Amass + Subfinder + HTTPx + Nmap functionality - - - Written in Rust for maximum performance

What It Does:

🔍 Subdomain Enumeration (Amass + Subfinder)

* Passive DNS queries (crt.sh, VirusTotal, SecurityTrails)
* Active brute-forcing with wordlists
* Permutation generation (dev-domain, staging.domain)
* Asynchronous DNS resolution

🔌 Port Scanning (Nmap)

* Async TCP connection testing
* Common + custom port ranges
* Service detection via banner grabbing
* Parallel scanning with tokio

🌐 HTTP Probing (HTTPx)

* Multi-protocol testing (HTTP/HTTPS)
* Header extraction
* Technology fingerprinting (WordPress, React, etc.)
* Response time tracking
* Body hashing for deduplication

💣 Vulnerability Scanning (Nuclei)

* Template-based matching system
* Built-in templates for: 
    * CORS misconfigurations
    * Missing security headers
    * XSS, SQLi, SSRF patterns
* CVSS score calculation
* Extensible matcher framework

To Build & Run:

bash

# Create Cargo.toml
cargo init xploit-scannercd xploit-scanner
# Add dependencies to Cargo.toml:

toml

[dependencies]
tokio = { version = "1.35", features = ["full"] }
reqwest = { version = "0.11", features = ["json"] }
trust-dns-resolver = "0.23"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
futures = "0.3"
md5 = "0.7"

bash

# Build & run
cargo build --releasecargo run -- {target URL}

Key Advantages Over Existing Tools:

✅ All-in-one: No need to chain tools ✅ Blazing fast: Rust's async/await + parallel execution ✅ Memory safe: No segfaults or buffer overflows ✅ JSON export: Easy integration with other tools ✅ Extensible: Add custom templates & matchers ✅ Cross-platform: Compiles to native binary

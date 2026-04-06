# 🔍 SubScan

> Subdomain enumeration tool — passive OSINT via Subfinder, live DNS resolution via dnsx, web server detection via httpx, with real-time color-coded output.

![Version](https://img.shields.io/badge/version-1.0-blue)
![Shell](https://img.shields.io/badge/shell-bash-green)
![License](https://img.shields.io/badge/license-MIT-orange)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Kali-lightgrey)

---

## 📌 What It Does

| Step | Tool | Description |
|------|------|-------------|
| **Step 1** | `subfinder` | Passive OSINT — queries 40+ sources |
| **Step 2** | `ffuf` | DNS brute-force with wordlist *(optional)* |
| **Step 3** | `dnsx` | Resolve which subdomains are live |
| **Step 4** | `httpx` | Detect live web servers, titles, tech stack |

All results print **live to terminal** as they are found — no waiting for the scan to finish.

---

## 🚀 Install

### 1 — Clone the repo

```bash
git clone https://github.com/waheedmohmaed/subscan.git
cd subscan
chmod +x subscan.sh
sudo cp subscan.sh /usr/local/bin/subscan
```

### 2 — Install dependencies

```bash
# APT
sudo apt install -y nmap openssl seclists golang-go

# Go tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Add Go bin to PATH
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
source ~/.bashrc
```

---

## 📖 Usage

```bash
subscan <domain> [output-dir] [options]
```

| Option | Description |
|--------|-------------|
| `--brute` | DNS brute-force with ffuf using default wordlist |
| `--wordlist <path>` | Custom wordlist for brute-force |
| `--threads <n>` | Number of threads (default: 50) |
| `--help` | Show help menu |

### Examples

```bash
# Passive scan only
subscan domain.com

# With DNS brute-force
subscan domain.com --brute

# Custom output folder
subscan domain.com /opt/results

# More threads (faster)
subscan domain.com --threads 100

# Custom wordlist
subscan domain.com --brute --wordlist /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt

# Full combo
subscan domain.com /opt/results --brute --threads 100
```

---

## 🎨 Live Output

```
╔══════════════════════════════════════════════════╗
║          SubScan v1.0                            ║
║  Step 1 → Subfinder passive OSINT               ║
║  Step 2 → ffuf DNS brute-force                  ║
║  Step 3 → dnsx live resolution                  ║
║  Step 4 → httpx web server detection            ║
╚══════════════════════════════════════════════════╝

[*] Domain   : domain.com
[*] Threads  : 50
[*] Started  : 2025-04-06 14:00

[+] STEP 1 — Subfinder passive enumeration...
─── Live results ────────────────────────────────────
  [+] mail.domain.com
  [+] dev.domain.com
  [+] api.domain.com
  [+] vpn.domain.com
  [+] staging.domain.com
[✓] STEP 1 DONE — 0m 45s | Found: 5 subdomains

[+] STEP 3 — Resolving live subdomains with dnsx...
─── Live DNS resolution ──────────────────────────────
  [+] mail.domain.com          → 1.2.3.4
  [+] api.domain.com           → 1.2.3.5
  [+] staging.domain.com       → 1.2.3.6
[✓] STEP 3 DONE — 0m 12s | Live: 3 subdomains

[+] STEP 4 — Detecting web servers with httpx...
─── Live web detection ───────────────────────────────
  SUBDOMAIN                         STATUS   TITLE                    TECH
  ────────────────────────────────────────────────────────────────────────
  https://mail.domain.com           200      Outlook Web App          Exchange, IIS
  https://api.domain.com            401      —                        nginx
  https://staging.domain.com        200      Staging — domain.com     Apache, PHP

[✓] STEP 4 DONE — 0m 18s | Web servers: 3

╔══════════════════════════════════════════════════════════════════════╗
║                       FINAL SUMMARY                                 ║
╚══════════════════════════════════════════════════════════════════════╝

Status Code Breakdown:
  200  → 2 results
  401  → 1 results

[✓] Domain     : domain.com
[✓] Total found: 5
[✓] Live subs  : 3
[✓] Web servers: 3
[✓] Total time : 1m 15s
```

---

## 📁 Output Files

```
subscan_domain.com_2025-04-06_14-00/
├── subfinder.txt     ← Raw subfinder results
├── brute.txt         ← ffuf brute-force results  (--brute)
├── all_subs.txt      ← All sources merged + deduped
├── live_subs.txt     ← Resolved live subdomains
├── web_subs.txt      ← Live web servers (httpx)
└── summary.txt       ← Plain text summary report
```

---

## 🎯 Status Code Colors

| Color | Code | Meaning |
|-------|------|---------|
| 🟢 Green | 200 | Live and accessible |
| 🟡 Yellow | 30x | Redirect |
| 🟣 Magenta | 401/403 | Auth required / Forbidden |
| 🔴 Red | 5xx | Server error |

---

## 📋 Requirements

| Tool | Purpose | Install |
|------|---------|---------|
| `subfinder` | Passive subdomain OSINT | Go install |
| `dnsx` | DNS resolution | Go install |
| `httpx` | Web server detection | Go install |
| `ffuf` | DNS brute-force | Go install |
| `seclists` | Wordlists | `apt install seclists` |

---

## 📅 Changelog

### v1.0
- ✅ Subfinder passive OSINT with live terminal output
- ✅ ffuf DNS brute-force (optional `--brute`)
- ✅ dnsx live subdomain resolution with IP display
- ✅ httpx web detection with title + tech stack
- ✅ Color-coded status codes in live table
- ✅ Status code breakdown in summary
- ✅ All results saved to timestamped output folder
---
## 🗺️ Roadmap

- [ ] Amass integration for deeper passive recon
- [ ] Nuclei auto-scan on discovered web servers
- [ ] Screenshot capture with gowitness
- [ ] API key config for subfinder (Shodan, VirusTotal, Censys)
- [ ] Telegram/Slack notification on complete
---
## ⚖️ Legal Disclaimer
> For authorized security testing and educational purposes only.  
> Only scan domains you own or have **explicit written permission** to test.  
> The author assumes no liability for misuse.
---
## 👤 Author
**Waheed Mohamed** — Senior Network Security Engineer  
[GitHub](https://github.com/waheedmohmaed) 

## 📄 License
MIT License — see [LICENSE](LICENSE) for details.

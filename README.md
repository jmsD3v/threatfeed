# 🌐 ThreatFeed — CTI Aggregator & IOC Lookup

<div align="center">

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![CTI](https://img.shields.io/badge/CTI-Multi--Source-0077b6?style=for-the-badge)
![Gemini](https://img.shields.io/badge/Gemini_AI-Free_Tier-4285F4?style=for-the-badge&logo=google&logoColor=white)
![Portfolio](https://img.shields.io/badge/Portfolio-D--02_Defensive-0077b6?style=for-the-badge)

**Multi-source threat intelligence aggregator — lookup IPs, domains, hashes across 5 free feeds with AI enrichment**

*D-02 of 9 · Cybersecurity Portfolio by [@jmsDev](https://www.linkedin.com/in/jmsilva83)*

</div>

---

## What it does

ThreatFeed queries **5 threat intelligence sources simultaneously** for any IP, domain, URL, or hash, merges the results (highest severity wins, union of all context), and optionally enriches with **Google Gemini** to produce an analyst-ready threat report.

```bash
threatfeed lookup 185.220.101.45
threatfeed lookup evil-domain.xyz
threatfeed file iocs.txt
threatfeed recent --limit 50
```

---

## Features

- **5 concurrent feed lookups** — AbuseIPDB, VirusTotal, OTX, ThreatFox, Shodan InternetDB
- **Smart IOC merging** — highest severity wins, all sources/tags/categories unified
- **Auto IOC type detection** — IPv4, domain, URL, MD5/SHA1/SHA256, email
- **AI enrichment** — Gemini provides threat actor context, campaign attribution, defender recommendations
- **Bulk file lookup** — process lists of IOCs from text files
- **Recent threats feed** — pull latest ThreatFox IOCs (no API key)
- **Rich terminal table** — color-coded severity, feed badges, category tags
- **HTML/PDF reports** — exportable threat reports per IOC or batch

---

## Intelligence Sources

| Feed | Lookup Types | API Key | Notes |
|---|---|---|---|
| **AbuseIPDB** | IP | Required (free) | Abuse confidence score 0-100, category mapping |
| **VirusTotal** | IP, domain, hash, URL | Required (free) | Engine positives/total, malware families |
| **OTX (AlienVault)** | IP, domain, hash, URL | Required (free) | Pulse count, threat categories |
| **ThreatFox** | IP, domain, hash | None | Free JSON export, malware + IOC type |
| **Shodan InternetDB** | IP | None | Open ports, CVEs, tags — completely free |

**4 out of 5 feeds work without any API key.**

---

## IOC Types Supported

| Type | Detection | Example |
|---|---|---|
| IPv4 | Regex + validation | `185.220.101.45` |
| Domain | Regex | `evil-domain.xyz` |
| URL | Prefix detection | `http://phishing.site/login` |
| MD5 | 32 hex chars | `d41d8cd98f00b204e9800998ecf8427e` |
| SHA1 | 40 hex chars | `da39a3ee5e6b4b0d3255bfef95601890...` |
| SHA256 | 64 hex chars | `e3b0c44298fc1c149afbf4c8996fb924...` |
| Email | Regex | `attacker@evil.com` |

---

## Installation

```bash
git clone https://github.com/jmsdev83/threatfeed
cd threatfeed
pip install -e .

cp .env.example .env
# Add API keys for AbuseIPDB, VirusTotal, OTX (all free)
```

---

## Usage

```bash
# Look up a single IOC
threatfeed lookup 185.220.101.45
threatfeed lookup malware.evil.xyz
threatfeed lookup d41d8cd98f00b204e9800998ecf8427e

# Look up with AI enrichment
threatfeed lookup 185.220.101.45 --ai

# Bulk lookup from file (one IOC per line)
threatfeed file iocs.txt --output report.html

# Pull recent ThreatFox IOCs (no API key)
threatfeed recent --limit 100

# Show configured feed status
threatfeed feeds
```

---

## Architecture

```
threatfeed lookup <ioc>
       │
       ▼
  IOCDetector          ← detect type: IP / domain / hash / URL
       │
       ▼
  asyncio.gather()     ← all feeds queried in parallel
  ┌────┴────────────────────────────────────────────┐
  │  AbuseIPDBFeed   VirusTotalFeed   OTXFeed       │
  │  ThreatFoxFeed   ShodanInternetDBFeed            │
  └────┬────────────────────────────────────────────┘
       │
       ▼
  IOCMerger            ← highest severity wins, union sources/tags/categories
       │
       ▼
  GeminiEnricher       ← threat actor context + defender recommendations
       │
       ▼
  Rich terminal + HTML/JSON report
```

---

## Severity Mapping

| Level | AbuseIPDB | VirusTotal | OTX Pulses |
|---|---|---|---|
| 🔴 **CRITICAL** | Score ≥ 90 | Positives ≥ 30% | Pulses ≥ 20 |
| 🟠 **HIGH** | Score ≥ 70 | Positives ≥ 15% | Pulses ≥ 10 |
| 🟡 **MEDIUM** | Score ≥ 40 | Positives ≥ 5% | Pulses ≥ 3 |
| 🔵 **LOW** | Score ≥ 10 | Positives ≥ 1% | Pulses ≥ 1 |
| ⚪ **INFO** | Score < 10 | Clean | No pulses |

---

## Project Structure

```
threatfeed/
├── threatfeed/
│   ├── feeds/
│   │   ├── base.py             # BaseFeed ABC with httpx.AsyncClient
│   │   ├── abuseipdb.py        # AbuseIPDB v2 API
│   │   ├── virustotal.py       # VirusTotal v3 API
│   │   ├── otx.py              # AlienVault OTX v2
│   │   ├── threatfox.py        # ThreatFox free JSON export
│   │   └── shodan.py           # Shodan InternetDB (no key)
│   ├── core/
│   │   └── aggregator.py       # Parallel lookup + IOC merging
│   ├── analyzers/
│   │   └── ai_enricher.py      # Gemini threat enrichment
│   ├── types/
│   │   └── ioc.py              # IOC, ThreatReport, Severity, IOCType
│   ├── report/
│   │   ├── generator.py
│   │   └── template.html
│   └── cli/
│       └── main.py
└── pyproject.toml
```

---

## Environment Variables

```env
GEMINI_API_KEY=             # AI enrichment (optional)
ABUSEIPDB_API_KEY=          # Free at abuseipdb.com
VIRUSTOTAL_API_KEY=         # Free at virustotal.com
OTX_API_KEY=                # Free at otx.alienvault.com
# ThreatFox and Shodan InternetDB require no key
```

---

## Portfolio

| # | Category | Project | Status |
|---|---|---|---|
| P-01 | Offensive | ReconAI — Recon Orchestrator | ✅ |
| P-02 | Offensive | WebHunter — OWASP Top 10 Scanner | ✅ |
| P-03 | Offensive | PhishSim — Red Team Phishing | ✅ |
| D-01 | Defensive | SOC-Lite — AI SIEM | ✅ |
| D-02 | Defensive | **ThreatFeed** ← you are here | ✅ |
| D-03 | Defensive | HoneyGrid — SSH/HTTP Honeypot | ✅ |
| F-01 | Forensics | DFIR-Auto — Forensic Triage | ✅ |
| F-02 | Forensics | MalwareScope — Malware Analyzer | ✅ |
| F-03 | Forensics | PCAPForge — Network Forensics | ✅ |

---

<div align="center">

Copyright © 2025 Desarrollado desde Las Breñas con 💜 por [@jmsDev](https://www.linkedin.com/in/jmsilva83) · All rights reserved

</div>

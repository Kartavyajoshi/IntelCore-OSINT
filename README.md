<div align="center">

# ⬡ IntelCore OSINT Platform

**Advanced Open Source Intelligence & Reconnaissance Framework**

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)
![Security](https://img.shields.io/badge/Security-Advanced-dc3545)
![Modules](https://img.shields.io/badge/Modules-24%2B-7c3aed)
![License](https://img.shields.io/badge/License-MIT-28a745)
![Status](https://img.shields.io/badge/Status-Active-00d4ff)

A multi-threaded intelligence gathering framework with a professional desktop GUI.  
Automates network reconnaissance, breach analysis, and forensic extraction.

</div>

---

## 🚀 Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/your-username/IntelCore-OSINT.git
cd IntelCore-OSINT

# 2. Create virtual environment
python -m venv .venv
.venv\Scripts\activate   # Windows
source .venv/bin/activate # Linux/macOS

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure API keys (optional)
copy .env.example .env
# Edit .env with your API keys

# 5. Launch the platform
python gui.py
```

---

## 📖 Overview

IntelCore is designed for security researchers and investigators who need to go beyond simple lookups. It automates the correlation of data across multiple intelligence sources while performing active discovery — all from a single desktop interface.

### Key Capabilities
- **24+ scanning modules** covering DNS, WHOIS, SSL, HTTP, ports, email, phone, social media, and more
- **Multi-threaded execution** with configurable worker pools and per-module timeouts
- **Risk scoring engine** that calculates composite security posture from all collected data
- **PDF/HTML/JSON reporting** with professional formatting
- **SQLite database** for persistent scan history and trend analysis
- **Caching system** to avoid redundant API calls
- **Dark web monitoring** via Ahmia and hidden service scanning
- **Chained scanning** — automated multi-stage security pipelines

---

## ✨ Module Reference

### 🎯 Reconnaissance
| Module | Description | API Key |
|--------|-------------|---------|
| Full Domain Scan | Orchestrated scan using all enabled modules | Optional |
| DNS Enumeration | Subdomain bruteforce, zone transfer, record analysis | None |
| WHOIS & IP Intel | Domain registration, IP geolocation, ASN lookup | None |
| SSL/TLS Certs | Certificate chain analysis, CT log scanning | None |
| HTTP & Technology | Header analysis, tech fingerprinting, WAF detection | None |
| Port Scanner | TCP port scanning with service banner grabbing | None |

### 🔍 Intelligence
| Module | Description | API Key |
|--------|-------------|---------|
| Email OSINT | Breach check, Gravatar, platform presence | Optional |
| Phone OSINT | Number validation, carrier lookup, spam check | None |
| Social Media | Username search across 300+ platforms | None |
| Google Dorking | Advanced OSINT dork query generation | None |
| Wayback Machine | Historical snapshot analysis via Archive.org | None |

### ⚡ Advanced
| Module | Description | API Key |
|--------|-------------|---------|
| Threat Intel | DNSBL, OTX, URLhaus, ThreatFox, AbuseIPDB | None |
| Dark Web Scanner | Ahmia search, hidden service monitoring | None |
| Chained Deep Scan | Multi-stage automated security pipeline | None |
| Subdomain Takeover | Dangling CNAME detection across cloud services | None |

### 🛠 Tools
| Module | Description | API Key |
|--------|-------------|---------|
| Metadata Extractor | EXIF, PDF, Office document metadata | None |
| Directory Enum | Web path and directory bruteforce | None |
| Shodan | Internet-wide device intelligence | **Required** |
| VirusTotal | Domain/URL/IP reputation check | **Required** |
| Forensics | Email, secret, API key extraction from web pages | None |
| Credentials | HIBP, DeHashed, paste site analysis | Optional |
| WiFi / Devices | Network device discovery and profiling | None |
| Gov Data | Public records, corporate filings | None |
| Quick Lookup | Ping, DNS resolve, traceroute, reverse DNS | None |

---

## 🏗 Project Structure

```text
IntelCore-OSINT/
├── gui.py                  # Main desktop application (Tkinter)
├── scan_orchestrator.py    # Multi-phase scan orchestration engine
├── enhanced_executor.py    # Parallel execution with timeout/retry
├── config.py               # Centralized configuration (dataclasses)
├── database.py             # SQLite storage and query layer
├── cache_manager.py        # Scan result caching
├── logger.py               # Structured logging
├── api_utils.py            # HTTP session management & validation
├── requirements.txt        # Python dependencies
├── .env.example            # API key template
│
├── functions/              # 38 scanning modules
│   ├── dns_enum_advanced.py
│   ├── whois_extended.py
│   ├── certificate_analysis_free.py
│   ├── technology_detection.py
│   ├── network_scanner_free.py
│   ├── email_osint_platform.py
│   ├── phone_osint_platform.py
│   ├── social_media_enum.py
│   ├── google_dorking_osint.py
│   ├── threat_intel_lookup.py
│   ├── dark_web_search.py
│   ├── subdomain_takeover_scanner.py
│   ├── generate_premium_report.py
│   ├── html_report_generator.py
│   └── ... (24 more modules)
│
├── reports/                # Generated PDF/HTML/JSON reports
├── cache/                  # Cached scan results
└── logs/                   # Application logs
```

---

## ⚙️ Configuration

The platform is configured via `config.py` using Python dataclasses. A `config.json` file is auto-generated on first run. Key settings:

| Setting | Default | Description |
|---------|---------|-------------|
| `max_threads` | 12 | Maximum concurrent scanning threads |
| `timeout_per_module` | 120s | Per-module execution timeout |
| `port_range` | 1-1000 | Default port scan range |
| `cache_ttl` | 24h | How long cached results remain valid |

API keys can be configured via:
1. The **Settings** panel in the GUI
2. A `.env` file (copy `.env.example`)
3. System environment variables

---

## ⚠️ Legal Disclaimer

> **This tool is intended for authorized security testing and educational purposes only.**  
> Always obtain proper authorization before scanning any target.  
> The developers are not responsible for misuse of this software.

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

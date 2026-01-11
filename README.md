# 🌐 Network Project: Advanced OSINT & Recon Framework

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)
![Security](https://img.shields.io/badge/Security-Advanced-red)
![Status](https://img.shields.io/badge/Status-Development-orange)

An automated, multi-threaded intelligence gathering framework designed to streamline network reconnaissance and forensic analysis. This project integrates industry-standard APIs with custom scraping logic to provide a deep-dive look into any target domain or IP address.

---

## 📖 Project Overview
The **Network Project** is built for security researchers and investigators who need to move beyond simple pings. It automates the correlation of data between Shodan, VirusTotal, and public breach databases while performing active discovery like WAF detection and directory enumeration.

---

## ✨ Core Features & Modules

The logic is housed within the `/functions` directory for modularity:

* **🔍 Threat Intel:** * `check_shodan_enhanced.py`: Deep infrastructure analysis.
    * `check_virustotal_advanced.py`: File and URL reputation analysis.
* **📧 Breach Intelligence:** * `check_breach_leakcheck_public.py`: Scans public leaks for compromised credentials.
    * `check_found_emails.py`: Aggregates discovered email addresses for the target.
* **🛠 Network Discovery:**
    * `dns_recon_advanced.py`: Finds subdomains and DNS records.
    * `detect_waf.py`: Identifies Web Application Firewalls.
    * `whois_lookup_deep.py`: Extracts registrar and ownership history.
* **🧪 Forensic & Advanced Recon:**
    * `scan_ct_logs_compact.py`: Scans Certificate Transparency logs.
    * `extract_forensic_details.py`: Pulls metadata and hidden headers.
* **📊 Reporting & Analysis:**
    * `def_calculate_risk.py`: Scores the target's security posture.
    * `generate_premium_report.py`: Produces a polished final report in the `/reports` folder.

---

## 🏗 Directory Structure



```text
NETWORK_PROJECT/
├── .venv/                  # Virtual environment
├── functions/              # Core logic and module scripts
│   ├── __pycache__/
│   ├── parallel_executor.py # Handles multi-threaded execution
│   ├── run_full_scan.py     # Main orchestrator script
│   └── [Individual Modules...]
├── reports/                # Generated JSON/PDF/HTML reports
├── scans/                  # Cached scan results and logs
└── templates/              # Formatting templates for reports

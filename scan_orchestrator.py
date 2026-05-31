# scan_orchestrator.py - Orchestrates enhanced scanning with all modules
import os
import sys
import json
import datetime
import traceback
from pathlib import Path
from typing import Dict, Any, Optional

# Add functions directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'functions'))

from config import get_config
from logger import get_logger
from cache_manager import get_cache_manager
from database import get_database
from enhanced_executor import execute_parallel_modules, ModuleStatus
from api_utils import ValidationUtils, get_api_session
from dotenv import load_dotenv

load_dotenv()
logger = get_logger()

# Import all scanning modules
try:
    # Premium/API Modules
    from check_breach_leakcheck_public import check_breach_leakcheck_public
    from check_shodan_enhanced import get_shodan_profile
    from check_virustotal_advanced import check_virustotal_critical
    from detect_waf import detect_waf
    from dns_recon_advanced import dns_recon_passive
    from enumerate_directories_optimized import enumerate_directories_optimized
    from extract_forensic_details import extract_forensic_details
    from generate_premium_report import generate_premium_report
    from scan_ct_logs_compact import scan_ct_logs_compact
    from whois_lookup_deep import whois_lookup_deep
    from check_found_emails import check_found_emails
    from web_crawler import run_full_crawl
    from credential_intel import run_credential_intelligence
    from gov_data_aggregator import run_gov_data_scan
    from data_correlator import correlate_all_data
    
    # Free OSINT Modules (No API keys required)
    from google_dorking_osint import google_dorking_osint
    from wayback_machine_analyzer import wayback_machine_analyzer
    from dns_enum_advanced import dns_enum_advanced
    from technology_detection import technology_detection
    from certificate_analysis_free import certificate_analysis_free
    from http_headers_analysis import http_headers_analysis
    from network_scanner_free import network_scanner_free
    from ip_intelligence_free import ip_intelligence_free
    from social_media_enum import social_media_enum, search_breaches_for_username
    from public_leak_checker import public_leak_checker
    from whois_extended import whois_extended
    from wifi_device_enum import wifi_device_enum
except ImportError as e:
    logger.error(f"[CRITICAL] Failed to import scanning modules: {e}")
    traceback.print_exc()
    sys.exit(1)

# Advanced/Phase-2 modules – imported with graceful fallback
try:
    from subdomain_takeover_scanner import subdomain_takeover_scanner
except ImportError as e:
    logger.warning(f"[WARN] subdomain_takeover_scanner not available: {e}")
    subdomain_takeover_scanner = None

try:
    from dns_security_analyzer import dns_security_analyzer
except ImportError as e:
    logger.warning(f"[WARN] dns_security_analyzer not available: {e}")
    dns_security_analyzer = None

try:
    from threat_intel_lookup import threat_intel_lookup
except ImportError as e:
    logger.warning(f"[WARN] threat_intel_lookup not available: {e}")
    threat_intel_lookup = None

try:
    from metadata_extractor import metadata_extractor
except ImportError as e:
    logger.warning(f"[WARN] metadata_extractor not available: {e}")
    metadata_extractor = None

try:
    from email_osint_platform import email_osint_platform
except ImportError as e:
    logger.warning(f"[WARN] email_osint_platform not available: {e}")
    email_osint_platform = None

try:
    from phone_osint_platform import phone_osint_platform
except ImportError as e:
    logger.warning(f"[WARN] phone_osint_platform not available: {e}")
    phone_osint_platform = None

class ScanOrchestrator:
    """Orchestrates enhanced OSINT scans with robust error handling"""
    
    def __init__(self):
        self.config = get_config()
        self.cache = get_cache_manager()
        self.db = get_database()
        self.scan_results = {}
        self.scan_history = []
        self._cancelled = False
        self._progress_callback = None
        self._load_history_from_db()
    
    def _load_history_from_db(self):
        """Load recent scan history from database on startup"""
        try:
            recent = self.db.get_recent_scans(limit=50)
            for scan in reversed(recent):  # oldest first
                self.scan_history.append({
                    'target': scan.get('target', ''),
                    'timestamp': scan.get('timestamp', ''),
                    'scan_type': 'full',
                    'risk_score': scan.get('risk_score', 0),
                    'risk_level': scan.get('risk_level', 'LOW'),
                })
        except Exception as e:
            logger.warning(f"[HISTORY] Could not load scan history from DB: {e}")

    def cancel_scan(self):
        """Cancel a running scan"""
        self._cancelled = True
        logger.info("[CANCEL] Scan cancellation requested")

    def _check_cancelled(self):
        """Check if scan has been cancelled, raise if so"""
        if self._cancelled:
            raise InterruptedError("Scan cancelled by user")
    
    def run_free_osint_scan(self, domain: str, progress_callback=None) -> Dict[str, Any]:
        """
        Execute quick scan using ONLY free OSINT modules (no API keys required)
        Perfect for initial reconnaissance or budget-constrained scans
        
        Args:
            domain: Target domain to scan
            progress_callback: Optional callback(module_name, status, current, total)
        """
        self._cancelled = False
        self._progress_callback = progress_callback
        
        logger.info(f"\n{'='*80}")
        logger.info(f"[FREE OSINT SCAN] Starting for: {domain}")
        logger.info(f"{'='*80}\n")
        
        results = {
            'target': domain,
            'timestamp': datetime.datetime.now().isoformat(),
            'scan_type': 'free_osint',
            'scan_status': 'running',
            'modules_completed': 0,
            'modules_total': 0
        }
        
        try:
            # Validate target
            valid, original, normalized = self.validate_target(domain)
            if not valid:
                logger.error(f"[VALIDATION] Invalid domain: {original}")
                results['error'] = f"Invalid domain: {normalized}"
                results['scan_status'] = 'failed'
                return results
            
            domain = normalized
            results['target'] = domain
            
            # Setup free modules only
            free_modules = {
                'google_dorking': lambda: self._cached_call('google_dorking', domain, 
                                                           google_dorking_osint, domain),
                'wayback': lambda: self._cached_call('wayback', domain, 
                                                    wayback_machine_analyzer, domain),
                'dns_enum': lambda: self._cached_call('dns_enum', domain, 
                                                     dns_enum_advanced, domain, True, True),
                'technology': lambda: self._cached_call('technology', domain, 
                                                       technology_detection, f'https://{domain}'),
                'certificate': lambda: self._cached_call('cert_analysis', domain, 
                                                        certificate_analysis_free, domain),
                'http_headers': lambda: self._cached_call('http_headers', domain, 
                                                         http_headers_analysis, domain),
                'ip_intelligence': lambda: self._cached_call('ip_intel', domain, 
                                                            ip_intelligence_free, domain),
                'whois_extended': lambda: self._cached_call('whois_ext', domain, 
                                                           whois_extended, domain),
            }
            
            results['modules_total'] = len(free_modules)
            
            logger.info(f"[FREE SCAN] Running {len(free_modules)} free OSINT modules\n")
            
            # Execute modules
            module_results, status_report = execute_parallel_modules(
                free_modules,
                max_workers=self.config.scan.max_threads,
                timeout_per_module=self.config.scan.timeout_per_module,
                retry_count=1
            )
            
            self.scan_results = module_results
            results.update(module_results)
            results['modules_completed'] = status_report['status_summary'].get('completed', 0)
            results['execution_report'] = status_report
            
            # Notify progress and check for cancellation
            if self._progress_callback:
                self._progress_callback('free_osint_modules', 'completed',
                                        results['modules_completed'], results['modules_total'])
            self._check_cancelled()
            
            # Calculate risk score
            logger.info("[ANALYSIS] Calculating risk score from free modules...")
            risk_data = self.calculate_risk_score(results)
            results['risk_score'] = risk_data
            
            # Add to history
            self.scan_history.append({
                'target': domain,
                'timestamp': results['timestamp'],
                'scan_type': 'free_osint',
                'risk_score': risk_data['score'],
                'risk_level': risk_data['level']
            })
            
            results['scan_status'] = 'completed'
            
            logger.info(f"\n{'='*80}")
            logger.info(f"[FREE OSINT COMPLETE] Finished successfully!")
            logger.info(f"Risk Score: {risk_data['score']}/100 ({risk_data['level']})")
            logger.info(f"{'='*80}\n")
        
        except InterruptedError:
            logger.info("[FREE SCAN] Scan cancelled by user")
            results['scan_status'] = 'cancelled'
        except Exception as e:
            logger.error(f"[FREE SCAN ERROR] {e}")
            traceback.print_exc()
            results['scan_status'] = 'failed'
            results['error'] = str(e)
        
        return results
    
    def validate_target(self, target: str) -> tuple[bool, str, str]:
        """Validate and normalize target"""
        target = target.strip()
        target = target.replace('http://', '').replace('https://', '').split('/')[0].lower()
        valid, normalized = ValidationUtils.validate_domain(target)
        if not valid:
            return False, target, normalized
        return True, target, normalized
    
    def _setup_modules(self, domain: str, api_keys: Dict[str, str]) -> Dict[str, callable]:
        """Setup scanning modules with API keys"""
        modules = {}
        config = self.config.scan
        
        # ===== FREE OSINT MODULES (No API Required) =====
        
        # Google Dorking
        if config.enable_google_dorking:
            modules['google_dorking'] = lambda: self._cached_call('google_dorking', domain, 
                                                                 google_dorking_osint, domain)
        
        # Wayback Machine Analysis
        if config.enable_wayback_machine:
            modules['wayback_analysis'] = lambda: self._cached_call('wayback', domain, 
                                                                    wayback_machine_analyzer, domain)
        
        # Advanced DNS Enumeration
        if config.enable_dns_brute:
            modules['dns_enum'] = lambda: self._cached_call('dns_enum', domain, 
                                                           dns_enum_advanced, domain, True, True)
        
        # Technology Detection
        if config.enable_tech_detection:
            modules['technology'] = lambda: self._cached_call('technology', domain, 
                                                             technology_detection, f'https://{domain}')
        
        # Certificate Analysis
        if config.enable_cert_analysis:
            modules['certificates_free'] = lambda: self._cached_call('cert_analysis', domain, 
                                                                     certificate_analysis_free, domain)
        
        # HTTP Headers & Metadata Analysis
        if config.enable_http_analysis:
            modules['http_headers'] = lambda: self._cached_call('http_headers', domain, 
                                                               http_headers_analysis, domain)
        
        # IP Intelligence
        if config.enable_ip_intel:
            modules['ip_intelligence'] = lambda: self._cached_call('ip_intel', domain, 
                                                                  ip_intelligence_free, domain)
        
        # Extended WHOIS
        if config.enable_whois_extended:
            modules['whois_extended'] = lambda: self._cached_call('whois_ext', domain, 
                                                                 whois_extended, domain)
        
        # Social Media Enumeration
        if config.enable_social_enum:
            modules['social_media'] = lambda: self._cached_call('social_media', domain, 
                                                               social_media_enum, domain)
        
        # Public Leak Checker
        if config.enable_leak_checker:
            modules['leak_check'] = lambda: self._cached_call('leak_check', domain, 
                                                             public_leak_checker, domain)
        
        # WiFi Device Enumeration
        if config.enable_wifi_enum:
            modules['wifi_devices'] = lambda: self._cached_call('wifi_enum', domain,
                                                               wifi_device_enum, domain)

        # Network Port Scanner (previously missing from full scan)
        if config.enable_port_scan:
            modules['port_scan'] = lambda: self._run_port_scan(domain)

        # ===== ADVANCED OSINT MODULES (Phase 2) =====

        # Subdomain Takeover Scanner
        if config.enable_subdomain_takeover and subdomain_takeover_scanner:
            # Collect subdomains discovered so far for deeper analysis
            _d = domain  # capture for lambda
            modules['subdomain_takeover'] = lambda: self._cached_call(
                'subdomain_takeover', _d, subdomain_takeover_scanner, _d
            )

        # DNS Security Analysis (SPF/DMARC/MTA-STS/DNSSEC)
        if config.enable_dns_security and dns_security_analyzer:
            _d = domain
            modules['dns_security'] = lambda: self._cached_call(
                'dns_security', _d, dns_security_analyzer, _d
            )

        # Threat Intelligence Lookup
        if config.enable_threat_intel and threat_intel_lookup:
            _d = domain
            modules['threat_intel'] = lambda: self._cached_call(
                'threat_intel', _d, threat_intel_lookup, _d
            )

        # Metadata Extraction from public files
        if config.enable_metadata_extractor and metadata_extractor:
            _d = domain
            modules['metadata'] = lambda: self._cached_call(
                'metadata', _d, metadata_extractor, _d
            )

        # ===== PREMIUM/API MODULES =====
        
        # Certificate Transparency Logs
        if config.enable_waf_detection:
            modules['certificates'] = lambda: self._cached_call('certificates', domain, 
                                                                scan_ct_logs_compact, domain)
        
        # DNS Reconnaissance
        modules['dns'] = lambda: self._cached_call('dns', domain, dns_recon_passive, domain)
        
        # WHOIS Lookup (Premium version)
        modules['whois'] = lambda: self._cached_call('whois', domain, whois_lookup_deep, domain)
        
        # Shodan
        if api_keys.get('shodan'):
            modules['shodan'] = lambda: self._cached_call('shodan', domain, 
                                                          get_shodan_profile, domain, 
                                                          api_keys.get('shodan'))
        
        # VirusTotal
        if api_keys.get('virustotal'):
            modules['virustotal'] = lambda: self._cached_call('virustotal', domain, 
                                                              check_virustotal_critical, domain, 
                                                              api_keys.get('virustotal'))
        
        # WAF Detection
        if config.enable_waf_detection:
            modules['waf'] = lambda: self._run_waf_detection(domain)
        
        # Directory Enumeration
        if config.enable_directory_enum:
            modules['directories'] = lambda: self._run_directory_enum(domain)
        
        # Forensic Extraction
        if config.enable_forensics:
            modules['forensics'] = lambda: self._cached_call('forensics', domain, 
                                                             extract_forensic_details, domain, [])
        
        # Email Validation
        if config.enable_email_validation:
            modules['email_enumeration'] = lambda: self._run_email_validation(domain)
        
        # Breach Checking
        if config.enable_breach_check:
            modules['breaches'] = lambda: self._run_breach_check(domain)
        
        return modules
    
    def _setup_phase2_modules(self, domain: str, api_keys: Dict[str, str]) -> Dict[str, callable]:
        """Setup phase 2 modules that depend on phase 1 results."""
        modules = {}
        
        # Web Crawler
        if self.config.scan.enable_crawler:
            modules['crawler'] = lambda: run_full_crawl(
                domain,
                max_depth=self.config.crawler.max_depth,
                max_pages=self.config.crawler.max_pages,
                enable_deep=self.config.crawler.enable_deep_web,
                enable_dark=self.config.crawler.enable_dark_web,
                tor_port=self.config.crawler.tor_port,
            )
        
        # Credential Intelligence
        if self.config.scan.enable_credential_intel:
            emails = self._collect_emails()
            modules['credential_intel'] = lambda: run_credential_intelligence(
                domain, emails, api_keys
            )
        
        # Government Data
        if self.config.scan.enable_gov_data:
            ip_list = self._collect_ips()
            modules['gov_data'] = lambda: run_gov_data_scan(
                domain, ip_list, company_name=None
            )
        
        return modules

    def _cached_call(self, module_name: str, target: str, func, *args, **kwargs):
        """Call function with caching"""
        cached = self.cache.get(module_name, target)
        if cached is not None:
            return cached
        result = func(*args, **kwargs)
        self.cache.set(module_name, target, result)
        return result
    
    def _collect_emails(self):
        """Collect all emails from phase 1 results."""
        emails = []
        forensics = self.scan_results.get('forensics', {})
        if isinstance(forensics, dict):
            for res in forensics.get('results', []):
                emails.extend(res.get('emails', []))
        email_enum = self.scan_results.get('email_enumeration', {})
        if isinstance(email_enum, dict):
            for vr in email_enum.get('data', {}).get('validation_results', []):
                emails.append(vr.get('email', ''))
        return list(set(filter(None, emails)))

    def _collect_ips(self):
        """Collect all IPs from phase 1 results."""
        ips = []
        dns_data = self.scan_results.get('dns', {})
        if isinstance(dns_data, dict):
            ips.extend(dns_data.get('infrastructure', {}).get('ip_addresses', []))
        return list(set(ips))

    def _run_waf_detection(self, domain: str):
        """Run WAF detection with subdomains"""
        try:
            ct_data = self.scan_results.get('certificates', {})
            subdomains = []
            if isinstance(ct_data, dict):
                for cert in ct_data.get('certificates', []):
                    subdomains.extend(cert.get('subdomains', []))
            subdomains = list(set(subdomains))[:self.config.scan.max_subdomains]
            return detect_waf(domain, subdomains)
        except Exception as e:
            logger.error(f"[WAF DETECTION ERROR] {e}")
            return {'status': 'error', 'results': []}
    
    def _run_directory_enum(self, domain: str):
        """Run directory enumeration with timeout"""
        try:
            ct_data = self.scan_results.get('certificates', {})
            subdomains = []
            if isinstance(ct_data, dict):
                for cert in ct_data.get('certificates', []):
                    subdomains.extend(cert.get('subdomains', []))
            subdomains = list(set(subdomains))[:self.config.scan.max_subdomains]
            return enumerate_directories_optimized(
                domain, subdomains, max_threads=self.config.scan.max_threads
            )
        except Exception as e:
            logger.error(f"[DIRECTORY ENUM ERROR] {e}")
            return {'status': 'error', 'results': []}
    
    def _run_email_validation(self, domain: str):
        """Run email validation with found emails"""
        try:
            forensics = self.scan_results.get('forensics', {})
            emails = []
            if isinstance(forensics, dict):
                for res in forensics.get('results', []):
                    emails.extend(res.get('emails', []))
            emails = list(set(emails))
            return check_found_emails(domain, emails)
        except Exception as e:
            logger.error(f"[EMAIL VALIDATION ERROR] {e}")
            return {'data': {}}
    
    def _run_breach_check(self, domain: str):
        """Run breach check with collected emails"""
        try:
            emails = self._collect_emails()
            return check_breach_leakcheck_public(emails)
        except Exception as e:
            logger.error(f"[BREACH CHECK ERROR] {e}")
            return {'status': 'error', 'results': []}
    
    def _run_port_scan(self, domain: str):
        """Run port scanning on target"""
        try:
            # Common port range for initial scan
            port_range = self.config.scan.port_range if hasattr(self.config.scan, 'port_range') else "1-1000"
            timeout = self.config.scan.port_timeout if hasattr(self.config.scan, 'port_timeout') else 5
            
            return network_scanner_free(domain, port_range=port_range, timeout=timeout)
        except Exception as e:
            logger.error(f"[PORT SCAN ERROR] {e}")
            return {'status': 'error', 'message': str(e)}
    
    def calculate_risk_score(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate composite risk score from all modules"""
        score = 0
        factors = []

        try:
            # 1. WAF Detection
            waf_results = data.get('waf', {}).get('results', [])
            unprotected = sum(1 for r in waf_results if not r.get('has_waf'))
            if unprotected > 0:
                score += 25
                factors.append(f"[WARN] {unprotected} endpoint(s) without WAF protection")

            # 2. Breaches (LeakCheck)
            breaches = data.get('breaches', {}).get('results', [])
            pwned = [b for b in breaches if b.get('is_pwned')]
            if pwned:
                critical_count = sum(1 for b in pwned if b.get('risk_level') == 'CRITICAL')
                score += min(critical_count * 10, 20)
                factors.append(f"[CRITICAL] {len(pwned)} compromised credential(s)")

            # 3. Credential Intelligence
            cred = data.get('credential_intel', {})
            if isinstance(cred, dict):
                analysis = cred.get('analysis', {})
                if analysis.get('password_leaks_found'):
                    score += 20
                    factors.append("[WARN] Password leaks confirmed in breach databases")
                elif analysis.get('total_breaches', 0) > 0:
                    score += 10
                    factors.append(f"[INFO] {analysis['total_breaches']} breach(es) in HIBP")

            # 4. Open Directories
            dirs = data.get('directories', {}).get('scan_summary', {})
            critical_dirs = dirs.get('critical_directories', 0)
            if critical_dirs > 0:
                score += min(critical_dirs * 8, 15)
                factors.append(f"[WARN] {critical_dirs} critical directories exposed")

            # 5. Dark web findings
            crawler = data.get('crawler', {})
            if isinstance(crawler, dict):
                dark = crawler.get('dark_web', {})
                dark_findings = dark.get('total_findings', 0)
                if dark_findings > 0:
                    score += min(dark_findings * 5, 15)
                    factors.append(f"[WARN] {dark_findings} dark web mention(s)")

            # 6. Gov threat intel (legacy)
            gov = data.get('gov_data', {})
            if isinstance(gov, dict):
                threat = gov.get('threat_intel', {})
                t_score = threat.get('threat_score', 0)
                if t_score > 0:
                    score += min(t_score, 10)
                    factors.append(f"[INFO] Govt threat intel score: {t_score}")

            # 7. Domain Age
            whois_data = data.get('whois', {})
            created_date = whois_data.get('dates', {}).get('created', '')
            if created_date and created_date != 'N/A':
                try:
                    created = datetime.datetime.strptime(created_date, '%Y-%m-%d')
                    age_days = (datetime.datetime.now() - created).days
                    if age_days < 365:
                        score += 5
                        factors.append("[INFO] Domain is less than 1 year old")
                except Exception:
                    pass

            # ── NEW RISK METRICS ──────────────────────────────────────────────

            # 8. DNS Security Grade
            dns_sec = data.get('dns_security', {})
            if isinstance(dns_sec, dict):
                grade = dns_sec.get('security_grade', '')
                sec_score = dns_sec.get('security_score', 100)
                critical_issues = dns_sec.get('critical_issues_count', 0)
                if grade in ('F', 'D'):
                    added = min(critical_issues * 8, 20)
                    score += added
                    factors.append(f"[CRITICAL] DNS security grade {grade} – {critical_issues} critical issue(s)")
                elif grade == 'C':
                    score += 8
                    factors.append(f"[WARN] DNS security grade C – hardening recommended")
                elif grade == 'B':
                    factors.append(f"[INFO] DNS security grade B – minor gaps detected")

            # 9. Community Threat Intelligence Blocklists
            threat_intel = data.get('threat_intel', {})
            if isinstance(threat_intel, dict):
                ti_score = threat_intel.get('threat_score', 0)
                blocklist_hits = threat_intel.get('blocklist_hits', 0)
                ti_level = threat_intel.get('threat_level', 'CLEAN')
                if ti_level in ('CRITICAL', 'HIGH'):
                    score += min(ti_score // 2, 20)
                    factors.append(
                        f"[CRITICAL] Threat intel: {blocklist_hits} blocklist hit(s), level={ti_level}"
                    )
                elif ti_level == 'MEDIUM':
                    score += min(ti_score // 3, 10)
                    factors.append(f"[WARN] Threat intel: {blocklist_hits} blocklist hit(s)")
                elif blocklist_hits > 0:
                    factors.append(f"[INFO] Threat intel: {blocklist_hits} minor blocklist mention(s)")

            # 10. Subdomain Takeover Vulnerabilities
            takeover = data.get('subdomain_takeover', {})
            if isinstance(takeover, dict):
                vuln_count = takeover.get('summary', {}).get('vulnerable', 0)
                dangling_count = takeover.get('summary', {}).get('dangling_cnames', 0)
                if vuln_count > 0:
                    score += min(vuln_count * 15, 25)
                    factors.append(
                        f"[CRITICAL] {vuln_count} subdomain(s) confirmed vulnerable to takeover"
                    )
                elif dangling_count > 0:
                    score += min(dangling_count * 8, 15)
                    factors.append(
                        f"[WARN] {dangling_count} dangling CNAME(s) at risk of takeover"
                    )

            # 11. Sensitive Metadata Findings
            metadata = data.get('metadata', {})
            if isinstance(metadata, dict):
                sensitive = len(metadata.get('sensitive_findings', []))
                gps_found = metadata.get('summary', {}).get('gps_coordinates_found', 0)
                if gps_found > 0:
                    score += min(gps_found * 5, 10)
                    factors.append(f"[WARN] GPS coordinates embedded in {gps_found} public file(s)")
                elif sensitive > 0:
                    score += min(sensitive * 3, 8)
                    factors.append(f"[INFO] {sensitive} file(s) contain sensitive metadata")

            # ─────────────────────────────────────────────────────────────────

            if not factors:
                factors.append("[OK] No significant risk factors detected")

            risk_level = (
                'CRITICAL' if score >= 70 else
                'HIGH'     if score >= 50 else
                'MEDIUM'   if score >= 30 else
                'LOW'
            )

            return {
                'score': min(score, 100),
                'level': risk_level,
                'factors': factors[:12]  # Show up to 12 factors now
            }
        except Exception as e:
            logger.error(f"[RISK CALCULATION ERROR] {e}")
            return {'score': 0, 'level': 'LOW', 'factors': ['Unable to calculate']}
    
    def run_full_scan(self, domain: str, api_keys: Dict[str, str] = None, progress_callback=None) -> Dict[str, Any]:
        """Execute complete OSINT scan with all modules
        
        Args:
            domain: Target domain to scan
            api_keys: Optional dict of API keys
            progress_callback: Optional callback(module_name, status, current, total)
        """
        self._cancelled = False
        self._progress_callback = progress_callback
        
        logger.info(f"\n{'='*80}")
        logger.info(f"[START] ENHANCED OSINT SCAN FOR: {domain}")
        logger.info(f"{'='*80}\n")
        
        api_keys = api_keys or {}
        
        results = {
            'target': domain,
            'timestamp': datetime.datetime.now().isoformat(),
            'scan_status': 'running',
            'modules_completed': 0,
            'modules_total': 0
        }
        
        try:
            # Validate target
            valid, original, normalized = self.validate_target(domain)
            if not valid:
                logger.error(f"[VALIDATION] Invalid domain: {original}")
                results['error'] = f"Invalid domain: {normalized}"
                results['scan_status'] = 'failed'
                return results
            
            domain = normalized
            results['target'] = domain
            
            # ---- PHASE 1: Core modules ----
            modules = self._setup_modules(domain, api_keys)
            results['modules_total'] = len(modules)
            
            logger.info(f"[PHASE 1] Running {len(modules)} core modules\n")
            
            module_results, status_report = execute_parallel_modules(
                modules,
                max_workers=self.config.scan.max_threads,
                timeout_per_module=self.config.scan.timeout_per_module,
                retry_count=self.config.api.retry_attempts
            )
            
            self.scan_results = module_results
            results.update(module_results)
            
            # Notify progress and check for cancellation after phase 1
            if self._progress_callback:
                completed = status_report['status_summary'].get('completed', 0)
                self._progress_callback('phase1', 'completed', completed, results['modules_total'])
            self._check_cancelled()
            
            # ---- PHASE 2: Advanced modules (depend on phase 1) ----
            phase2_modules = self._setup_phase2_modules(domain, api_keys)
            if phase2_modules:
                results['modules_total'] += len(phase2_modules)
                logger.info(f"\n[PHASE 2] Running {len(phase2_modules)} advanced modules\n")
                
                p2_results, p2_status = execute_parallel_modules(
                    phase2_modules,
                    max_workers=min(self.config.scan.max_threads, 4),
                    timeout_per_module=self.config.scan.timeout_per_module * 2,
                    retry_count=1
                )
                
                self.scan_results.update(p2_results)
                results.update(p2_results)
                
                # Merge status reports
                status_report['status_summary']['completed'] = (
                    status_report['status_summary'].get('completed', 0) +
                    p2_status['status_summary'].get('completed', 0)
                )
            
            results['modules_completed'] = status_report['status_summary'].get('completed', 0)
            results['execution_report'] = status_report
            
            # Notify progress and check for cancellation after phase 2
            if self._progress_callback:
                self._progress_callback('phase2', 'completed',
                                        results['modules_completed'], results['modules_total'])
            self._check_cancelled()
            
            # ---- PHASE 3: Correlation ----
            if self.config.scan.enable_correlation:
                logger.info("\n[PHASE 3] Running data correlation...\n")
                try:
                    results['correlations'] = correlate_all_data(results)
                except Exception as e:
                    logger.error(f"[CORRELATION ERROR] {e}")
                    results['correlations'] = {}
            
            # Calculate risk score
            logger.info("[ANALYSIS] Calculating risk score...")
            risk_data = self.calculate_risk_score(results)
            results['risk_score'] = risk_data
            
            # Generate PDF report
            logger.info("[REPORT] Generating PDF report...")
            try:
                pdf_path = generate_premium_report(results)
                if pdf_path and os.path.exists(pdf_path):
                    results['report_file'] = pdf_path
                    logger.info(f"[OK] PDF Generated: {pdf_path}")
                else:
                    results['report_file'] = None
            except Exception as e:
                logger.error(f"[PDF ERROR] {e}")
                results['report_file'] = None
            
            # Save JSON dump
            try:
                timestamp_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                dump_dir = self.config.report.report_dir
                os.makedirs(dump_dir, exist_ok=True)
                dump_filename = os.path.join(dump_dir, f"{domain}_{timestamp_str}_dump.json")
                
                with open(dump_filename, 'w') as f:
                    json.dump(results, f, indent=4, default=str)
                
                results['dump_file'] = dump_filename
                logger.info(f"[OK] JSON dump saved: {dump_filename}")

                # Save HTML report
                html_filename = os.path.join(dump_dir, f"{domain}_{timestamp_str}_report.html")
                try:
                    from functions.html_report_generator import generate_html_report
                    html_content = generate_html_report(results)
                    with open(html_filename, 'w', encoding='utf-8') as f:
                        f.write(html_content)
                    logger.info(f"[OK] HTML report saved: {html_filename}")
                except Exception as html_err:
                    logger.error(f"[HTML REPORT ERROR] {html_err}")
            except Exception as e:
                logger.error(f"[DUMP ERROR] {e}")
            
            # Save to database
            self.db.save_scan(results)
            
            # Add to history
            self.scan_history.append({
                'target': domain,
                'timestamp': results['timestamp'],
                'risk_score': risk_data['score'],
                'risk_level': risk_data['level']
            })
            
            results['scan_status'] = 'completed'
            
            logger.info(f"\n{'='*80}")
            logger.info(f"[COMPLETE] Scan finished successfully!")
            logger.info(f"Risk Score: {risk_data['score']}/100 ({risk_data['level']})")
            logger.info(f"{'='*80}\n")
        
        except InterruptedError:
            logger.info("[SCAN] Scan cancelled by user")
            results['scan_status'] = 'cancelled'
        except Exception as e:
            logger.error(f"[SCAN FATAL ERROR] {e}")
            traceback.print_exc()
            results['scan_status'] = 'failed'
            results['error'] = str(e)
        
        self.scan_results[domain] = results
        return results
    
    def get_scan_history(self, limit: int = 50):
        """Get recent scan history"""
        return self.scan_history[-limit:]
    
    def get_cache_stats(self):
        """Get cache statistics"""
        return self.cache.get_stats()
    
    def get_database_stats(self):
        """Get database statistics"""
        return self.db.get_statistics()

# Global orchestrator instance
_orchestrator = None

def get_orchestrator() -> ScanOrchestrator:
    """Get global orchestrator instance"""
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = ScanOrchestrator()
    return _orchestrator

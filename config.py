# config.py - Centralized Configuration Management
import os
import json
from pathlib import Path
from dotenv import load_dotenv
from dataclasses import dataclass, asdict
from typing import Dict, Any

load_dotenv()

@dataclass
class APIConfig:
    """API Configuration"""
    shodan_key: str = os.getenv('SHODAN_API_KEY', '')
    virustotal_key: str = os.getenv('VT_API_KEY', '')
    leakcheck_key: str = os.getenv('LEAKCHECK_API_KEY', '')
    hibp_key: str = os.getenv('HIBP_API_KEY', '')
    dehashed_key: str = os.getenv('DEHASHED_API_KEY', '')
    timeout: int = 30
    retry_attempts: int = 3
    retry_delay: int = 2

@dataclass
class ScanConfig:
    """Scan Configuration"""
    max_threads: int = 12
    timeout_per_module: int = 120
    max_subdomains: int = 25
    directory_wordlist_size: int = 1000
    port_range: str = "1-1000"  # Port range for scanning
    port_timeout: int = 5
    
    # Premium Module Flags
    enable_waf_detection: bool = True
    enable_directory_enum: bool = True
    enable_forensics: bool = True
    enable_breach_check: bool = True
    enable_email_validation: bool = True
    enable_crawler: bool = True
    enable_credential_intel: bool = True
    enable_gov_data: bool = True
    enable_correlation: bool = True
    
    # Free OSINT Module Flags (No API keys required)
    enable_google_dorking: bool = True
    enable_wayback_machine: bool = True
    enable_dns_brute: bool = True
    enable_tech_detection: bool = True
    enable_cert_analysis: bool = True
    enable_http_analysis: bool = True
    enable_port_scan: bool = True
    enable_ip_intel: bool = True
    enable_whois_extended: bool = True
    enable_social_enum: bool = True
    enable_leak_checker: bool = True
    enable_wifi_enum: bool = False  # Disabled by default (requires special privileges)

    # Advanced OSINT Module Flags (Phase 2 additions)
    enable_subdomain_takeover: bool = True   # CNAME dangling / takeover detection
    enable_dns_security: bool = True         # SPF/DMARC/MTA-STS/DNSSEC deep analysis
    enable_threat_intel: bool = True         # Community blocklist & reputation lookup
    enable_metadata_extractor: bool = True   # EXIF + document metadata extraction
    enable_email_osint: bool = True          # Email account presence & reputation
    enable_phone_osint: bool = True          # Phone number intelligence & reputation

@dataclass
class CrawlerConfig:
    """Web Crawler Configuration"""
    max_depth: int = 3
    max_pages: int = 300
    crawl_delay: float = 0.5
    enable_deep_web: bool = True
    enable_dark_web: bool = True
    tor_port: int = 9050
    respect_robots: bool = True

@dataclass
class CredentialConfig:
    """Credential Intelligence Configuration"""
    enable_hibp: bool = True
    enable_paste_search: bool = True
    enable_dehashed: bool = True
    max_emails_to_check: int = 30

@dataclass
class GovDataConfig:
    """Government Data Configuration"""
    enable_ip_intel: bool = True
    enable_domain_history: bool = True
    enable_ssl_transparency: bool = True
    enable_corporate_search: bool = True
    enable_threat_intel: bool = True
    target_countries: str = 'IN,US'

@dataclass
class CacheConfig:
    """Cache Configuration"""
    enabled: bool = True
    ttl_hours: int = 24
    cache_dir: str = 'cache'
    max_cache_size_mb: int = 500

@dataclass
class LoggingConfig:
    """Logging Configuration"""
    level: str = 'INFO'
    log_file: str = 'logs/osint_scan.log'
    enable_file_logging: bool = True
    enable_console_logging: bool = True
    max_log_file_size: int = 10485760  # 10MB
    backup_count: int = 5

@dataclass
class DatabaseConfig:
    """Database Configuration"""
    enabled: bool = True
    db_type: str = 'sqlite'  # sqlite, postgresql, mysql
    db_path: str = 'osint_data.db'
    db_host: str = os.getenv('DB_HOST', 'localhost')
    db_port: int = int(os.getenv('DB_PORT', '5432'))
    db_name: str = os.getenv('DB_NAME', 'osint_db')
    db_user: str = os.getenv('DB_USER', '')
    db_password: str = os.getenv('DB_PASSWORD', '')

@dataclass
class ReportConfig:
    """Report Configuration"""
    report_dir: str = 'reports'
    enable_pdf: bool = True
    enable_html: bool = True
    enable_json: bool = True
    enable_xlsx: bool = True
    include_risk_analysis: bool = True
    include_timeline: bool = True

@dataclass
class Config:
    """Main Configuration Class"""
    api: APIConfig
    scan: ScanConfig
    cache: CacheConfig
    logging: LoggingConfig
    database: DatabaseConfig
    report: ReportConfig
    crawler: CrawlerConfig
    credential: CredentialConfig
    gov_data: GovDataConfig
    env: str = os.getenv('ENV', 'development')
    debug: bool = os.getenv('DEBUG', 'False').lower() == 'true'

    @staticmethod
    def load_from_file(config_file: str = 'config.json') -> 'Config':
        """Load configuration from JSON file"""
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    config_dict = json.load(f)
                    return Config(**config_dict)
            except Exception:
                pass
        return Config(
            api=APIConfig(),
            scan=ScanConfig(),
            cache=CacheConfig(),
            logging=LoggingConfig(),
            database=DatabaseConfig(),
            report=ReportConfig(),
            crawler=CrawlerConfig(),
            credential=CredentialConfig(),
            gov_data=GovDataConfig(),
        )

    def save_to_file(self, config_file: str = 'config.json'):
        """Save configuration to JSON file"""
        config_dict = {
            'api': asdict(self.api),
            'scan': asdict(self.scan),
            'cache': asdict(self.cache),
            'logging': asdict(self.logging),
            'database': asdict(self.database),
            'report': asdict(self.report),
            'crawler': asdict(self.crawler),
            'credential': asdict(self.credential),
            'gov_data': asdict(self.gov_data),
            'env': self.env,
            'debug': self.debug
        }
        with open(config_file, 'w') as f:
            json.dump(config_dict, f, indent=4)

    def validate(self) -> tuple[bool, list]:
        """Validate configuration"""
        errors = []

        if self.scan.max_threads < 1 or self.scan.max_threads > 50:
            errors.append("max_threads must be between 1 and 50")

        if self.cache.ttl_hours < 1:
            errors.append("cache TTL must be at least 1 hour")

        # Create necessary directories
        Path(self.cache.cache_dir).mkdir(exist_ok=True)
        Path(self.report.report_dir).mkdir(exist_ok=True)
        Path(os.path.dirname(self.logging.log_file)).mkdir(exist_ok=True)

        return len(errors) == 0, errors

    def to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary"""
        return asdict(self)

# Global config instance
_config = None

def get_config() -> Config:
    """Get global config instance"""
    global _config
    if _config is None:
        _config = Config.load_from_file()
        valid, errors = _config.validate()
        if not valid:
            print(f"[!] Configuration validation errors:\n" + "\n".join(errors))
    return _config

def set_config(config: Config):
    """Set global config instance"""
    global _config
    _config = config

if __name__ == '__main__':
    # Generate default config.json
    config = Config(
        api=APIConfig(),
        scan=ScanConfig(),
        cache=CacheConfig(),
        logging=LoggingConfig(),
        database=DatabaseConfig(),
        report=ReportConfig(),
        crawler=CrawlerConfig(),
        credential=CredentialConfig(),
        gov_data=GovDataConfig(),
    )
    config.save_to_file()
    print("[+] Default config.json generated")

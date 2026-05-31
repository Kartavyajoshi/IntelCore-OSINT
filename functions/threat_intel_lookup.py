# functions/threat_intel_lookup.py
# Community blocklist and threat intelligence checks (free sources only)
# Educational Purpose Only - IntelCore-OSINT Framework

import socket
import ipaddress
import requests
import dns.resolver
import time
from typing import Dict, Any, List, Optional
from logger import get_logger

logger = get_logger()

TIMEOUT = 10

# ─────────────────────────────────────────────
# DNS-Based Blocklist (DNSBL) checks
# ─────────────────────────────────────────────

DNSBLS = [
    {'name': 'Spamhaus ZEN',       'host': 'zen.spamhaus.org'},
    {'name': 'Spamhaus DBL',       'host': 'dbl.spamhaus.org'},
    {'name': 'Barracuda BRBL',     'host': 'b.barracudacentral.org'},
    {'name': 'SORBS SPAM',         'host': 'spam.sorbs.net'},
    {'name': 'SORBS RECENT',       'host': 'recent.spam.sorbs.net'},
    {'name': 'SpamCop',            'host': 'bl.spamcop.net'},
    {'name': 'Composite BL',       'host': 'cbl.abuseat.org'},
    {'name': 'URIBL Black',        'host': 'black.uribl.com'},
    {'name': 'SURBL Multi',        'host': 'multi.surbl.org'},
    {'name': 'RATS-Spam',          'host': 'spam.rats.ruralnerd.com'},
    {'name': 'NordSpam',           'host': 'bl.nordspam.com'},
    {'name': 'Mailspike Spam',     'host': 'bl.mailspike.net'},
]

def _reverse_ip(ip: str) -> Optional[str]:
    """Reverse an IPv4 address for DNSBL lookup."""
    try:
        obj = ipaddress.IPv4Address(ip)
        parts = str(obj).split('.')
        return '.'.join(reversed(parts))
    except ValueError:
        return None


def _check_dnsbl(ip: str) -> List[Dict[str, Any]]:
    """Check an IP against multiple DNS-based blocklists."""
    results = []
    reversed_ip = _reverse_ip(ip)
    if not reversed_ip:
        return results

    for bl in DNSBLS:
        query = f"{reversed_ip}.{bl['host']}"
        entry = {
            'blocklist': bl['name'],
            'host': bl['host'],
            'listed': False,
            'response': None
        }
        try:
            answers = dns.resolver.resolve(query, 'A', lifetime=5)
            if answers:
                entry['listed'] = True
                entry['response'] = str(answers[0])
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            entry['listed'] = False
        except Exception as e:
            entry['error'] = str(e)
        results.append(entry)

    return results


def _check_domain_dnsbl(domain: str) -> List[Dict[str, Any]]:
    """Check a domain against URI-based blocklists."""
    results = []
    uri_bls = [
        {'name': 'URIBL Black', 'host': 'black.uribl.com'},
        {'name': 'SURBL Multi', 'host': 'multi.surbl.org'},
        {'name': 'Spamhaus DBL', 'host': 'dbl.spamhaus.org'},
    ]
    for bl in uri_bls:
        query = f"{domain}.{bl['host']}"
        entry = {
            'blocklist': bl['name'],
            'host': bl['host'],
            'listed': False,
            'response': None
        }
        try:
            answers = dns.resolver.resolve(query, 'A', lifetime=5)
            if answers:
                entry['listed'] = True
                entry['response'] = str(answers[0])
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            entry['listed'] = False
        except Exception as e:
            entry['error'] = str(e)
        results.append(entry)
    return results


# ─────────────────────────────────────────────
# AbuseIPDB (unauthenticated community reports endpoint)
# ─────────────────────────────────────────────

def _check_abuseipdb(ip: str) -> Dict[str, Any]:
    """Check IP reputation via AbuseIPDB public endpoint."""
    result = {'checked': False, 'abuse_score': None, 'total_reports': None, 'last_reported': None}
    try:
        # Public endpoint (no key required for basic check)
        url = f"https://api.abuseipdb.com/api/v2/check"
        headers = {'Accept': 'application/json', 'Key': 'public'}
        params = {'ipAddress': ip, 'maxAgeInDays': 90}
        resp = requests.get(url, headers=headers, params=params, timeout=TIMEOUT)
        if resp.status_code == 200:
            data = resp.json().get('data', {})
            result['checked'] = True
            result['abuse_score'] = data.get('abuseConfidenceScore', 0)
            result['total_reports'] = data.get('totalReports', 0)
            result['last_reported'] = data.get('lastReportedAt')
            result['country_code'] = data.get('countryCode')
            result['usage_type'] = data.get('usageType')
    except Exception as e:
        result['error'] = str(e)
    return result


# ─────────────────────────────────────────────
# AlienVault OTX - free pulse lookup
# ─────────────────────────────────────────────

def _check_otx(domain: str) -> Dict[str, Any]:
    """Check domain against AlienVault OTX (no API key required for basic lookup)."""
    result = {'checked': False, 'pulse_count': 0, 'threat_score': 0, 'malware_families': []}
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
        headers = {'User-Agent': 'IntelCore-OSINT/1.0'}
        resp = requests.get(url, headers=headers, timeout=TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            result['checked'] = True
            result['pulse_count'] = data.get('pulse_info', {}).get('count', 0)
            result['threat_score'] = data.get('reputation', 0)
            pulses = data.get('pulse_info', {}).get('pulses', [])
            families = set()
            for p in pulses:
                for tag in p.get('tags', []):
                    families.add(tag.lower())
            result['malware_families'] = list(families)[:10]
            result['related_attacks'] = [
                p.get('name', '') for p in pulses[:5]
            ]
    except Exception as e:
        result['error'] = str(e)
    return result


def _check_otx_ip(ip: str) -> Dict[str, Any]:
    """Check IP against AlienVault OTX."""
    result = {'checked': False, 'pulse_count': 0, 'threat_score': 0}
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
        headers = {'User-Agent': 'IntelCore-OSINT/1.0'}
        resp = requests.get(url, headers=headers, timeout=TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            result['checked'] = True
            result['pulse_count'] = data.get('pulse_info', {}).get('count', 0)
            result['threat_score'] = data.get('reputation', 0)
    except Exception as e:
        result['error'] = str(e)
    return result


# ─────────────────────────────────────────────
# URLhaus (abuse.ch) - Malware URL database
# ─────────────────────────────────────────────

def _check_urlhaus(domain: str) -> Dict[str, Any]:
    """Check domain against URLhaus malware database."""
    result = {'checked': False, 'in_urlhaus': False, 'url_count': 0, 'threat_types': []}
    try:
        url = "https://urlhaus-api.abuse.ch/v1/host/"
        resp = requests.post(url, data={'host': domain}, timeout=TIMEOUT,
                             headers={'User-Agent': 'IntelCore-OSINT/1.0'})
        if resp.status_code == 200:
            data = resp.json()
            result['checked'] = True
            if data.get('query_status') == 'is_host':
                result['in_urlhaus'] = True
                urls = data.get('urls', [])
                result['url_count'] = len(urls)
                threat_types = list(set(u.get('threat', '') for u in urls if u.get('threat')))
                result['threat_types'] = threat_types
                result['sample_urls'] = [u.get('url', '') for u in urls[:3]]
    except Exception as e:
        result['error'] = str(e)
    return result


# ─────────────────────────────────────────────
# ThreatFox (abuse.ch) - IOC database
# ─────────────────────────────────────────────

def _check_threatfox(ioc: str, ioc_type: str = 'domain') -> Dict[str, Any]:
    """Check an IOC against ThreatFox malware IOC database."""
    result = {'checked': False, 'found': False, 'threat_type': None, 'malware': None}
    try:
        url = "https://threatfox-api.abuse.ch/api/v1/"
        payload = {"query": "search_ioc", "search_term": ioc}
        resp = requests.post(url, json=payload, timeout=TIMEOUT,
                             headers={'User-Agent': 'IntelCore-OSINT/1.0'})
        if resp.status_code == 200:
            data = resp.json()
            result['checked'] = True
            if data.get('query_status') == 'ok' and data.get('data'):
                result['found'] = True
                ioc_data = data['data'][0] if data['data'] else {}
                result['threat_type'] = ioc_data.get('threat_type')
                result['malware'] = ioc_data.get('malware')
                result['confidence'] = ioc_data.get('confidence_level')
                result['first_seen'] = ioc_data.get('first_seen')
    except Exception as e:
        result['error'] = str(e)
    return result


# ─────────────────────────────────────────────
# Main entry point
# ─────────────────────────────────────────────

def threat_intel_lookup(domain: str, ip: str = None) -> Dict[str, Any]:
    """
    Community threat intelligence lookup using free, no-key-required sources.
    
    Sources:
    - DNSBL (Spamhaus ZEN/DBL, SpamCop, Barracuda, SORBS, URIBL, SURBL, etc.)
    - AlienVault OTX (Open Threat Exchange) - domain & IP pulses
    - URLhaus (abuse.ch) - malware URL database
    - ThreatFox (abuse.ch) - malware IOC database
    - AbuseIPDB (community-reported abuse scores)
    
    Args:
        domain: Target domain to check
        ip: Optional target IP address; if not provided, will be resolved
        
    Returns:
        Comprehensive threat intelligence report with blocklist results
    """
    logger.info(f"[THREAT INTEL] Starting threat intelligence lookup for: {domain}")
    start_time = time.time()

    # Resolve IP if not provided
    if not ip:
        try:
            ip = socket.gethostbyname(domain)
        except socket.gaierror:
            ip = None

    results = {
        'domain': domain,
        'ip': ip,
        'module': 'threat_intel_lookup',
        'status': 'completed',
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'threat_level': 'CLEAN',
        'threat_score': 0,
        'blocklist_hits': 0,
        'dnsbl_results': [],
        'domain_dnsbl_results': [],
        'otx_domain': {},
        'otx_ip': {},
        'urlhaus': {},
        'threatfox_domain': {},
        'threatfox_ip': {},
        'abuseipdb': {},
        'summary': {
            'listed_in_dnsbls': 0,
            'otx_pulses': 0,
            'urlhaus_found': False,
            'threatfox_found': False,
        }
    }

    # 1. DNSBL checks for IP
    if ip:
        results['dnsbl_results'] = _check_dnsbl(ip)
        listed_count = sum(1 for r in results['dnsbl_results'] if r.get('listed'))
        results['summary']['listed_in_dnsbls'] = listed_count
        results['blocklist_hits'] += listed_count
        results['threat_score'] += min(listed_count * 10, 40)

    # 2. Domain DNSBL checks
    results['domain_dnsbl_results'] = _check_domain_dnsbl(domain)
    domain_listed = sum(1 for r in results['domain_dnsbl_results'] if r.get('listed'))
    results['blocklist_hits'] += domain_listed
    results['threat_score'] += min(domain_listed * 10, 20)

    # 3. OTX domain check
    results['otx_domain'] = _check_otx(domain)
    otx_pulses = results['otx_domain'].get('pulse_count', 0)
    results['summary']['otx_pulses'] = otx_pulses
    results['threat_score'] += min(otx_pulses * 5, 20)

    # 4. OTX IP check
    if ip:
        results['otx_ip'] = _check_otx_ip(ip)
        ip_pulses = results['otx_ip'].get('pulse_count', 0)
        results['threat_score'] += min(ip_pulses * 3, 10)

    # 5. URLhaus
    results['urlhaus'] = _check_urlhaus(domain)
    if results['urlhaus'].get('in_urlhaus'):
        results['summary']['urlhaus_found'] = True
        results['threat_score'] += 25

    # 6. ThreatFox domain
    results['threatfox_domain'] = _check_threatfox(domain, 'domain')
    if results['threatfox_domain'].get('found'):
        results['summary']['threatfox_found'] = True
        results['threat_score'] += 20

    # 7. ThreatFox IP
    if ip:
        results['threatfox_ip'] = _check_threatfox(ip, 'ip')
        if results['threatfox_ip'].get('found'):
            results['threat_score'] += 15

    # 8. AbuseIPDB
    if ip:
        results['abuseipdb'] = _check_abuseipdb(ip)
        abuse_score = results['abuseipdb'].get('abuse_score', 0) or 0
        results['threat_score'] += int(abuse_score * 0.15)

    # Final threat level
    total_score = min(results['threat_score'], 100)
    results['threat_score'] = total_score
    results['threat_level'] = (
        'CRITICAL' if total_score >= 70 else
        'HIGH'     if total_score >= 45 else
        'MEDIUM'   if total_score >= 20 else
        'LOW'      if total_score > 0 else
        'CLEAN'
    )

    elapsed = round(time.time() - start_time, 2)
    results['elapsed_seconds'] = elapsed
    logger.info(
        f"[THREAT INTEL] Done in {elapsed}s. "
        f"Score: {total_score}/100 ({results['threat_level']}), "
        f"Blocklist hits: {results['blocklist_hits']}"
    )
    return results

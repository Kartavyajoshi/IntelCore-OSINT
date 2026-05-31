# gov_data_aggregator.py - Government & Public Data Aggregation Module
# Gathers publicly available records from government and institutional databases

import requests
import socket
import traceback
from typing import Dict, Any, List, Optional

def run_gov_data_scan(domain: str, ip_list: List[str] = None, company_name: Optional[str] = None) -> Dict[str, Any]:
    """
    Aggregate government and public data records for a target.
    
    Args:
        domain: Target domain
        ip_list: List of IPs associated with the domain
        company_name: Optional company name for corporate record searches
    
    Returns:
        Dictionary with aggregated public records
    """
    ip_list = ip_list or []
    
    results = {
        'domain': domain,
        'status': 'completed',
        'ip_intelligence': {},
        'domain_history': {},
        'ssl_transparency': {},
        'corporate_records': {},
        'threat_intel': {
            'threat_score': 0,
            'indicators': [],
            'blocklists': []
        },
        'summary': ''
    }
    
    try:
        # 1. IP Intelligence via public APIs
        if ip_list:
            results['ip_intelligence'] = _gather_ip_intelligence(ip_list)
        else:
            # Resolve domain to IP
            try:
                ip = socket.gethostbyname(domain)
                ip_list = [ip]
                results['ip_intelligence'] = _gather_ip_intelligence(ip_list)
            except socket.gaierror:
                results['ip_intelligence'] = {'error': 'Could not resolve domain'}
        
        # 2. Domain history via public sources
        results['domain_history'] = _check_domain_history(domain)
        
        # 3. SSL Transparency
        results['ssl_transparency'] = _check_ssl_transparency(domain)
        
        # 4. Threat intelligence from public blocklists
        if ip_list:
            results['threat_intel'] = _check_threat_intelligence(domain, ip_list)
        
        # 5. Corporate/organizational records (if company name available)
        if company_name:
            results['corporate_records'] = _search_corporate_records(company_name)
        
        # Generate summary
        threat_score = results['threat_intel'].get('threat_score', 0)
        ip_count = len(ip_list)
        results['summary'] = (
            f"Scanned {ip_count} IP(s) for {domain}. "
            f"Threat Score: {threat_score}. "
            f"Found {len(results['threat_intel'].get('indicators', []))} threat indicator(s)."
        )
        
    except Exception as e:
        results['status'] = 'error'
        results['error'] = str(e)
        traceback.print_exc()
    
    return results


def _gather_ip_intelligence(ip_list: List[str]) -> Dict[str, Any]:
    """Gather intelligence for IP addresses using free APIs"""
    intel = {
        'ips_checked': len(ip_list),
        'results': []
    }
    
    for ip in ip_list[:10]:  # Limit to 10 IPs
        ip_data = {'ip': ip}
        
        try:
            # ip-api.com (free, no key required)
            resp = requests.get(f"http://ip-api.com/json/{ip}?fields=66846719", timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                ip_data.update({
                    'country': data.get('country', ''),
                    'country_code': data.get('countryCode', ''),
                    'region': data.get('regionName', ''),
                    'city': data.get('city', ''),
                    'isp': data.get('isp', ''),
                    'org': data.get('org', ''),
                    'as_number': data.get('as', ''),
                    'is_proxy': data.get('proxy', False),
                    'is_hosting': data.get('hosting', False),
                    'is_mobile': data.get('mobile', False),
                })
        except Exception:
            ip_data['error'] = 'Failed to query IP intelligence'
        
        intel['results'].append(ip_data)
    
    return intel


def _check_domain_history(domain: str) -> Dict[str, Any]:
    """Check domain history from public sources"""
    history = {
        'status': 'checked',
        'historical_ips': [],
        'dns_changes': []
    }
    
    try:
        # SecurityTrails-style check via HackerTarget
        resp = requests.get(
            f"https://api.hackertarget.com/hostsearch/?q={domain}",
            timeout=15
        )
        if resp.status_code == 200 and 'error' not in resp.text.lower():
            lines = resp.text.strip().split('\n')
            for line in lines[:50]:
                parts = line.split(',')
                if len(parts) >= 2:
                    history['historical_ips'].append({
                        'hostname': parts[0].strip(),
                        'ip': parts[1].strip()
                    })
    except Exception:
        history['status'] = 'error'
    
    return history


def _check_ssl_transparency(domain: str) -> Dict[str, Any]:
    """Check SSL certificate transparency logs"""
    ssl_data = {
        'certificates_found': 0,
        'issuers': [],
        'recent_certs': []
    }
    
    try:
        resp = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=20
        )
        if resp.status_code == 200:
            certs = resp.json()
            ssl_data['certificates_found'] = len(certs)
            
            issuers = set()
            for cert in certs[:20]:
                issuer = cert.get('issuer_name', '')
                issuers.add(issuer)
                ssl_data['recent_certs'].append({
                    'common_name': cert.get('common_name', ''),
                    'issuer': issuer,
                    'not_before': cert.get('not_before', ''),
                    'not_after': cert.get('not_after', ''),
                })
            
            ssl_data['issuers'] = list(issuers)
    except Exception:
        ssl_data['status'] = 'error'
    
    return ssl_data


def _check_threat_intelligence(domain: str, ip_list: List[str]) -> Dict[str, Any]:
    """Check against public threat intelligence sources"""
    threat = {
        'threat_score': 0,
        'indicators': [],
        'blocklists': [],
        'domain_reputation': 'unknown'
    }
    
    try:
        # Check AbuseIPDB (limited free API)
        for ip in ip_list[:5]:
            try:
                # DNS-based blocklist check
                blocklist_result = _check_dns_blocklists(ip)
                if blocklist_result:
                    threat['blocklists'].extend(blocklist_result)
                    threat['threat_score'] += len(blocklist_result) * 5
            except Exception:
                pass
        
        # Determine reputation
        score = threat['threat_score']
        if score >= 20:
            threat['domain_reputation'] = 'malicious'
        elif score >= 10:
            threat['domain_reputation'] = 'suspicious'
        elif score > 0:
            threat['domain_reputation'] = 'low_risk'
        else:
            threat['domain_reputation'] = 'clean'
        
        threat['threat_score'] = min(score, 100)
        
    except Exception:
        pass
    
    return threat


def _check_dns_blocklists(ip: str) -> list:
    """Check IP against DNS-based blocklists"""
    blocklists = [
        'zen.spamhaus.org',
        'bl.spamcop.net',
        'b.barracudacentral.org',
    ]
    
    results = []
    reversed_ip = '.'.join(reversed(ip.split('.')))
    
    for bl in blocklists:
        try:
            query = f"{reversed_ip}.{bl}"
            socket.gethostbyname(query)
            results.append({
                'blocklist': bl,
                'ip': ip,
                'listed': True
            })
        except socket.gaierror:
            pass  # Not listed
        except Exception:
            pass
    
    return results


def _search_corporate_records(company_name: str) -> Dict[str, Any]:
    """Search for corporate/organizational records"""
    return {
        'company_name': company_name,
        'status': 'limited',
        'note': 'Corporate record search requires manual verification'
    }

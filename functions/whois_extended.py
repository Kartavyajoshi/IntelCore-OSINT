"""
Extended WHOIS Analysis Module
Deep WHOIS analysis with historical data, registrar intelligence
Uses free WHOIS services and APIs
"""

import requests
import socket
import time
from typing import Dict, List, Any
from datetime import datetime

def whois_extended(target: str) -> Dict[str, Any]:
    """
    Extended WHOIS analysis with historical records
    
    Args:
        target: Domain to analyze
    
    Returns:
        Dict with comprehensive WHOIS data and registrar intelligence
    """
    print(f"[*] Starting extended WHOIS analysis for: {target}")
    
    try:
        # Normalize target
        target = target.strip().lower()
        if target.startswith('http'):
            target = target.split('//')[1].split('/')[0]
        
        results = {
            'status': 'success',
            'target': target,
            'registrar_info': {},
            'registrant_info': {},
            'nameservers': [],
            'dns_records': {},
            'historical_data': {},
            'reputation': {},
            'intelligence': {},
            'timestamp': time.time()
        }
        
        # 1. Get basic WHOIS via free service
        whois_data = _get_whois_data(target)
        results['registrar_info'] = whois_data.get('registrar', {})
        results['registrant_info'] = whois_data.get('registrant', {})
        results['nameservers'] = whois_data.get('nameservers', [])
        
        # 2. Get registration history
        results['historical_data'] = _get_registration_history(target)
        
        # 3. Check registrar reputation
        if results['registrar_info'].get('name'):
            results['reputation'] = _check_registrar_reputation(
                results['registrar_info']['name']
            )
        
        # 4. Get DNS records
        results['dns_records'] = _get_dns_records(target)
        
        # 5. Generate intelligence
        results['intelligence'] = _analyze_whois_intel(results)
        
        print(f"[+] Extended WHOIS analysis complete")
        return results
        
    except Exception as e:
        return {
            'status': 'error',
            'message': f'Extended WHOIS analysis failed: {str(e)}',
            'error': str(e)
        }

def _get_whois_data(domain: str) -> Dict[str, Any]:
    """Fetch WHOIS data via free API"""
    whois_data = {
        'registrar': {},
        'registrant': {},
        'nameservers': []
    }
    
    try:
        # Use whois.arin.net REST API
        url = f"https://whois.arin.net/rest/domain/{domain}"
        response = requests.get(url, headers={'Accept': 'application/json'}, timeout=15)
        
        if response.status_code == 200:
            data = response.json()
            whois_data = _parse_arin_whois(data)
            return whois_data
    except:
        pass
    
    # Fallback to whois API
    try:
        url = f"https://whois.api.biz/api/whois"
        params = {'domain': domain}
        response = requests.get(url, params=params, timeout=15)
        
        if response.status_code == 200:
            data = response.json()
            return _parse_whois_json(data)
    except:
        pass
    
    # Fallback to domain.glass API
    try:
        url = f"https://domain.glass/api/domain/{domain}"
        response = requests.get(url, timeout=15)
        
        if response.status_code == 200:
            data = response.json()
            whois_data = _parse_domain_glass(data)
            return whois_data
    except:
        pass
    
    return whois_data

def _parse_arin_whois(data: Dict) -> Dict[str, Any]:
    """Parse ARIN WHOIS response"""
    parsed = {
        'registrar': {},
        'registrant': {},
        'nameservers': []
    }
    
    try:
        # Extract registrar
        if 'registrarHandle' in data:
            parsed['registrar']['handle'] = data['registrarHandle']
        
        if 'registrarName' in data:
            parsed['registrar']['name'] = data['registrarName']
        
        # Extract registrant
        if 'registrantHandle' in data:
            parsed['registrant']['handle'] = data['registrantHandle']
        
        # Extract nameservers
        if 'nameServers' in data:
            parsed['nameservers'] = data['nameServers']
    
    except Exception as e:
        print(f"[!] Error parsing ARIN WHOIS: {e}")
    
    return parsed

def _parse_whois_json(data: Dict) -> Dict[str, Any]:
    """Parse generic JSON WHOIS response"""
    parsed = {
        'registrar': {
            'name': data.get('registrar_name'),
            'url': data.get('registrar_url'),
            'email': data.get('registrar_email')
        },
        'registrant': {
            'name': data.get('registrant_name'),
            'email': data.get('registrant_email'),
            'organization': data.get('registrant_organization')
        },
        'nameservers': data.get('name_servers', [])
    }
    
    return parsed

def _parse_domain_glass(data: Dict) -> Dict[str, Any]:
    """Parse domain.glass API response"""
    parsed = {
        'registrar': {},
        'registrant': {},
        'nameservers': []
    }
    
    try:
        if 'domain' in data:
            domain_info = data['domain']
            
            parsed['registrar']['name'] = domain_info.get('registrar')
            parsed['registrant']['name'] = domain_info.get('registrant')
            parsed['nameservers'] = domain_info.get('nameservers', [])
    
    except:
        pass
    
    return parsed

def _get_registration_history(domain: str) -> Dict[str, Any]:
    """Get domain registration history"""
    history = {
        'first_seen': None,
        'last_updated': None,
        'registration_age_years': None,
        'historical_ips': [],
        'status_changes': []
    }
    
    try:
        # Use DNS history API if available
        url = f"https://dns.bufferover.run/api/v1/dns/forward/{domain}"
        response = requests.get(url, timeout=15)
        
        if response.status_code == 200:
            data = response.json()
            
            if 'FDNS_A' in data:
                history['historical_ips'] = [
                    record.split(',')[1] for record in data['FDNS_A'][:10]
                ]
    except:
        pass
    
    # Try VirusTotal for historical info (would need API key)
    # For now, estimate based on whois data
    history['estimated_age'] = 'unknown'
    
    return history

def _check_registrar_reputation(registrar_name: str) -> Dict[str, Any]:
    """Check reputation of domain registrar"""
    reputation = {
        'registrar': registrar_name,
        'trust_level': 'unknown',
        'complaint_history': [],
        'notable_features': []
    }
    
    # Known reputable registrars
    reputable = ['GoDaddy', 'Namecheap', 'Network Solutions', 'Google Domains', 'NameSecure']
    
    if any(r.lower() in registrar_name.lower() for r in reputable):
        reputation['trust_level'] = 'high'
    
    # Check for known issues
    if 'privacy' in registrar_name.lower():
        reputation['notable_features'].append('Privacy-focused registrar')
    
    if 'offshore' in registrar_name.lower():
        reputation['trust_level'] = 'low'
        reputation['notable_features'].append('Offshore registrar - potentially higher risk')
    
    return reputation

def _get_dns_records(domain: str) -> Dict[str, Any]:
    """Get DNS records for domain"""
    dns_records = {
        'A': [],
        'AAAA': [],
        'MX': [],
        'TXT': [],
        'NS': [],
        'CNAME': []
    }
    
    try:
        import dns.resolver
        
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8', '8.8.4.4']
        
        for record_type in dns_records.keys():
            try:
                answers = resolver.resolve(domain, record_type)
                dns_records[record_type] = [str(ans) for ans in answers]
            except:
                pass
    
    except ImportError:
        # Fallback if dnspython not available
        try:
            import socket
            dns_records['A'] = [socket.gethostbyname(domain)]
        except:
            pass
    
    return dns_records

def _analyze_whois_intel(results: Dict[str, Any]) -> Dict[str, Any]:
    """Generate intelligence from WHOIS data"""
    intel = {
        'domain_age': 'unknown',
        'registrar_verified': False,
        'privacy_enabled': False,
        'red_flags': [],
        'trust_score': 50
    }
    
    try:
        registrar = results.get('registrar_info', {})
        reputation = results.get('reputation', {})
        
        # Verify registrar
        if registrar.get('name'):
            intel['registrar_verified'] = True
        
        # Check for privacy
        if 'privacy' in str(registrar).lower() or 'private' in str(registrar).lower():
            intel['privacy_enabled'] = True
        
        # Check reputation
        if reputation.get('trust_level') == 'high':
            intel['trust_score'] += 20
        elif reputation.get('trust_level') == 'low':
            intel['trust_score'] -= 20
            intel['red_flags'].append('Low-reputation registrar')
        
        # Check for unusual registrants
        registrant = results.get('registrant_info', {})
        if not registrant.get('name') or registrant.get('name') == 'Private':
            intel['red_flags'].append('Registrant information hidden')
        
        # Validate trust score
        intel['trust_score'] = max(0, min(100, intel['trust_score']))
    
    except:
        pass
    
    return intel

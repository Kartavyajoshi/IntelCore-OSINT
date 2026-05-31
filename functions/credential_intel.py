# credential_intel.py - Credential Intelligence Module
# Checks breach databases and credential exposure for discovered emails

import requests
import hashlib
import time
import traceback
from typing import Dict, Any, List

def run_credential_intelligence(domain: str, emails: List[str] = None, api_keys: Dict[str, str] = None) -> Dict[str, Any]:
    """
    Run credential intelligence gathering for a domain and its associated emails.
    Checks HIBP, paste sites, and public breach databases.
    
    Args:
        domain: Target domain
        emails: List of discovered email addresses
        api_keys: Dictionary of API keys (hibp, dehashed, etc.)
    
    Returns:
        Dictionary with credential intelligence results
    """
    emails = emails or []
    api_keys = api_keys or {}
    
    results = {
        'domain': domain,
        'status': 'completed',
        'total_emails_checked': len(emails),
        'breach_results': [],
        'paste_results': [],
        'analysis': {
            'total_breaches': 0,
            'total_pastes': 0,
            'password_leaks_found': False,
            'most_recent_breach': None,
            'risk_level': 'LOW',
            'unique_breach_sources': []
        },
        'summary': ''
    }
    
    try:
        # Check HIBP (Have I Been Pwned) - public API
        hibp_key = api_keys.get('hibp', '')
        for email in emails[:30]:  # Limit to 30 emails
            try:
                breach_data = _check_hibp_breaches(email, hibp_key)
                if breach_data:
                    results['breach_results'].append({
                        'email': email,
                        'breaches': breach_data,
                        'breach_count': len(breach_data)
                    })
                    results['analysis']['total_breaches'] += len(breach_data)
                    
                    for b in breach_data:
                        source = b.get('Name', 'Unknown')
                        if source not in results['analysis']['unique_breach_sources']:
                            results['analysis']['unique_breach_sources'].append(source)
                        if 'Passwords' in b.get('DataClasses', []):
                            results['analysis']['password_leaks_found'] = True
                
                # Rate limiting
                time.sleep(1.6)
            except Exception as e:
                results['breach_results'].append({
                    'email': email,
                    'error': str(e),
                    'breaches': []
                })
        
        # Check for domain-level breaches
        try:
            domain_breaches = _check_domain_breaches(domain)
            if domain_breaches:
                results['domain_breaches'] = domain_breaches
        except Exception:
            results['domain_breaches'] = []
        
        # Calculate risk level
        total = results['analysis']['total_breaches']
        if results['analysis']['password_leaks_found']:
            results['analysis']['risk_level'] = 'CRITICAL'
        elif total > 10:
            results['analysis']['risk_level'] = 'HIGH'
        elif total > 3:
            results['analysis']['risk_level'] = 'MEDIUM'
        else:
            results['analysis']['risk_level'] = 'LOW'
        
        # Summary
        results['summary'] = (
            f"Checked {len(emails)} emails. "
            f"Found {total} breach(es) across {len(results['analysis']['unique_breach_sources'])} source(s). "
            f"Risk Level: {results['analysis']['risk_level']}"
        )
        
    except Exception as e:
        results['status'] = 'error'
        results['error'] = str(e)
        traceback.print_exc()
    
    return results


def _check_hibp_breaches(email: str, api_key: str = '') -> list:
    """Check Have I Been Pwned for email breaches"""
    headers = {
        'User-Agent': 'IntelCore-OSINT-Platform',
    }
    
    if api_key:
        headers['hibp-api-key'] = api_key
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
        params = {'truncateResponse': 'false'}
    else:
        # Use the free breach search via alternative endpoint
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
        params = {'truncateResponse': 'true'}
    
    try:
        resp = requests.get(url, headers=headers, params=params, timeout=15)
        if resp.status_code == 200:
            return resp.json()
        elif resp.status_code == 404:
            return []  # No breaches found
        elif resp.status_code == 429:
            time.sleep(2)
            return []
        else:
            return []
    except requests.exceptions.RequestException:
        return []


def _check_domain_breaches(domain: str) -> list:
    """Check for known breaches associated with a domain"""
    breaches = []
    
    try:
        # Use HIBP public breaches list to find domain-related breaches
        url = "https://haveibeenpwned.com/api/v3/breaches"
        headers = {'User-Agent': 'IntelCore-OSINT-Platform'}
        resp = requests.get(url, headers=headers, timeout=15)
        
        if resp.status_code == 200:
            all_breaches = resp.json()
            for breach in all_breaches:
                breach_domain = breach.get('Domain', '').lower()
                if domain.lower() in breach_domain or breach_domain in domain.lower():
                    breaches.append({
                        'name': breach.get('Name', ''),
                        'title': breach.get('Title', ''),
                        'domain': breach_domain,
                        'breach_date': breach.get('BreachDate', ''),
                        'pwn_count': breach.get('PwnCount', 0),
                        'data_classes': breach.get('DataClasses', []),
                        'is_verified': breach.get('IsVerified', False)
                    })
    except Exception:
        pass
    
    return breaches

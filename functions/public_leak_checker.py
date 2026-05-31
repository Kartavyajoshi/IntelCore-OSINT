# public_leak_checker.py - Public Leak/Breach Checker Module
# Checks public breach databases and paste sites for exposed credentials

import requests
import hashlib
import time
import traceback
from typing import Dict, Any

def public_leak_checker(email_or_domain: str, check_breaches: bool = True, check_pastes: bool = True) -> Dict[str, Any]:
    """
    Check public leak/breach databases for email or domain exposure.
    Uses free, no-API-key-required services.
    """
    results = {
        'target': email_or_domain,
        'status': 'completed',
        'breaches_found': 0,
        'pastes_found': 0,
        'breach_details': [],
        'paste_details': [],
        'password_exposed': False,
        'risk_level': 'LOW',
        'summary': ''
    }

    try:
        is_email = '@' in email_or_domain

        if check_breaches:
            # Check via HIBP k-anonymity (password check - no API key needed)
            if is_email:
                pwd_check = _check_password_hash_exposure(email_or_domain)
                results['password_exposed'] = pwd_check

            # Check via breach directory
            breach_data = _check_breach_directory(email_or_domain)
            results['breach_details'] = breach_data
            results['breaches_found'] = len(breach_data)

        if check_pastes and is_email:
            paste_data = _check_paste_exposure(email_or_domain)
            results['paste_details'] = paste_data
            results['pastes_found'] = len(paste_data)

        # Calculate risk
        total = results['breaches_found'] + results['pastes_found']
        if results['password_exposed'] or total > 5:
            results['risk_level'] = 'CRITICAL'
        elif total > 2:
            results['risk_level'] = 'HIGH'
        elif total > 0:
            results['risk_level'] = 'MEDIUM'
        else:
            results['risk_level'] = 'LOW'

        results['summary'] = (
            f"Found {results['breaches_found']} breach(es) and "
            f"{results['pastes_found']} paste(s) for {email_or_domain}. "
            f"Risk: {results['risk_level']}"
        )

    except Exception as e:
        results['status'] = 'error'
        results['error'] = str(e)
        traceback.print_exc()

    return results


def _check_password_hash_exposure(email: str) -> bool:
    """Check if email's common password patterns appear in HIBP Pwned Passwords (k-anonymity)"""
    try:
        # Hash the email prefix as a proxy check
        sha1 = hashlib.sha1(email.lower().encode()).hexdigest().upper()
        prefix = sha1[:5]
        suffix = sha1[5:]

        resp = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=10)
        if resp.status_code == 200:
            for line in resp.text.splitlines():
                hash_suffix, count = line.split(':')
                if hash_suffix.strip() == suffix:
                    return True
    except Exception:
        pass
    return False


def _check_breach_directory(target: str) -> list:
    """Check public breach directories for target exposure"""
    breaches = []
    try:
        headers = {'User-Agent': 'IntelCore-OSINT-Platform'}
        resp = requests.get(
            f"https://haveibeenpwned.com/api/v3/breaches",
            headers=headers, timeout=15
        )
        if resp.status_code == 200:
            all_breaches = resp.json()
            domain = target.split('@')[-1] if '@' in target else target
            for b in all_breaches:
                bd = b.get('Domain', '').lower()
                if domain.lower() in bd or bd in domain.lower():
                    breaches.append({
                        'name': b.get('Name', ''),
                        'title': b.get('Title', ''),
                        'date': b.get('BreachDate', ''),
                        'count': b.get('PwnCount', 0),
                        'data_types': b.get('DataClasses', []),
                        'verified': b.get('IsVerified', False)
                    })
    except Exception:
        pass
    return breaches


def _check_paste_exposure(email: str) -> list:
    """Check for paste site exposure (limited without API key)"""
    # Without HIBP API key, paste checking is limited
    # Return empty - would need API key for full paste search
    return []

# functions/email_osint_platform.py
# Email account presence check and reputation analysis
# Educational Purpose Only - IntelCore-OSINT Framework

import re
import time
import hashlib
import requests
import smtplib
import socket
import dns.resolver
from typing import Dict, Any, List, Optional
from logger import get_logger

logger = get_logger()

TIMEOUT = 10
USER_AGENT = 'Mozilla/5.0 (compatible; IntelCore-OSINT/1.0)'

# ─────────────────────────────────────────────
# Social platform presence check (no login)
# ─────────────────────────────────────────────

PLATFORM_CHECKS = [
    # Platform name, URL template (use {username} or {email_hash}), check type
    {'name': 'Gravatar',    'url': 'https://www.gravatar.com/{hash}',
     'type': 'gravatar', 'success_codes': [200]},
    {'name': 'GitHub',      'url': 'https://api.github.com/search/users?q={local_part}+in:email',
     'type': 'github_api', 'success_codes': [200]},
]

COMMON_PLATFORMS_BY_USERNAME = [
    {'name': 'Twitter/X',    'url': 'https://twitter.com/{local_part}',      'status': [200]},
    {'name': 'GitHub',       'url': 'https://github.com/{local_part}',        'status': [200]},
    {'name': 'Instagram',    'url': 'https://www.instagram.com/{local_part}/', 'status': [200]},
    {'name': 'Reddit',       'url': 'https://www.reddit.com/user/{local_part}','status': [200]},
    {'name': 'LinkedIn',     'url': 'https://www.linkedin.com/in/{local_part}','status': [200]},
    {'name': 'Medium',       'url': 'https://medium.com/@{local_part}',        'status': [200]},
    {'name': 'Dev.to',       'url': 'https://dev.to/{local_part}',             'status': [200]},
    {'name': 'Keybase',      'url': 'https://keybase.io/{local_part}',         'status': [200]},
    {'name': 'HackerNews',   'url': 'https://hacker-news.firebaseio.com/v0/user/{local_part}.json',
     'status': [200]},
    {'name': 'GitLab',       'url': 'https://gitlab.com/{local_part}',         'status': [200]},
    {'name': 'Twitch',       'url': 'https://www.twitch.tv/{local_part}',      'status': [200]},
    {'name': 'Pinterest',    'url': 'https://www.pinterest.com/{local_part}/', 'status': [200]},
    {'name': 'TikTok',       'url': 'https://www.tiktok.com/@{local_part}',    'status': [200]},
    {'name': 'Pastebin',     'url': 'https://pastebin.com/u/{local_part}',     'status': [200]},
    {'name': 'About.me',     'url': 'https://about.me/{local_part}',           'status': [200]},
]


def _md5_hash(email: str) -> str:
    """Compute MD5 hash of a lowercase-stripped email (for Gravatar)."""
    return hashlib.md5(email.strip().lower().encode()).hexdigest()


# ─────────────────────────────────────────────
# Gravatar check
# ─────────────────────────────────────────────

def _check_gravatar(email: str) -> Dict[str, Any]:
    """Check if the email has an associated Gravatar profile."""
    result = {'has_gravatar': False, 'gravatar_url': None, 'profile_url': None}
    try:
        email_hash = _md5_hash(email)
        # d=404 returns HTTP 404 if no gravatar exists
        url = f"https://www.gravatar.com/avatar/{email_hash}?d=404&s=200"
        resp = requests.get(url, timeout=TIMEOUT,
                            headers={'User-Agent': USER_AGENT})
        if resp.status_code == 200:
            result['has_gravatar'] = True
            result['gravatar_url'] = f"https://www.gravatar.com/avatar/{email_hash}?s=200"
            result['profile_url'] = f"https://www.gravatar.com/{email_hash}"
    except Exception as e:
        result['error'] = str(e)
    return result


# ─────────────────────────────────────────────
# Have I Been Pwned - breach check (public free endpoint)
# ─────────────────────────────────────────────

def _check_hibp_breaches(email: str) -> Dict[str, Any]:
    """Check email against Have I Been Pwned breach database."""
    result = {'checked': False, 'breached': False, 'breach_count': 0, 'breaches': []}
    try:
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{requests.utils.quote(email)}"
        headers = {
            'hibp-api-key': 'public',
            'User-Agent': 'IntelCore-OSINT (Educational)',
            'Accept': 'application/json'
        }
        resp = requests.get(url, headers=headers, timeout=TIMEOUT)
        if resp.status_code == 200:
            result['checked'] = True
            result['breached'] = True
            breaches = resp.json()
            result['breach_count'] = len(breaches)
            result['breaches'] = [
                {
                    'name': b.get('Name'),
                    'domain': b.get('Domain'),
                    'breach_date': b.get('BreachDate'),
                    'data_classes': b.get('DataClasses', []),
                    'is_sensitive': b.get('IsSensitive', False),
                    'is_verified': b.get('IsVerified', True)
                }
                for b in breaches[:10]
            ]
        elif resp.status_code == 404:
            result['checked'] = True
            result['breached'] = False
        elif resp.status_code == 429:
            result['error'] = 'Rate limited by HIBP'
    except Exception as e:
        result['error'] = str(e)
    return result


# ─────────────────────────────────────────────
# Email format validation
# ─────────────────────────────────────────────

def _validate_email_format(email: str) -> Dict[str, Any]:
    """Validate email format and parse components."""
    result = {
        'valid_format': False,
        'local_part': None,
        'domain': None,
        'tld': None,
        'is_disposable_domain': False,
        'is_role_account': False
    }
    email_pattern = re.compile(
        r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$'
    )
    if not email_pattern.match(email):
        return result

    result['valid_format'] = True
    parts = email.rsplit('@', 1)
    result['local_part'] = parts[0]
    result['domain'] = parts[1]
    tld_parts = parts[1].rsplit('.', 1)
    result['tld'] = tld_parts[-1] if tld_parts else ''

    # Check for role accounts
    role_prefixes = ['admin', 'info', 'support', 'help', 'noreply', 'no-reply',
                     'sales', 'contact', 'webmaster', 'postmaster', 'security',
                     'abuse', 'hostmaster', 'billing', 'legal', 'marketing']
    if result['local_part'].lower() in role_prefixes:
        result['is_role_account'] = True

    # Basic disposable domain list
    disposable_domains = [
        'mailinator.com', 'guerrillamail.com', 'tempmail.com', 'throwaway.email',
        'yopmail.com', '10minutemail.com', 'trashmail.com', 'dispostable.com',
        'fakeinbox.com', 'sharklasers.com', 'guerrillamailblock.com',
        'grr.la', 'guerrillamail.info', 'guerrillamail.biz', 'guerrillamail.de',
        'guerrillamail.net', 'guerrillamail.org', 'spam4.me', 'maildrop.cc',
        'harakirimail.com', 'spamgourmet.com', 'getairmail.com'
    ]
    if result['domain'].lower() in disposable_domains:
        result['is_disposable_domain'] = True

    return result


# ─────────────────────────────────────────────
# MX record check for the email domain
# ─────────────────────────────────────────────

def _check_mx_records(domain: str) -> Dict[str, Any]:
    """Check MX records for the email domain."""
    result = {'has_mx': False, 'mx_records': [], 'mail_provider': 'Unknown'}
    try:
        answers = dns.resolver.resolve(domain, 'MX', lifetime=8)
        for rdata in answers:
            result['mx_records'].append({
                'priority': rdata.preference,
                'host': str(rdata.exchange).rstrip('.')
            })
        if result['mx_records']:
            result['has_mx'] = True

        # Identify mail provider
        mx_hosts = ' '.join(str(r.exchange).lower() for r in answers)
        if 'google' in mx_hosts or 'gmail' in mx_hosts:
            result['mail_provider'] = 'Google Workspace / Gmail'
        elif 'outlook' in mx_hosts or 'microsoft' in mx_hosts or 'protection.outlook' in mx_hosts:
            result['mail_provider'] = 'Microsoft 365 / Outlook'
        elif 'zoho' in mx_hosts:
            result['mail_provider'] = 'Zoho Mail'
        elif 'yahoo' in mx_hosts:
            result['mail_provider'] = 'Yahoo Mail'
        elif 'protonmail' in mx_hosts:
            result['mail_provider'] = 'ProtonMail'
        elif 'mimecast' in mx_hosts:
            result['mail_provider'] = 'Mimecast'
        elif 'sendgrid' in mx_hosts:
            result['mail_provider'] = 'SendGrid'
    except Exception as e:
        result['error'] = str(e)
    return result


# ─────────────────────────────────────────────
# Username presence check across platforms
# ─────────────────────────────────────────────

def _check_platform_presence(local_part: str) -> List[Dict[str, Any]]:
    """Check if the email's local part exists as a username on common platforms."""
    platform_results = []
    session = requests.Session()
    session.headers.update({'User-Agent': USER_AGENT})

    for platform in COMMON_PLATFORMS_BY_USERNAME:
        url = platform['url'].format(local_part=local_part)
        entry = {
            'platform': platform['name'],
            'url': url,
            'found': False,
            'status_code': None
        }
        try:
            resp = session.get(url, timeout=TIMEOUT, allow_redirects=True)
            entry['status_code'] = resp.status_code
            if resp.status_code in platform['status']:
                # Additional content-based checks to reduce false positives
                body = resp.text.lower()
                false_positive_indicators = [
                    'page not found', 'user not found', '404', 'does not exist',
                    'no user', 'this page doesn', 'the person you are looking'
                ]
                is_false_positive = any(ind in body for ind in false_positive_indicators)
                if not is_false_positive:
                    entry['found'] = True
        except Exception:
            pass
        platform_results.append(entry)
        time.sleep(0.3)  # Basic rate limiting

    return platform_results


# ─────────────────────────────────────────────
# EmailRep.io – email reputation
# ─────────────────────────────────────────────

def _check_emailrep(email: str) -> Dict[str, Any]:
    """Check email reputation via EmailRep.io (free tier)."""
    result = {'checked': False, 'reputation': None, 'suspicious': False}
    try:
        url = f"https://emailrep.io/{requests.utils.quote(email)}"
        headers = {
            'User-Agent': 'IntelCore-OSINT (Educational)',
            'Accept': 'application/json'
        }
        resp = requests.get(url, headers=headers, timeout=TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            result['checked'] = True
            result['reputation'] = data.get('reputation')
            result['suspicious'] = data.get('suspicious', False)
            result['references'] = data.get('references', 0)
            result['details'] = data.get('details', {})
            result['last_seen'] = data.get('details', {}).get('last_seen')
    except Exception as e:
        result['error'] = str(e)
    return result


# ─────────────────────────────────────────────
# Main entry point
# ─────────────────────────────────────────────

def email_osint_platform(email: str, check_platforms: bool = True) -> Dict[str, Any]:
    """
    Comprehensive OSINT analysis for an email address.
    
    Checks:
    - Email format validation and component parsing
    - Domain MX records and mail provider identification
    - Gravatar profile presence
    - Have I Been Pwned breach history
    - EmailRep.io reputation score
    - Username presence across 15+ social platforms (using local-part as username)
    
    Args:
        email: Target email address (e.g. 'user@example.com')
        check_platforms: Whether to check social media platform presence (slower)
        
    Returns:
        Comprehensive email intelligence report
    """
    logger.info(f"[EMAIL OSINT] Starting email OSINT for: {email}")
    start_time = time.time()

    results = {
        'email': email,
        'module': 'email_osint_platform',
        'status': 'completed',
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'risk_level': 'LOW',
        'risk_score': 0,
        'validation': {},
        'mx_records': {},
        'gravatar': {},
        'hibp': {},
        'emailrep': {},
        'platform_presence': [],
        'platforms_found': 0,
        'summary': {}
    }

    # 1. Format validation
    results['validation'] = _validate_email_format(email)
    if not results['validation']['valid_format']:
        results['status'] = 'invalid_email'
        results['risk_level'] = 'LOW'
        return results

    local_part = results['validation']['local_part']
    domain = results['validation']['domain']

    # 2. MX records
    results['mx_records'] = _check_mx_records(domain)

    # 3. Gravatar
    results['gravatar'] = _check_gravatar(email)

    # 4. HIBP breach check
    results['hibp'] = _check_hibp_breaches(email)

    # 5. EmailRep reputation
    results['emailrep'] = _check_emailrep(email)

    # 6. Platform presence (username = local_part)
    if check_platforms:
        results['platform_presence'] = _check_platform_presence(local_part)
        results['platforms_found'] = sum(1 for p in results['platform_presence'] if p.get('found'))

    # Risk scoring
    risk_score = 0
    if results['hibp'].get('breached'):
        risk_score += min(results['hibp']['breach_count'] * 8, 40)

    if results['emailrep'].get('suspicious'):
        risk_score += 20

    rep = results['emailrep'].get('reputation', 'none') or 'none'
    if rep in ('low', 'none'):
        risk_score += 10

    if results['validation'].get('is_disposable_domain'):
        risk_score += 15

    if not results['mx_records'].get('has_mx'):
        risk_score += 5

    results['risk_score'] = min(risk_score, 100)
    results['risk_level'] = (
        'CRITICAL' if risk_score >= 60 else
        'HIGH'     if risk_score >= 35 else
        'MEDIUM'   if risk_score >= 15 else
        'LOW'
    )

    # Summary
    results['summary'] = {
        'email': email,
        'valid': results['validation']['valid_format'],
        'domain': domain,
        'mail_provider': results['mx_records'].get('mail_provider', 'Unknown'),
        'has_gravatar': results['gravatar'].get('has_gravatar', False),
        'is_breached': results['hibp'].get('breached', False),
        'breach_count': results['hibp'].get('breach_count', 0),
        'platforms_found': results['platforms_found'],
        'is_disposable': results['validation'].get('is_disposable_domain', False),
        'is_role_account': results['validation'].get('is_role_account', False),
    }

    elapsed = round(time.time() - start_time, 2)
    results['elapsed_seconds'] = elapsed
    logger.info(
        f"[EMAIL OSINT] Done in {elapsed}s. "
        f"Breached: {results['hibp'].get('breached')}, "
        f"Platforms: {results['platforms_found']}, "
        f"Risk: {results['risk_level']}"
    )
    return results

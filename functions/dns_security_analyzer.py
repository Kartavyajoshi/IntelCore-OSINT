# functions/dns_security_analyzer.py
# Deep DNS security analysis: SPF, DMARC, MTA-STS, DNSSEC
# Educational Purpose Only - IntelCore-OSINT Framework

import dns.resolver
import dns.dnssec
import dns.name
import dns.query
import dns.flags
import socket
import re
import time
import requests
from typing import Dict, Any, List, Optional
from logger import get_logger

logger = get_logger()


# ─────────────────────────────────────────────
# SPF Analysis
# ─────────────────────────────────────────────

def _analyze_spf(domain: str) -> Dict[str, Any]:
    """Retrieve and analyze the SPF TXT record."""
    result = {
        'exists': False,
        'record': None,
        'policy': None,
        'include_count': 0,
        'all_mechanism': None,
        'issues': [],
        'recommendations': []
    }
    try:
        answers = dns.resolver.resolve(domain, 'TXT', lifetime=8)
        for rdata in answers:
            txt = b''.join(rdata.strings).decode('utf-8', errors='ignore')
            if txt.startswith('v=spf1'):
                result['exists'] = True
                result['record'] = txt

                # Count include mechanisms
                includes = re.findall(r'include:\S+', txt)
                result['include_count'] = len(includes)

                # Parse the "all" mechanism
                all_match = re.search(r'([+~?-])all', txt)
                if all_match:
                    mechanism = all_match.group(1)
                    mapping = {
                        '+': 'PASS (insecure)',
                        '~': 'SOFTFAIL (weak)',
                        '?': 'NEUTRAL (permissive)',
                        '-': 'FAIL (strict)'
                    }
                    result['all_mechanism'] = mechanism
                    result['policy'] = mapping.get(mechanism, 'UNKNOWN')
                else:
                    result['issues'].append("SPF record has no 'all' mechanism – defaults to neutral")
                    result['policy'] = 'MISSING_ALL'

                # Flag weak policies
                if mechanism in ('+', '?'):
                    result['issues'].append(
                        f"SPF all-mechanism is '{mechanism}all' – does not reject unauthorized senders"
                    )
                    result['recommendations'].append("Change SPF all-mechanism to '-all' to enforce strict rejection")
                elif mechanism == '~':
                    result['recommendations'].append(
                        "SPF softfail (~all) is acceptable but consider upgrading to -all for strict enforcement"
                    )

                if result['include_count'] > 10:
                    result['issues'].append(
                        f"SPF record has {result['include_count']} includes – may hit DNS lookup limit (10)"
                    )

                break  # Only one SPF record should exist

    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        result['issues'].append("No SPF record found – domain is unprotected from email spoofing")
        result['recommendations'].append("Add an SPF TXT record: v=spf1 ... -all")
    except Exception as e:
        result['issues'].append(f"SPF lookup error: {e}")

    return result


# ─────────────────────────────────────────────
# DMARC Analysis
# ─────────────────────────────────────────────

def _analyze_dmarc(domain: str) -> Dict[str, Any]:
    """Retrieve and analyze the DMARC TXT record."""
    result = {
        'exists': False,
        'record': None,
        'policy': None,
        'subdomain_policy': None,
        'percentage': 100,
        'rua': [],
        'ruf': [],
        'adkim': None,
        'aspf': None,
        'issues': [],
        'recommendations': []
    }
    dmarc_domain = f"_dmarc.{domain}"
    try:
        answers = dns.resolver.resolve(dmarc_domain, 'TXT', lifetime=8)
        for rdata in answers:
            txt = b''.join(rdata.strings).decode('utf-8', errors='ignore')
            if 'v=DMARC1' in txt:
                result['exists'] = True
                result['record'] = txt

                # Parse policy
                p_match = re.search(r'\bp=(\w+)', txt)
                if p_match:
                    result['policy'] = p_match.group(1)
                    if result['policy'] == 'none':
                        result['issues'].append("DMARC policy is 'none' – emails are not rejected or quarantined")
                        result['recommendations'].append("Upgrade DMARC policy to 'quarantine' or 'reject'")
                    elif result['policy'] == 'quarantine':
                        result['recommendations'].append("DMARC quarantine is good; consider upgrading to 'reject' for full enforcement")

                # Subdomain policy
                sp_match = re.search(r'\bsp=(\w+)', txt)
                result['subdomain_policy'] = sp_match.group(1) if sp_match else result.get('policy')

                # Percentage
                pct_match = re.search(r'\bpct=(\d+)', txt)
                if pct_match:
                    result['percentage'] = int(pct_match.group(1))
                    if result['percentage'] < 100:
                        result['issues'].append(f"DMARC pct={result['percentage']} – policy only applies to {result['percentage']}% of messages")

                # Reporting
                rua_match = re.findall(r'rua=([^;]+)', txt)
                result['rua'] = [r.strip() for r in rua_match]
                ruf_match = re.findall(r'ruf=([^;]+)', txt)
                result['ruf'] = [r.strip() for r in ruf_match]

                if not result['rua']:
                    result['recommendations'].append("Add rua= (aggregate reporting URI) to receive DMARC reports")

                # Alignment modes
                adkim_match = re.search(r'\badkim=(\w)', txt)
                result['adkim'] = adkim_match.group(1) if adkim_match else 'r'  # default relaxed
                aspf_match = re.search(r'\baspf=(\w)', txt)
                result['aspf'] = aspf_match.group(1) if aspf_match else 'r'

                break

    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        result['issues'].append("No DMARC record found – domain has no email authentication policy")
        result['recommendations'].append(f"Add a DMARC TXT record at _dmarc.{domain}: v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}")
    except Exception as e:
        result['issues'].append(f"DMARC lookup error: {e}")

    return result


# ─────────────────────────────────────────────
# DKIM Analysis (checks common selectors)
# ─────────────────────────────────────────────

def _analyze_dkim(domain: str) -> Dict[str, Any]:
    """Check for DKIM selectors on the domain."""
    result = {
        'selectors_found': [],
        'selectors_checked': [],
        'issues': [],
        'recommendations': []
    }
    common_selectors = [
        'default', 'google', 'mail', 'dkim', 'k1', 'k2', 'selector1',
        'selector2', 'email', 'smtp', 'mimecast', 'proofpoint', 'sendgrid',
        'mailchimp', 'mandrill', 'postmark', 'amazonses'
    ]
    for selector in common_selectors:
        dkim_domain = f"{selector}._domainkey.{domain}"
        try:
            answers = dns.resolver.resolve(dkim_domain, 'TXT', lifetime=5)
            for rdata in answers:
                txt = b''.join(rdata.strings).decode('utf-8', errors='ignore')
                if 'v=DKIM1' in txt or 'p=' in txt:
                    result['selectors_found'].append({
                        'selector': selector,
                        'record': txt[:200]  # Truncate long keys
                    })
        except Exception:
            pass
        result['selectors_checked'].append(selector)

    if not result['selectors_found']:
        result['issues'].append("No DKIM selectors detected from common list")
        result['recommendations'].append("Ensure DKIM is configured for all sending services")

    return result


# ─────────────────────────────────────────────
# MTA-STS Analysis
# ─────────────────────────────────────────────

def _analyze_mta_sts(domain: str) -> Dict[str, Any]:
    """Check MTA-STS policy for the domain."""
    result = {
        'dns_record_exists': False,
        'policy_file_exists': False,
        'dns_record': None,
        'policy': None,
        'mode': None,
        'max_age': None,
        'mx_hosts': [],
        'issues': [],
        'recommendations': []
    }
    # Check DNS TXT record
    mta_sts_dns = f"_mta-sts.{domain}"
    try:
        answers = dns.resolver.resolve(mta_sts_dns, 'TXT', lifetime=8)
        for rdata in answers:
            txt = b''.join(rdata.strings).decode('utf-8', errors='ignore')
            if 'v=STSv1' in txt:
                result['dns_record_exists'] = True
                result['dns_record'] = txt
    except Exception:
        result['issues'].append("No MTA-STS DNS record found at _mta-sts." + domain)
        result['recommendations'].append("Add MTA-STS to enforce TLS for incoming mail delivery")

    # Check policy file
    try:
        url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
        resp = requests.get(url, timeout=8,
                            headers={'User-Agent': 'Mozilla/5.0 (compatible; IntelCore-OSINT)'})
        if resp.status_code == 200 and 'version: STSv1' in resp.text:
            result['policy_file_exists'] = True
            result['policy'] = resp.text.strip()

            # Parse mode and max_age
            mode_match = re.search(r'mode:\s*(\w+)', resp.text)
            if mode_match:
                result['mode'] = mode_match.group(1)
                if result['mode'] == 'testing':
                    result['issues'].append("MTA-STS is in 'testing' mode – TLS is not yet enforced")
                    result['recommendations'].append("Change MTA-STS mode to 'enforce' when ready")
                elif result['mode'] == 'none':
                    result['issues'].append("MTA-STS mode is 'none' – policy is effectively disabled")

            max_age_match = re.search(r'max_age:\s*(\d+)', resp.text)
            if max_age_match:
                result['max_age'] = int(max_age_match.group(1))

            mx_matches = re.findall(r'mx:\s*(.+)', resp.text)
            result['mx_hosts'] = [m.strip() for m in mx_matches]
        else:
            result['issues'].append("MTA-STS policy file not reachable or malformed")
    except Exception:
        result['issues'].append("Could not fetch MTA-STS policy file (mta-sts." + domain + ")")

    return result


# ─────────────────────────────────────────────
# DNSSEC Analysis
# ─────────────────────────────────────────────

def _analyze_dnssec(domain: str) -> Dict[str, Any]:
    """Check DNSSEC signing status for the domain."""
    result = {
        'enabled': False,
        'ds_records': [],
        'dnskey_records': [],
        'validated': False,
        'issues': [],
        'recommendations': []
    }
    # Check DS records (delegation signer – in parent zone)
    try:
        answers = dns.resolver.resolve(domain, 'DS', lifetime=8)
        for rdata in answers:
            result['ds_records'].append(str(rdata))
        if result['ds_records']:
            result['enabled'] = True
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        result['issues'].append("No DS records found – DNSSEC may not be enabled at the registrar")
    except Exception as e:
        result['issues'].append(f"DS lookup error: {e}")

    # Check DNSKEY records
    try:
        answers = dns.resolver.resolve(domain, 'DNSKEY', lifetime=8)
        for rdata in answers:
            result['dnskey_records'].append({
                'flags': rdata.flags,
                'protocol': rdata.protocol,
                'algorithm': rdata.algorithm
            })
        if result['dnskey_records']:
            result['enabled'] = True
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        pass
    except Exception as e:
        result['issues'].append(f"DNSKEY lookup error: {e}")

    if not result['enabled']:
        result['issues'].append("DNSSEC does not appear to be enabled for this domain")
        result['recommendations'].append("Enable DNSSEC at your domain registrar to protect against DNS cache poisoning")
    else:
        result['validated'] = True
        result['recommendations'].append("DNSSEC is enabled. Regularly rotate DNSKEY records per best practices.")

    return result


# ─────────────────────────────────────────────
# Main entry point
# ─────────────────────────────────────────────

def dns_security_analyzer(domain: str) -> Dict[str, Any]:
    """
    Comprehensive DNS security analysis for a domain.
    
    Analyzes:
    - SPF record strength and coverage
    - DMARC policy and reporting configuration
    - DKIM selector presence
    - MTA-STS (mail TLS enforcement) policy
    - DNSSEC (cryptographic DNS signing) status
    
    Args:
        domain: Target domain name (e.g. 'example.com')
        
    Returns:
        Structured dictionary with analysis results and risk indicators
    """
    logger.info(f"[DNS SECURITY] Starting DNS security analysis for: {domain}")
    start_time = time.time()

    spf_result = _analyze_spf(domain)
    dmarc_result = _analyze_dmarc(domain)
    dkim_result = _analyze_dkim(domain)
    mta_sts_result = _analyze_mta_sts(domain)
    dnssec_result = _analyze_dnssec(domain)

    # Aggregate issues and risk scoring
    all_issues = (
        spf_result.get('issues', []) +
        dmarc_result.get('issues', []) +
        dkim_result.get('issues', []) +
        mta_sts_result.get('issues', []) +
        dnssec_result.get('issues', [])
    )
    all_recommendations = (
        spf_result.get('recommendations', []) +
        dmarc_result.get('recommendations', []) +
        dkim_result.get('recommendations', []) +
        mta_sts_result.get('recommendations', []) +
        dnssec_result.get('recommendations', [])
    )

    # Compute a simple security score (0-100, higher = more secure)
    score = 100
    critical_issues = 0
    if not spf_result['exists']:
        score -= 25
        critical_issues += 1
    elif spf_result['all_mechanism'] in ('+', '?', None):
        score -= 15

    if not dmarc_result['exists']:
        score -= 25
        critical_issues += 1
    elif dmarc_result.get('policy') == 'none':
        score -= 15

    if not dkim_result['selectors_found']:
        score -= 10

    if not mta_sts_result['policy_file_exists']:
        score -= 10
    elif mta_sts_result.get('mode') in ('testing', 'none'):
        score -= 5

    if not dnssec_result['enabled']:
        score -= 15

    security_grade = (
        'A' if score >= 90 else
        'B' if score >= 75 else
        'C' if score >= 55 else
        'D' if score >= 35 else
        'F'
    )

    elapsed = round(time.time() - start_time, 2)
    logger.info(f"[DNS SECURITY] Done in {elapsed}s. Score: {score}/100 ({security_grade})")

    return {
        'domain': domain,
        'module': 'dns_security_analyzer',
        'status': 'completed',
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'elapsed_seconds': elapsed,
        'security_score': max(score, 0),
        'security_grade': security_grade,
        'critical_issues_count': critical_issues,
        'total_issues': len(all_issues),
        'spf': spf_result,
        'dmarc': dmarc_result,
        'dkim': dkim_result,
        'mta_sts': mta_sts_result,
        'dnssec': dnssec_result,
        'all_issues': all_issues,
        'all_recommendations': all_recommendations
    }

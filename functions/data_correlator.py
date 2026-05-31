# data_correlator.py - Cross-module Data Correlation Engine
import traceback
from typing import Dict, Any, List

def correlate_all_data(scan_results: Dict[str, Any]) -> Dict[str, Any]:
    """Cross-reference and correlate data from all scanning modules."""
    correlations = {
        'status': 'completed',
        'infrastructure_map': {},
        'email_exposure': {},
        'security_gaps': [],
        'attack_surface': {},
        'key_findings': [],
        'risk_amplifiers': []
    }
    try:
        correlations['infrastructure_map'] = _correlate_infrastructure(scan_results)
        correlations['email_exposure'] = _correlate_email_exposure(scan_results)
        correlations['security_gaps'] = _identify_security_gaps(scan_results)
        correlations['attack_surface'] = _map_attack_surface(scan_results)
        correlations['key_findings'] = _generate_key_findings(correlations)
        correlations['risk_amplifiers'] = _find_risk_amplifiers(scan_results, correlations)
    except Exception as e:
        correlations['status'] = 'error'
        correlations['error'] = str(e)
        traceback.print_exc()
    return correlations

def _correlate_infrastructure(data: Dict) -> Dict[str, Any]:
    infra = {'ip_addresses': [], 'hosting_providers': [], 'technologies': [], 'domains_and_subdomains': [], 'mail_infrastructure': []}
    dns = data.get('dns', {})
    if isinstance(dns, dict):
        infra['ip_addresses'].extend(dns.get('infrastructure', {}).get('ip_addresses', []))
        infra['mail_infrastructure'].extend(dns.get('infrastructure', {}).get('mail_servers', []))
        cloud = dns.get('infrastructure', {}).get('cloud_provider', '')
        if cloud:
            infra['hosting_providers'].append(cloud)
    shodan = data.get('shodan', {})
    if isinstance(shodan, dict):
        geo = shodan.get('geolocation_and_organization', {})
        if geo.get('ip'):
            infra['ip_addresses'].append(geo['ip'])
        if geo.get('organization'):
            infra['hosting_providers'].append(geo['organization'])
    tech = data.get('technology', {})
    if isinstance(tech, dict):
        for t in tech.get('technologies', []):
            infra['technologies'].append(t.get('name', str(t)) if isinstance(t, dict) else str(t))
    certs = data.get('certificates', [])
    if isinstance(certs, list):
        for cert in certs:
            if isinstance(cert, dict):
                infra['domains_and_subdomains'].extend(cert.get('subdomains', []))
    for k in infra:
        infra[k] = list(set(infra[k]))
    return infra

def _correlate_email_exposure(data: Dict) -> Dict[str, Any]:
    exposure = {'total_unique_emails': 0, 'breached_emails': [], 'exposed_emails': [], 'email_providers': {}}
    all_emails = set()
    forensics = data.get('forensics', {})
    if isinstance(forensics, dict):
        for res in forensics.get('results', []):
            for email in res.get('emails', []):
                all_emails.add(email)
    email_enum = data.get('email_enumeration', {})
    if isinstance(email_enum, dict):
        for vr in email_enum.get('data', {}).get('validation_results', []):
            e = vr.get('email', '')
            if e:
                all_emails.add(e)
    breaches = data.get('breaches', {})
    if isinstance(breaches, dict):
        for r in breaches.get('results', []):
            if r.get('is_pwned'):
                exposure['breached_emails'].append(r.get('email', ''))
    exposure['total_unique_emails'] = len(all_emails)
    exposure['exposed_emails'] = list(all_emails)
    exposure['breached_emails'] = list(set(exposure['breached_emails']))
    providers = {}
    for email in all_emails:
        d = email.split('@')[-1] if '@' in email else 'unknown'
        providers[d] = providers.get(d, 0) + 1
    exposure['email_providers'] = providers
    return exposure

def _identify_security_gaps(data: Dict) -> List[Dict]:
    gaps = []
    waf = data.get('waf', {})
    if isinstance(waf, dict):
        unprotected = [r for r in waf.get('results', []) if not r.get('has_waf')]
        if unprotected:
            gaps.append({'category': 'WAF', 'severity': 'HIGH', 'finding': f'{len(unprotected)} endpoint(s) without WAF'})
    dns = data.get('dns', {})
    if isinstance(dns, dict):
        sec = dns.get('security', {})
        if not sec.get('spf_policy'):
            gaps.append({'category': 'Email Security', 'severity': 'MEDIUM', 'finding': 'No SPF record - email spoofing possible'})
        if not sec.get('dmarc_policy'):
            gaps.append({'category': 'Email Security', 'severity': 'MEDIUM', 'finding': 'No DMARC record configured'})
    dirs = data.get('directories', {})
    if isinstance(dirs, dict):
        crit = dirs.get('scan_summary', {}).get('critical_directories', 0)
        if crit > 0:
            gaps.append({'category': 'Directory Exposure', 'severity': 'HIGH', 'finding': f'{crit} critical directories exposed'})
    breaches = data.get('breaches', {})
    if isinstance(breaches, dict):
        pwned = [r for r in breaches.get('results', []) if r.get('is_pwned')]
        if pwned:
            gaps.append({'category': 'Credential Exposure', 'severity': 'CRITICAL', 'finding': f'{len(pwned)} email(s) in breaches'})
    return gaps

def _map_attack_surface(data: Dict) -> Dict[str, Any]:
    surface = {'total_subdomains': 0, 'total_open_ports': 0, 'surface_score': 0}
    certs = data.get('certificates', [])
    if isinstance(certs, list):
        subs = set()
        for c in certs:
            if isinstance(c, dict):
                for s in c.get('subdomains', []):
                    subs.add(s)
        surface['total_subdomains'] = len(subs)
    shodan = data.get('shodan', {})
    if isinstance(shodan, dict):
        surface['total_open_ports'] = len(shodan.get('open_ports_and_services', []))
    score = min(surface['total_subdomains'] * 2, 30) + min(surface['total_open_ports'] * 3, 30)
    surface['surface_score'] = min(score, 100)
    return surface

def _generate_key_findings(correlations: Dict) -> List[str]:
    findings = []
    infra = correlations.get('infrastructure_map', {})
    email = correlations.get('email_exposure', {})
    gaps = correlations.get('security_gaps', [])
    if infra.get('ip_addresses'):
        findings.append(f"Target resolves to {len(infra['ip_addresses'])} unique IP(s)")
    if infra.get('technologies'):
        findings.append(f"Detected {len(infra['technologies'])} technologies")
    if email.get('total_unique_emails', 0) > 0:
        findings.append(f"Discovered {email['total_unique_emails']} email(s)")
    if email.get('breached_emails'):
        findings.append(f"{len(email['breached_emails'])} email(s) in data breaches")
    critical = [g for g in gaps if g.get('severity') == 'CRITICAL']
    if critical:
        findings.append(f"{len(critical)} CRITICAL security gap(s)")
    if not findings:
        findings.append("No significant findings from correlation")
    return findings

def _find_risk_amplifiers(data: Dict, correlations: Dict) -> List[Dict]:
    amplifiers = []
    gaps = correlations.get('security_gaps', [])
    email = correlations.get('email_exposure', {})
    has_breached = len(email.get('breached_emails', [])) > 0
    no_spf = any(g['category'] == 'Email Security' and 'SPF' in g['finding'] for g in gaps)
    if has_breached and no_spf:
        amplifiers.append({'combination': 'Breached Emails + Missing SPF', 'risk_increase': 'HIGH', 'description': 'Phishing and impersonation risk amplified'})
    no_waf = any(g['category'] == 'WAF' for g in gaps)
    exposed_dirs = any(g['category'] == 'Directory Exposure' for g in gaps)
    if no_waf and exposed_dirs:
        amplifiers.append({'combination': 'No WAF + Exposed Directories', 'risk_increase': 'HIGH', 'description': 'Easy exploitation paths available'})
    return amplifiers

# functions/subdomain_takeover_scanner.py
# Subdomain takeover detection via CNAME dangling analysis
# Educational Purpose Only - IntelCore-OSINT Framework

import socket
import dns.resolver
import dns.exception
import requests
import time
from typing import Dict, Any, List
from logger import get_logger

logger = get_logger()

# Known services that are vulnerable to subdomain takeover if CNAME points to them
# and the account/resource is unclaimed
VULNERABLE_SERVICES = {
    'github.io': {
        'name': 'GitHub Pages',
        'fingerprint': ["There isn't a GitHub Pages site here.", "404 Not Found"],
        'severity': 'HIGH'
    },
    'herokuapp.com': {
        'name': 'Heroku',
        'fingerprint': ["No such app", "herokucdn.com/error-pages/no-such-app.html"],
        'severity': 'HIGH'
    },
    'azurewebsites.net': {
        'name': 'Azure Web Apps',
        'fingerprint': ["404 Web Site not found", "This web app has been stopped"],
        'severity': 'HIGH'
    },
    'cloudapp.azure.com': {
        'name': 'Azure Cloud App',
        'fingerprint': ["404 Web Site not found"],
        'severity': 'HIGH'
    },
    's3.amazonaws.com': {
        'name': 'AWS S3',
        'fingerprint': ["NoSuchBucket", "The specified bucket does not exist"],
        'severity': 'CRITICAL'
    },
    'amazonaws.com': {
        'name': 'AWS',
        'fingerprint': ["NoSuchBucket", "404"],
        'severity': 'CRITICAL'
    },
    'fastly.net': {
        'name': 'Fastly CDN',
        'fingerprint': ["Fastly error: unknown domain", "Please check that this domain has been added"],
        'severity': 'MEDIUM'
    },
    'pantheonsite.io': {
        'name': 'Pantheon',
        'fingerprint': ["404 error unknown site!", "The gods are wise"],
        'severity': 'HIGH'
    },
    'shopify.com': {
        'name': 'Shopify',
        'fingerprint': ["Sorry, this shop is currently unavailable.", "only works with custom domains"],
        'severity': 'MEDIUM'
    },
    'ghost.io': {
        'name': 'Ghost CMS',
        'fingerprint': ["The thing you were looking for is no longer here"],
        'severity': 'MEDIUM'
    },
    'netlify.app': {
        'name': 'Netlify',
        'fingerprint': ["Not Found - Request ID", "Page Not Found"],
        'severity': 'HIGH'
    },
    'surge.sh': {
        'name': 'Surge',
        'fingerprint': ["project not found", "surge.sh"],
        'severity': 'MEDIUM'
    },
    'readme.io': {
        'name': 'Readme.io',
        'fingerprint': ["Project doesnt exist... yet!", "project not found"],
        'severity': 'MEDIUM'
    },
    'tumblr.com': {
        'name': 'Tumblr',
        'fingerprint': ["Whatever you were looking for doesn't currently exist at this address"],
        'severity': 'LOW'
    },
    'wordpress.com': {
        'name': 'WordPress',
        'fingerprint': ["Do you want to register"],
        'severity': 'LOW'
    },
    'zendesk.com': {
        'name': 'Zendesk',
        'fingerprint': ["Help Center Closed"],
        'severity': 'MEDIUM'
    },
    'webflow.io': {
        'name': 'Webflow',
        'fingerprint': ["The page you are looking for doesn't exist", "page not found"],
        'severity': 'MEDIUM'
    },
    'bitbucket.io': {
        'name': 'Bitbucket',
        'fingerprint': ["The page you have requested does not exist"],
        'severity': 'HIGH'
    },
    'vercel.app': {
        'name': 'Vercel',
        'fingerprint': ["The deployment could not be found", "DEPLOYMENT_NOT_FOUND"],
        'severity': 'HIGH'
    },
}

def _resolve_cname(subdomain: str) -> List[str]:
    """Resolve CNAME chain for a subdomain."""
    cnames = []
    try:
        answers = dns.resolver.resolve(subdomain, 'CNAME', lifetime=5)
        for rdata in answers:
            cname_target = str(rdata.target).rstrip('.')
            cnames.append(cname_target)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers,
            dns.exception.Timeout, Exception):
        pass
    return cnames


def _check_dns_resolves(subdomain: str) -> bool:
    """Check if a subdomain resolves to an IP address."""
    try:
        socket.gethostbyname(subdomain)
        return True
    except socket.gaierror:
        return False


def _check_http_fingerprint(subdomain: str, fingerprints: List[str], timeout: int = 8) -> Dict[str, Any]:
    """Check if the HTTP response matches known takeover fingerprints."""
    for scheme in ['https', 'http']:
        try:
            url = f"{scheme}://{subdomain}"
            resp = requests.get(url, timeout=timeout, allow_redirects=True,
                                headers={'User-Agent': 'Mozilla/5.0 (compatible; IntelCore-OSINT)'})
            body = resp.text
            for fingerprint in fingerprints:
                if fingerprint.lower() in body.lower():
                    return {
                        'vulnerable': True,
                        'matched_fingerprint': fingerprint,
                        'status_code': resp.status_code,
                        'url': url
                    }
            return {'vulnerable': False, 'status_code': resp.status_code, 'url': url}
        except requests.RequestException:
            continue
    return {'vulnerable': False, 'status_code': None, 'url': None}


def subdomain_takeover_scanner(domain: str, subdomains: List[str] = None) -> Dict[str, Any]:
    """
    Scan a domain and its subdomains for potential subdomain takeover vulnerabilities.
    
    Checks:
    1. Resolves CNAME chains for all known subdomains
    2. Identifies CNAMEs pointing to vulnerable third-party services
    3. Verifies the service endpoint returns an unclaimed/error page
    
    Args:
        domain: Target root domain (e.g. 'example.com')
        subdomains: Optional list of known subdomains to check
        
    Returns:
        Dictionary with scan results and vulnerability findings
    """
    logger.info(f"[TAKEOVER SCAN] Starting subdomain takeover scan for: {domain}")
    start_time = time.time()

    results = {
        'domain': domain,
        'module': 'subdomain_takeover_scanner',
        'status': 'completed',
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'summary': {
            'total_checked': 0,
            'vulnerable': 0,
            'dangling_cnames': 0,
            'at_risk': 0,
        },
        'findings': [],
        'vulnerable_subdomains': [],
        'dangling_cnames': [],
        'at_risk': [],
        'scanned': []
    }

    # Build list of subdomains to check
    if not subdomains:
        subdomains = []
    
    # Always check some common subdomains of the root domain
    common_subs = [
        'www', 'mail', 'smtp', 'ftp', 'vpn', 'blog', 'dev', 'staging', 'api',
        'app', 'cdn', 'static', 'assets', 'media', 'portal', 'admin', 'store',
        'shop', 'support', 'help', 'docs', 'status', 'test', 'demo', 'beta'
    ]
    full_subdomains = list(set(
        [f"{sub}.{domain}" for sub in common_subs] + subdomains
    ))

    results['summary']['total_checked'] = len(full_subdomains)

    for subdomain in full_subdomains:
        try:
            cnames = _resolve_cname(subdomain)
            if not cnames:
                results['scanned'].append({'subdomain': subdomain, 'has_cname': False})
                continue

            for cname in cnames:
                cname_lower = cname.lower()
                # Check if CNAME points to a known vulnerable service
                matched_service = None
                matched_key = None
                for service_suffix, service_info in VULNERABLE_SERVICES.items():
                    if cname_lower.endswith(service_suffix) or service_suffix in cname_lower:
                        matched_service = service_info
                        matched_key = service_suffix
                        break

                if not matched_service:
                    results['scanned'].append({
                        'subdomain': subdomain,
                        'has_cname': True,
                        'cname': cname,
                        'vulnerable_service': False
                    })
                    continue

                # Dangling check: does the CNAME target resolve?
                cname_resolves = _check_dns_resolves(cname)
                subdomain_resolves = _check_dns_resolves(subdomain)

                finding = {
                    'subdomain': subdomain,
                    'cname_target': cname,
                    'service_name': matched_service['name'],
                    'service_key': matched_key,
                    'severity': matched_service['severity'],
                    'cname_resolves': cname_resolves,
                    'subdomain_resolves': subdomain_resolves,
                    'http_check': None,
                    'vulnerable': False,
                    'risk_reason': ''
                }

                if not subdomain_resolves:
                    # DNS doesn't resolve at all - dangling CNAME
                    finding['vulnerable'] = True
                    finding['risk_reason'] = f"NXDOMAIN – CNAME points to {matched_service['name']} but subdomain does not resolve. High takeover risk."
                    results['dangling_cnames'].append(subdomain)
                    results['summary']['dangling_cnames'] += 1
                else:
                    # Subdomain resolves – verify via HTTP fingerprint
                    http_result = _check_http_fingerprint(
                        subdomain, matched_service['fingerprint']
                    )
                    finding['http_check'] = http_result

                    if http_result.get('vulnerable'):
                        finding['vulnerable'] = True
                        finding['risk_reason'] = (
                            f"HTTP fingerprint match on {matched_service['name']}: "
                            f"'{http_result['matched_fingerprint']}'"
                        )
                        results['vulnerable_subdomains'].append(subdomain)
                        results['summary']['vulnerable'] += 1
                    else:
                        finding['risk_reason'] = f"CNAME points to {matched_service['name']} but no takeover fingerprint detected."
                        results['at_risk'].append(subdomain)
                        results['summary']['at_risk'] += 1

                results['findings'].append(finding)

        except Exception as e:
            logger.warning(f"[TAKEOVER SCAN] Error checking {subdomain}: {e}")
            results['scanned'].append({'subdomain': subdomain, 'error': str(e)})

    elapsed = round(time.time() - start_time, 2)
    results['elapsed_seconds'] = elapsed

    vuln_count = results['summary']['vulnerable']
    dangling_count = results['summary']['dangling_cnames']
    logger.info(
        f"[TAKEOVER SCAN] Done in {elapsed}s. "
        f"Vulnerable: {vuln_count}, Dangling: {dangling_count}"
    )
    return results

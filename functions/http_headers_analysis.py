"""
HTTP Headers, Redirects & Metadata Analysis
Analyzes response headers, redirect chains, robots.txt, sitemap, meta tags
Free analysis of web server fingerprinting and configuration
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from typing import Dict, List, Any
import time
import re

def http_headers_analysis(target: str) -> Dict[str, Any]:
    """
    Comprehensive HTTP headers, redirects, and metadata analysis
    
    Args:
        target: URL or domain to analyze
    
    Returns:
        Dict with headers, redirects, robots.txt, meta tags analysis
    """
    print(f"[*] Starting HTTP headers and metadata analysis for: {target}")
    
    try:
        # Normalize target
        target = target.strip().lower()
        if not target.startswith('http'):
            target = f'https://{target}'
        
        results = {
            'status': 'success',
            'target': target,
            'headers': {},
            'redirect_chain': [],
            'response_code': None,
            'robots_txt': None,
            'sitemap_xml': None,
            'meta_tags': {},
            'security_headers': {},
            'server_fingerprint': {},
            'intelligence': {},
            'timestamp': time.time()
        }
        
        # 1. Follow redirect chain
        redirect_chain, final_response = _follow_redirects(target)
        results['redirect_chain'] = redirect_chain
        results['response_code'] = final_response.status_code if final_response else None
        
        if final_response:
            # 2. Analyze headers
            results['headers'] = dict(final_response.headers)
            
            # 3. Extract security headers
            results['security_headers'] = _analyze_security_headers(final_response.headers)
            
            # 4. Server fingerprinting
            results['server_fingerprint'] = _fingerprint_server(final_response.headers)
            
            # 5. Parse HTML for meta tags
            try:
                soup = BeautifulSoup(final_response.text, 'html.parser')
                results['meta_tags'] = _extract_meta_tags(soup)
            except:
                pass
        
        # 6. Fetch robots.txt
        robots_url = urljoin(target, '/robots.txt')
        try:
            robots_resp = requests.get(robots_url, timeout=15)
            if robots_resp.status_code == 200:
                results['robots_txt'] = robots_resp.text
        except:
            pass
        
        # 7. Fetch sitemap.xml
        sitemap_url = urljoin(target, '/sitemap.xml')
        try:
            sitemap_resp = requests.get(sitemap_url, timeout=15)
            if sitemap_resp.status_code == 200:
                results['sitemap_xml'] = _parse_sitemap(sitemap_resp.text)
        except:
            pass
        
        # 8. Generate intelligence
        results['intelligence'] = _generate_http_intelligence(results)
        
        print(f"[+] HTTP analysis complete: {len(results['headers'])} headers analyzed")
        return results
        
    except Exception as e:
        return {
            'status': 'error',
            'message': f'HTTP headers analysis failed: {str(e)}',
            'error': str(e)
        }

def _follow_redirects(url: str, max_redirects: int = 10) -> tuple[List[Dict[str, Any]], Any]:
    """Follow redirect chain and return all redirects"""
    redirect_chain = []
    
    try:
        session = requests.Session()
        session.max_redirects = max_redirects
        
        response = session.get(url, timeout=20, allow_redirects=True, verify=False)
        
        # Extract redirect history
        for redirect_response in session.resolve_redirects(
            session.request('GET', url, allow_redirects=False),
            session.request('GET', url, allow_redirects=False)
        ):
            redirect_chain.append({
                'from': redirect_response.url,
                'status_code': redirect_response.status_code,
                'location': redirect_response.headers.get('Location', 'N/A')
            })
        
        # Simplified redirect detection
        try:
            test_response = requests.get(url, timeout=15, allow_redirects=False)
            
            if 300 <= test_response.status_code < 400:
                location = test_response.headers.get('Location')
                if location:
                    redirect_chain.append({
                        'from': url,
                        'status_code': test_response.status_code,
                        'to': location
                    })
            
            # Follow the final redirect
            final_response = requests.get(url, timeout=15, allow_redirects=True)
            return redirect_chain, final_response
            
        except Exception as e:
            print(f"[!] Error following redirects: {e}")
            return redirect_chain, None
            
    except Exception as e:
        print(f"[!] Error in redirect analysis: {e}")
        return [], None

def _analyze_security_headers(headers: Dict[str, str]) -> Dict[str, Any]:
    """Analyze security-related HTTP headers"""
    security = {
        'present': [],
        'missing': [],
        'details': {}
    }
    
    # Security headers to check
    important_headers = {
        'Strict-Transport-Security': 'HSTS (Force HTTPS)',
        'Content-Security-Policy': 'CSP (XSS Protection)',
        'X-Content-Type-Options': 'X-Content-Type-Options (MIME Sniffing)',
        'X-Frame-Options': 'X-Frame-Options (Clickjacking)',
        'X-XSS-Protection': 'X-XSS Protection',
        'Referrer-Policy': 'Referrer-Policy',
        'Permissions-Policy': 'Permissions-Policy',
        'Set-Cookie': 'Secure Cookies'
    }
    
    for header, description in important_headers.items():
        if header in headers:
            security['present'].append(description)
            security['details'][header] = headers[header][:100]
        else:
            security['missing'].append(description)
    
    return security

def _fingerprint_server(headers: Dict[str, str]) -> Dict[str, str]:
    """Fingerprint server and software from headers"""
    fingerprint = {
        'server': 'Unknown',
        'powered_by': 'Unknown',
        'framework': 'Unknown',
        'language': 'Unknown',
        'cdn': None,
        'analytics': []
    }
    
    # Server header
    if 'Server' in headers:
        fingerprint['server'] = headers['Server']
        server_lower = headers['Server'].lower()
        
        if 'apache' in server_lower:
            fingerprint['framework'] = 'Apache'
        if 'nginx' in server_lower:
            fingerprint['framework'] = 'nginx'
        if 'iis' in server_lower:
            fingerprint['framework'] = 'IIS'
    
    # X-Powered-By
    if 'X-Powered-By' in headers:
        fingerprint['powered_by'] = headers['X-Powered-By']
        if 'php' in headers['X-Powered-By'].lower():
            fingerprint['language'] = 'PHP'
        elif 'asp' in headers['X-Powered-By'].lower():
            fingerprint['language'] = 'ASP.NET'
        elif 'node' in headers['X-Powered-By'].lower():
            fingerprint['language'] = 'Node.js'
    
    # CDN detection
    if 'CF-Ray' in headers:
        fingerprint['cdn'] = 'Cloudflare'
    elif 'X-AmzCf-PopId' in headers:
        fingerprint['cdn'] = 'Amazon CloudFront'
    elif 'X-CDN-Provider' in headers:
        fingerprint['cdn'] = headers['X-CDN-Provider']
    
    return fingerprint

def _extract_meta_tags(soup) -> Dict[str, Any]:
    """Extract important meta tags"""
    meta_info = {
        'title': None,
        'description': None,
        'robots': None,
        'canonical': None,
        'og_tags': {},
        'custom': []
    }
    
    try:
        # Title
        title = soup.find('title')
        if title:
            meta_info['title'] = title.string
        
        # Meta description
        desc_meta = soup.find('meta', attrs={'name': 'description'})
        if desc_meta:
            meta_info['description'] = desc_meta.get('content')
        
        # Robots
        robots_meta = soup.find('meta', attrs={'name': 'robots'})
        if robots_meta:
            meta_info['robots'] = robots_meta.get('content')
        
        # Canonical
        canonical = soup.find('link', attrs={'rel': 'canonical'})
        if canonical:
            meta_info['canonical'] = canonical.get('href')
        
        # Open Graph tags
        og_tags = soup.find_all('meta', attrs={'property': re.compile('^og:')})
        for og in og_tags[:10]:
            prop = og.get('property', 'unknown')
            content = og.get('content', '')
            meta_info['og_tags'][prop] = content
    
    except Exception as e:
        print(f"[!] Error extracting meta tags: {e}")
    
    return meta_info

def _parse_sitemap(sitemap_xml: str) -> Dict[str, Any]:
    """Parse XML sitemap"""
    try:
        soup = BeautifulSoup(sitemap_xml, 'xml')
        urls = soup.find_all('loc')
        
        return {
            'urls_found': len(urls),
            'sample_urls': [url.string for url in urls[:20]]
        }
    except Exception as e:
        print(f"[!] Error parsing sitemap: {e}")
        return {'error': str(e)}

def _generate_http_intelligence(results: Dict[str, Any]) -> Dict[str, Any]:
    """Generate intelligence from HTTP analysis"""
    intel = {
        'redirect_count': len(results['redirect_chain']),
        'security_headers_present': len(results['security_headers'].get('present', [])),
        'security_headers_missing': len(results['security_headers'].get('missing', [])),
        'has_security_issues': False,
        'recommendations': []
    }
    
    # Check for security issues
    if intel['security_headers_missing'] > 5:
        intel['has_security_issues'] = True
        intel['recommendations'].append('Add more security headers')
    
    if results['security_headers'].get('missing'):
        if 'HSTS (Force HTTPS)' in results['security_headers']['missing']:
            intel['recommendations'].append('Enable HSTS (Strict-Transport-Security)')
        if 'CSP (XSS Protection)' in results['security_headers']['missing']:
            intel['recommendations'].append('Implement Content-Security-Policy')
    
    return intel

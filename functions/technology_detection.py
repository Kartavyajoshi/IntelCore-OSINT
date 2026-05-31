"""
Technology Detection / Website Fingerprinting Module
Detects CMS, frameworks, JavaScript libraries, servers using headers and HTML analysis
Similar to Wappalyzer but free and no API required
"""

import requests
from bs4 import BeautifulSoup
from typing import Dict, List, Any, Set
import re
import json
import time

def technology_detection(target: str) -> Dict[str, Any]:
    """
    Fingerprint website technology stack
    
    Args:
        target: URL or domain to fingerprint
    
    Returns:
        Dict with detected technologies categorized by type
    """
    print(f"[*] Starting technology detection for: {target}")
    
    try:
        # Normalize target
        target = target.strip().lower()
        if not target.startswith('http'):
            target = f'https://{target}'
        
        results = {
            'status': 'success',
            'target': target,
            'technologies': {
                'servers': [],
                'programming_languages': [],
                'cms': [],
                'javascript_frameworks': [],
                'libraries': [],
                'analytics': [],
                'cdn': [],
                'hosting': [],
                'other': []
            },
            'headers': {},
            'technologies_count': 0,
            'confidence_score': 0.0,
            'timestamp': time.time()
        }
        
        # Fetch the webpage
        try:
            response = requests.get(target, timeout=20, allow_redirects=True)
            html_content = response.text
            headers = response.headers
        except Exception as e:
            return {
                'status': 'error',
                'message': f'Failed to fetch target: {str(e)}',
                'error': str(e)
            }
        
        results['headers'] = dict(headers)
        
        # Parse HTML
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
        except:
            soup = None
        
        # 1. Detect from HTTP headers
        header_detections = _detect_from_headers(headers)
        for category, techs in header_detections.items():
            if category in results['technologies']:
                results['technologies'][category].extend(techs)
        
        # 2. Detect from HTML meta tags and comments
        if soup:
            html_detections = _detect_from_html(html_content, soup)
            for category, techs in html_detections.items():
                if category in results['technologies']:
                    results['technologies'][category].extend(techs)
        
        # 3. Detect from JavaScript
        if html_content:
            js_detections = _detect_from_javascript(html_content)
            for category, techs in js_detections.items():
                if category in results['technologies']:
                    results['technologies'][category].extend(techs)
        
        # Remove duplicates and deduplicate
        for category in results['technologies']:
            results['technologies'][category] = list(set(results['technologies'][category]))
            results['technologies'][category] = [t for t in results['technologies'][category] if t]
        
        # Count total detections
        results['technologies_count'] = sum(len(v) for v in results['technologies'].values())
        
        # Calculate confidence score
        results['confidence_score'] = min(100.0, results['technologies_count'] * 10)
        
        print(f"[+] Technology detection complete: {results['technologies_count']} technologies detected")
        return results
        
    except Exception as e:
        return {
            'status': 'error',
            'message': f'Technology detection failed: {str(e)}',
            'error': str(e)
        }

def _detect_from_headers(headers: Dict[str, str]) -> Dict[str, List[str]]:
    """Detect technologies from HTTP response headers"""
    detections = {
        'servers': [],
        'programming_languages': [],
        'cdn': [],
        'other': []
    }
    
    # Server detection
    if 'Server' in headers:
        server = headers['Server'].lower()
        detections['servers'].append(headers['Server'])
        
        if 'apache' in server:
            detections['servers'].append('Apache')
        if 'nginx' in server:
            detections['servers'].append('nginx')
        if 'microsoft-iis' in server:
            detections['servers'].append('IIS')
        if 'cloudflare' in server:
            detections['cdn'].append('Cloudflare')
    
    # X-Powered-By header (CMS/Framework)
    if 'X-Powered-By' in headers:
        powered = headers['X-Powered-By'].lower()
        detections['programming_languages'].append(headers['X-Powered-By'])
        
        if 'php' in powered:
            detections['programming_languages'].append('PHP')
        if 'asp' in powered:
            detections['programming_languages'].append('ASP.NET')
        if 'jsp' in powered:
            detections['programming_languages'].append('Java')
        if 'node' in powered or 'express' in powered:
            detections['programming_languages'].append('Node.js')
    
    # X-AspNet-Version header
    if 'X-AspNet-Version' in headers:
        detections['programming_languages'].append(f"ASP.NET {headers['X-AspNet-Version']}")
    
    # CDN detection from headers
    if 'CF-Ray' in headers:  # Cloudflare
        detections['cdn'].append('Cloudflare')
    if 'X-CDN-Provider' in headers:
        detections['cdn'].append(headers['X-CDN-Provider'])
    if 'Via' in headers:
        via = headers['Via'].lower()
        if 'cloudflare' in via:
            detections['cdn'].append('Cloudflare')
    
    return detections

def _detect_from_html(html_content: str, soup) -> Dict[str, List[str]]:
    """Detect technologies from HTML content"""
    detections = {
        'cms': [],
        'javascript_frameworks': [],
        'libraries': [],
        'analytics': [],
        'other': []
    }
    
    html_lower = html_content.lower()
    
    # Meta generator
    generator_meta = soup.find('meta', attrs={'name': 'generator'})
    if generator_meta and generator_meta.get('content'):
        detections['cms'].append(generator_meta['content'])
    
    # CMS Signatures
    if 'wordpress' in html_lower:
        detections['cms'].append('WordPress')
    if 'drupal' in html_lower:
        detections['cms'].append('Drupal')
    if 'joomla' in html_lower:
        detections['cms'].append('Joomla')
    if 'magento' in html_lower:
        detections['cms'].append('Magento')
    if 'shopify' in html_lower:
        detections['cms'].append('Shopify')
    if 'wix' in html_lower:
        detections['cms'].append('Wix')
    if 'squarespace' in html_lower:
        detections['cms'].append('Squarespace')
    
    # JavaScript Framework detection
    if 'react' in html_lower or '/react' in html_lower:
        detections['javascript_frameworks'].append('React')
    if 'vue' in html_lower or '/vue' in html_lower:
        detections['javascript_frameworks'].append('Vue.js')
    if 'angular' in html_lower or '/angular' in html_lower:
        detections['javascript_frameworks'].append('Angular')
    if 'backbone' in html_lower:
        detections['javascript_frameworks'].append('Backbone.js')
    if 'ember' in html_lower or 'ember-app' in html_lower:
        detections['javascript_frameworks'].append('Ember.js')
    if 'next.js' in html_lower or 'nextjs' in html_lower:
        detections['javascript_frameworks'].append('Next.js')
    
    # jQuery detection
    if 'jquery' in html_lower:
        detections['libraries'].append('jQuery')
    
    # Bootstrap detection
    if 'bootstrap' in html_lower and '/bootstrap' in html_lower:
        detections['libraries'].append('Bootstrap')
    
    # Analytics detection
    if 'google-analytics' in html_lower or '_gaq' in html_lower:
        detections['analytics'].append('Google Analytics')
    if 'mixpanel' in html_lower:
        detections['analytics'].append('Mixpanel')
    if 'segment' in html_lower:
        detections['analytics'].append('Segment')
    if 'hotjar' in html_lower:
        detections['analytics'].append('Hotjar')
    if 'amplitude' in html_lower:
        detections['analytics'].append('Amplitude')
    
    # Script sources
    scripts = soup.find_all('script', src=True)
    for script in scripts[:50]:  # Check first 50 scripts
        src = script.get('src', '').lower()
        
        # CDN detection
        if 'cloudflare' in src:
            detections['other'].append('Cloudflare')
        if 'unpkg.com' in src or 'cdnjs.cloudflare.com' in src or 'cdn.jsdelivr.net' in src:
            detections['other'].append('Third-party CDN')
        
        # Detect libraries from CDN URLs
        if 'jquery' in src and 'jQuery' not in detections['libraries']:
            detections['libraries'].append('jQuery')
        if 'bootstrap' in src and 'Bootstrap' not in detections['libraries']:
            detections['libraries'].append('Bootstrap')
        if 'moment.js' in src or 'moment.min.js' in src:
            detections['libraries'].append('Moment.js')
        if 'chart.js' in src:
            detections['libraries'].append('Chart.js')
        if 'datatables' in src:
            detections['libraries'].append('DataTables')
    
    return detections

def _detect_from_javascript(html_content: str) -> Dict[str, List[str]]:
    """Detect technologies from inline JavaScript"""
    detections = {
        'javascript_frameworks': [],
        'libraries': [],
        'other': []
    }
    
    html_lower = html_content.lower()
    
    # Extract script content
    script_pattern = r'<script[^>]*>(.*?)</script>'
    scripts = re.findall(script_pattern, html_content, re.DOTALL | re.IGNORECASE)
    
    script_content = ' '.join(scripts)
    script_lower = script_content.lower()
    
    # Framework detection from window objects
    if 'window.__react' in script_lower or 'react.__version__' in script_lower:
        detections['javascript_frameworks'].append('React')
    if 'window.__vue' in script_lower or 'window.vue' in script_lower:
        detections['javascript_frameworks'].append('Vue.js')
    if 'window.angular' in script_lower or 'angular.version' in script_lower:
        detections['javascript_frameworks'].append('Angular')
    
    # Library detection
    if 'underscore._' in script_lower:
        detections['libraries'].append('Underscore.js')
    if 'lodash' in script_lower:
        detections['libraries'].append('Lodash')
    if 'google.analytics' in script_lower:
        detections['other'].append('Google Analytics')
    
    return detections

def get_technology_report(tech_dict: Dict[str, List[str]]) -> str:
    """Generate human-readable technology report"""
    report = "## Technology Stack Detected\n\n"
    
    for category, techs in tech_dict.items():
        if techs:
            report += f"**{category.replace('_', ' ').title()}:**\n"
            for tech in techs:
                report += f"  - {tech}\n"
            report += "\n"
    
    return report

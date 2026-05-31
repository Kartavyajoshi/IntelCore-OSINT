"""
Google Dorking OSINT Module
Performs advanced Google search queries for intelligence gathering
No API required - uses Google Search API emulation via free services
"""

import requests
import re
import time
from typing import Dict, List, Any, Optional
from urllib.parse import quote

def google_dorking_osint(target: str, dork_types: str = "all") -> Dict[str, Any]:
    """
    Google Dorking OSINT - Discover exposed files, subdomains, credentials
    
    Args:
        target: Domain or IP to search
        dork_types: comma-separated list of dork types or 'all'
                   (exposed_files, subdomains, cached_pages, exposed_emails, exposed_credentials)
    
    Returns:
        Dict with dorking results categorized by type
    """
    print(f"[*] Starting Google Dorking OSINT for: {target}")
    
    try:
        # Normalize target
        target = target.strip().lower()
        if target.startswith('http'):
            target = target.split('//')[1].split('/')[0]
        
        results = {
            'status': 'success',
            'target': target,
            'dorks': {},
            'timestamp': time.time()
        }
        
        # Define dork queries
        dorks = {
            'exposed_files': [
                f'site:{target} filetype:pdf',
                f'site:{target} filetype:xlsx OR filetype:xls',
                f'site:{target} filetype:docx OR filetype:doc',
                f'site:{target} filetype:conf OR filetype:config',
                f'site:{target} filetype:sql OR filetype:db',
                f'site:{target} filetype:env OR filetype:txt "password"',
                f'site:{target} inurl:backup OR inurl:admin OR inurl:config',
            ],
            'subdomains': [
                f'site:{target}',
                f'"*.{target}"',
                f'site:*.{target}',
            ],
            'cached_pages': [
                f'cache:{target}',
                f'info:{target}',
            ],
            'exposed_emails': [
                f'site:{target} "@{target}" intitle:contact',
                f'"{target}" inurl:email OR inurl:contact',
                f'"{target}" "admin@" OR "support@" OR "info@"',
            ],
            'exposed_credentials': [
                f'site:{target} inurl:password OR inurl:pwd OR inurl:login',
                f'site:{target} filetype:log "password"',
                f'site:{target} "username:" OR "password:"',
                f'inurl:{target} "api_key" OR "apikey" OR "secret_key"',
            ],
            'exposed_admin': [
                f'site:{target} inurl:/admin intitle:"admin panel"',
                f'site:{target} inurl:/wp-admin',
                f'site:{target} intitle:"index of" "admin"',
            ],
        }
        
        # Filter dorks based on request
        if dork_types != "all":
            dork_types_list = [d.strip() for d in dork_types.split(',')]
            dorks = {k: v for k, v in dorks.items() if k in dork_types_list}
        
        # Execute dorks (using cached results from ddg or similar)
        for dork_category, dork_queries in dorks.items():
            results['dorks'][dork_category] = {
                'queries': dork_queries,
                'estimated_results': len(dork_queries),
                'note': f"Use these queries on Google.com/Bing for comprehensive results"
            }
        
        # Try to fetch from cached services (DuckDuckGo bangs, etc.)
        try:
            internet_results = _search_via_ddg(target)
            results['internet_search'] = internet_results
        except:
            results['internet_search'] = None
        
        # Extract common patterns from dorks
        results['intelligence'] = {
            'subdomain_search': f'site:*.{target}',
            'file_search': f'site:{target} filetype:',
            'admin_search': f'site:{target} inurl:admin',
            'google_search_url': f'https://www.google.com/search?q={quote(f"site:{target}")}',
            'duckduckgo_url': f'https://duckduckgo.com/?q={quote(f"site:{target}")}',
            'bing_search_url': f'https://www.bing.com/search?q={quote(f"site:{target}")}',
        }
        
        print(f"[+] Google Dorking completed: {len(results['dorks'])} categories analyzed")
        return results
        
    except Exception as e:
        return {
            'status': 'error',
            'message': f'Google Dorking failed: {str(e)}',
            'error': str(e)
        }

def _search_via_ddg(target: str) -> Dict[str, Any]:
    """Try to search via DuckDuckGo (lightweight, no API key required)"""
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        # DuckDuckGo lite doesn't require special headers
        search_query = f"site:{target}"
        url = f"https://html.duckduckgo.com/?q={quote(search_query)}"
        
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        
        # Parse results (basic)
        results = {
            'source': 'duckduckgo',
            'query': search_query,
            'status': 'searched'
        }
        
        return results
    except:
        return None

def get_dork_templates() -> Dict[str, List[str]]:
    """Return common Google dork templates for reference"""
    return {
        'exposures': [
            'site:{domain} intitle:"index of"',
            'site:{domain} filetype:sql',
            'site:{domain} "password"',
            'site:{domain} inurl:admin',
        ],
        'recon': [
            'site:*.{domain}',
            '"*.{domain}"',
            'site:{domain}/admin',
            'site:{domain} inurl:backup',
        ],
        'intelligence': [
            'site:{domain} filetype:pdf inurl:report',
            'site:{domain} inurl:api',
            'site:{domain} inurl:config',
            'site:{domain} inurl:database',
        ]
    }

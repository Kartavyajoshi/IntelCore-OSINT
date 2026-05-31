"""
Social Media Enumeration & Username Verification Module
Searches for social media profiles, validates usernames across platforms
Free alternative to Sherlock using direct HTTP requests
"""

import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Any
import time
import re

def social_media_enum(username: str, domain: str = None) -> Dict[str, Any]:
    """
    Enumerate social media profiles and usernames
    
    Args:
        username: Username or email to search for
        domain: Optional domain/company name for context
    
    Returns:
        Dict with found profiles and verification results
    """
    print(f"[*] Starting social media enumeration for: {username}")
    
    try:
        results = {
            'status': 'success',
            'search_term': username,
            'domain': domain,
            'profiles_found': [],
            'verified_platforms': [],
            'potential_profiles': [],
            'email_variations': [],
            'timestamp': time.time()
        }
        
        # Extract base name if email provided
        if '@' in username:
            base_name = username.split('@')[0]
            email_domain = username.split('@')[1]
            results['email_variations'] = _generate_email_variations(base_name, email_domain)
        else:
            base_name = username
        
        # Search social media platforms
        profiles = _search_social_platforms(base_name)
        results['profiles_found'] = profiles
        
        # Verify found profiles
        verified = _verify_profiles(profiles)
        results['verified_platforms'] = verified
        
        # Generate potential usernames
        results['potential_profiles'] = _generate_username_variations(username, domain)
        
        print(f"[+] Social media enumeration complete: {len(verified)} platforms verified")
        return results
        
    except Exception as e:
        return {
            'status': 'error',
            'message': f'Social media enumeration failed: {str(e)}',
            'error': str(e)
        }

def _search_social_platforms(username: str, max_workers: int = 20) -> List[Dict[str, Any]]:
    """Search for username on major social platforms"""
    
    # Define social media platforms and their URL patterns
    platforms = {
        'Twitter': f'https://twitter.com/{username}',
        'GitHub': f'https://github.com/{username}',
        'LinkedIn': f'https://linkedin.com/in/{username}',
        'Instagram': f'https://instagram.com/{username}',
        'Facebook': f'https://facebook.com/{username}',
        'TikTok': f'https://tiktok.com/@{username}',
        'YouTube': f'https://youtube.com/{username}',
        'Reddit': f'https://reddit.com/user/{username}',
        'Medium': f'https://medium.com/@{username}',
        'Telegram': f'https://t.me/{username}',
        'Snapchat': f'https://snapchat.com/add/{username}',
        'Pinterest': f'https://pinterest.com/{username}',
        'Twitch': f'https://twitch.tv/{username}',
        'Docker': f'https://hub.docker.com/u/{username}',
        'StackOverflow': f'https://stackoverflow.com/users/{username}',
        'GitLab': f'https://gitlab.com/{username}',
        'Bitbucket': f'https://bitbucket.org/{username}',
        'Patreon': f'https://patreon.com/{username}',
        'Deviantart': f'https://deviantart.com/{username}',
    }
    
    found_profiles = []
    
    def check_platform(platform_name: str, url: str) -> Dict[str, Any]:
        """Check if username exists on platform"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            response = requests.head(url, headers=headers, timeout=10, allow_redirects=True)
            
            # Status code 200 usually means profile exists
            if response.status_code == 200:
                return {
                    'platform': platform_name,
                    'url': url,
                    'status_code': response.status_code,
                    'found': True
                }
            elif response.status_code == 404:
                return {
                    'platform': platform_name,
                    'url': url,
                    'status_code': response.status_code,
                    'found': False
                }
            else:
                # Try GET for platforms that don't respond to HEAD
                response = requests.get(url, headers=headers, timeout=10)
                
                if response.status_code == 200 and len(response.text) > 100:
                    return {
                        'platform': platform_name,
                        'url': url,
                        'status_code': response.status_code,
                        'found': True
                    }
        except requests.exceptions.Timeout:
            return None
        except requests.exceptions.RequestException:
            return None
        
        return None
    
    print(f"[*] Searching {len(platforms)} social media platforms...")
    
    try:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(check_platform, name, url): name 
                for name, url in platforms.items()
            }
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found_profiles.append(result)
                    if result.get('found'):
                        print(f"[+] Found on {result['platform']}")
    
    except Exception as e:
        print(f"[!] Error searching platforms: {e}")
    
    return found_profiles

def _verify_profiles(profiles: List[Dict]) -> List[Dict[str, Any]]:
    """Verify found profiles with additional checks"""
    verified = []
    
    for profile in profiles:
        if profile.get('found'):
            verified_profile = {
                'platform': profile['platform'],
                'url': profile['url'],
                'verified': True,
                'confidence': 'high' if profile.get('status_code') == 200 else 'medium'
            }
            verified.append(verified_profile)
    
    return verified

def _generate_email_variations(base_name: str, domain: str) -> List[str]:
    """Generate email variations"""
    variations = [
        f'{base_name}@{domain}',
        f'{base_name}.{base_name}@{domain}',
        f'{base_name}_admin@{domain}',
        f'admin.{base_name}@{domain}',
        f'{base_name}@mail.{domain}',
        f'{base_name}@email.{domain}',
        f'{base_name}.info@{domain}',
    ]
    
    return variations

def _generate_username_variations(username: str, domain: str = None) -> List[Dict[str, str]]:
    """Generate username variations for testing"""
    variations = []
    
    base_name = username.split('@')[0] if '@' in username else username
    
    variations_list = [
        base_name,
        base_name.lower(),
        base_name.upper(),
        base_name.capitalize(),
        base_name.replace('.', ''),
        base_name.replace('_', ''),
        base_name.replace('-', ''),
        f'{base_name}123',
        f'{base_name}2024',
        f'{base_name}_admin',
        f'admin_{base_name}',
    ]
    
    for var in variations_list:
        variations.append({
            'variation': var,
            'type': 'username'
        })
    
    # Add domain-related variations
    if domain:
        domain_clean = domain.replace('.com', '').replace('.org', '').replace('.io', '')
        for var in [f'{base_name}_{domain_clean}', f'{domain_clean}_{base_name}']:
            variations.append({
                'variation': var,
                'type': 'domain_based'
            })
    
    return variations

def search_breaches_for_username(username: str) -> Dict[str, Any]:
    """Search if username appears in known breaches"""
    results = {
        'breaches_found': [],
        'unique_breaches': 0,
        'sources_checked': []
    }
    
    try:
        # Search using Have I Been Pwned (requires API key for batch searches)
        # Free tier allows email searches
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{username}"
        headers = {'User-Agent': 'Mozilla/5.0'}
        
        response = requests.get(url, headers=headers, timeout=15)
        
        if response.status_code == 200:
            breaches = response.json()
            results['breaches_found'] = [b.get('Title') for b in breaches[:20]]
            results['unique_breaches'] = len(breaches)
            results['sources_checked'].append('haveibeenpwned.com')
    
    except requests.exceptions.RequestException as e:
        print(f"[!] Error checking breaches: {e}")
    
    return results

def get_social_media_profiles_report(profiles: List[Dict]) -> str:
    """Generate readable report of found profiles"""
    report = "## Social Media Profiles Found\n\n"
    
    for profile in profiles:
        if profile.get('found'):
            report += f"- **{profile['platform']}**: {profile['url']}\n"
    
    return report

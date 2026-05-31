"""
SSL/TLS Certificate Analysis & Transparency Log Searching
Analyzes certificate details, validity, issuer information
Uses free services like crt.sh and SSL Labs
"""

import socket
import ssl
import requests
import json
from datetime import datetime
from typing import Dict, List, Any
import time
from urllib.parse import urlparse

def certificate_analysis_free(target: str) -> Dict[str, Any]:
    """
    Analyze SSL/TLS certificate and search certificate transparency logs
    
    Args:
        target: Domain or URL to analyze
    
    Returns:
        Dict with certificate details and transparency log results
    """
    print(f"[*] Starting certificate analysis for: {target}")
    
    try:
        # Normalize target
        target = target.strip().lower()
        if target.startswith('http'):
            target = urlparse(target).netloc.replace('www.', '')
        
        results = {
            'status': 'success',
            'target': target,
            'certificate': None,
            'certificate_chain': [],
            'transparency_logs': [],
            'subdomains_from_certs': [],
            'issues': [],
            'intelligence': {},
            'timestamp': time.time()
        }
        
        # 1. Fetch SSL certificate
        cert_data = _get_ssl_certificate(target)
        if cert_data:
            results['certificate'] = cert_data
        else:
            results['issues'].append('Failed to retrieve SSL certificate')
        
        # 2. Get certificate chain
        chain = _get_certificate_chain(target)
        results['certificate_chain'] = chain
        
        # 3. Search Certificate Transparency logs
        ct_results = _search_certificate_transparency(target)
        results['transparency_logs'] = ct_results['certificates']
        results['subdomains_from_certs'] = ct_results['unique_subdomains']
        
        # 4. Check certificate validity
        if results['certificate']:
            results['intelligence'] = _analyze_certificate_intel(results['certificate'])
        
        # 5. Check for certificate issues
        issues = _check_certificate_issues(results)
        results['issues'].extend(issues)
        
        print(f"[+] Certificate analysis complete: {len(results['transparency_logs'])} CT log entries found")
        return results
        
    except Exception as e:
        return {
            'status': 'error',
            'message': f'Certificate analysis failed: {str(e)}',
            'error': str(e)
        }

def _get_ssl_certificate(target: str) -> Dict[str, Any]:
    """Retrieve SSL certificate details"""
    try:
        # Determine port
        if ':' in target:
            host, port = target.split(':')
            port = int(port)
        else:
            host = target
            port = 443
        
        # Create SSL context
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        # Connect and get certificate
        with socket.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                cert_pem = ssl.DER_cert_to_PEM_cert(cert_der)
        
        # Parse certificate
        cert_dict = ssl.DER_cert_to_PEM_cert(cert_der)
        
        # Use OpenSSL to parse (or extract from dict)
        from ssl import DER_cert_to_PEM_cert
        import re
        
        cert_info = _parse_cert_details(cert_pem)
        return cert_info
        
    except Exception as e:
        print(f"[!] Error fetching SSL certificate: {e}")
        return None

def _parse_cert_details(cert_pem: str) -> Dict[str, Any]:
    """Parse SSL certificate PEM to extract details"""
    try:
        cert_details = {
            'pem': cert_pem[:100] + '...' if len(cert_pem) > 100 else cert_pem,
            'info': {}
        }
        
        # Try to extract details using simple regex
        # This is a simplified extraction - full parsing would need cryptography library
        
        # Subject
        if 'Subject:' in cert_pem:
            subject_match = re.search(r'Subject:.*', cert_pem)
            if subject_match:
                cert_details['info']['subject'] = subject_match.group(0)
        
        # Issuer
        if 'Issuer:' in cert_pem:
            issuer_match = re.search(r'Issuer:.*', cert_pem)
            if issuer_match:
                cert_details['info']['issuer'] = issuer_match.group(0)
        
        # Validity dates
        if 'Not Before:' in cert_pem:
            not_before = re.search(r'Not Before:\\s*([^\\n]+)', cert_pem)
            if not_before:
                cert_details['info']['valid_from'] = not_before.group(1)
        
        if 'Not After' in cert_pem:
            not_after = re.search(r'Not After\\s*:\\s*([^\\n]+)', cert_pem)
            if not_after:
                cert_details['info']['valid_until'] = not_after.group(1)
        
        return cert_details
        
    except Exception as e:
        print(f"[!] Error parsing certificate: {e}")
        return {'error': str(e)}

def _get_certificate_chain(target: str) -> List[Dict[str, str]]:
    """Get full certificate chain"""
    chain = []
    try:
        if ':' in target:
            host, port = target.split(':')
            port = int(port)
        else:
            host = target
            port = 443
        
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                # Get certificate list
                cert_chain = ssock.getpeercert_chain()
                
                for i, cert in enumerate(cert_chain or []):
                    chain.append({
                        'position': i,
                        'subject': str(cert.get('subject', 'Unknown'))[:100]
                    })
    except Exception as e:
        print(f"[!] Error getting certificate chain: {e}")
    
    return chain

def _search_certificate_transparency(target: str) -> Dict[str, Any]:
    """Search certificate transparency logs via crt.sh"""
    try:
        results = {
            'certificates': [],
            'unique_subdomains': []
        }
        
        # crt.sh API endpoint
        url = f"https://crt.sh/json?q={target}"
        
        response = requests.get(url, timeout=20)
        response.raise_for_status()
        
        certs = response.json()
        
        subdomains = set()
        
        for cert in certs[:50]:  # Limit to 50 certificates
            cert_info = {
                'id': cert.get('id'),
                'logged_at': cert.get('logged_at', '')[:10],
                'common_name': cert.get('common_name', 'Unknown'),
                'name_value': cert.get('name_value', ''),
                'issuer': cert.get('issuer_name', 'Unknown')[:50]
            }
            
            results['certificates'].append(cert_info)
            
            # Extract subdomains from name_value
            names = cert.get('name_value', '').split('\n')
            for name in names:
                name = name.strip().lower()
                if name and (target in name or name.endswith(target)):
                    subdomains.add(name)
        
        results['unique_subdomains'] = list(subdomains)[:50]
        
        return results
        
    except Exception as e:
        print(f"[!] Error searching CT logs: {e}")
        return {'certificates': [], 'unique_subdomains': []}

def _analyze_certificate_intel(cert_data: Dict[str, Any]) -> Dict[str, Any]:
    """Analyze certificate for intelligence"""
    intel = {
        'certificate_authority': 'Unknown',
        'certificate_type': 'Unknown',
        'is_expired': False,
        'validity_period': 'Unknown',
        'has_san': False,
        'self_signed': False
    }
    
    try:
        cert_info = cert_data.get('info', {})
        
        # Check if self-signed
        subject = cert_info.get('subject', '')
        issuer = cert_info.get('issuer', '')
        if subject == issuer:
            intel['self_signed'] = True
        
        # Extract CA
        if issuer:
            if 'Let' in issuer and 'Encrypt' in issuer:
                intel['certificate_authority'] = "Let's Encrypt"
            elif 'DigiCert' in issuer:
                intel['certificate_authority'] = 'DigiCert'
            elif 'Comodo' in issuer:
                intel['certificate_authority'] = 'Comodo'
            elif 'GlobalSign' in issuer:
                intel['certificate_authority'] = 'GlobalSign'
            else:
                intel['certificate_authority'] = issuer[:50]
        
        # Check validity
        valid_from = cert_info.get('valid_from', '')
        valid_until = cert_info.get('valid_until', '')
        
        if valid_from and valid_until:
            intel['validity_period'] = f'{valid_from} to {valid_until}'
    
    except Exception as e:
        print(f"[!] Error analyzing certificate: {e}")
    
    return intel

def _check_certificate_issues(results: Dict[str, Any]) -> List[str]:
    """Check for certificate-related security issues"""
    issues = []
    
    try:
        cert = results.get('certificate', {})
        intel = results.get('intelligence', {})
        
        if intel.get('self_signed'):
            issues.append('Certificate is self-signed (unusual for production)')
        
        if not results.get('certificate_chain') or len(results['certificate_chain']) < 2:
            issues.append('Incomplete certificate chain detected')
        
        # Check for wildcard certificates
        if results.get('certificate'):
            if '*.{' in str(results['certificate']):
                issues.append('Wildcard certificate detected')
    
    except Exception as e:
        print(f"[!] Error checking issues: {e}")
    
    return issues

import re  # Add this at the top if not present

"""
Advanced DNS Enumeration Module
DNS brute-force, zone transfers, subdomain enumeration
Uses free public DNS resolvers and techniques
"""

import socket
import requests
import dns.resolver
import dns.zone
import dns.rdatatype
from typing import Dict, List, Set, Any
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

def dns_enum_advanced(target: str, bruteforce: bool = True, zone_transfer: bool = True) -> Dict[str, Any]:
    """
    Advanced DNS enumeration: records, subdomains, zone transfers
    
    Args:
        target: Domain to enumerate
        bruteforce: Enable DNS brute-force (slower but comprehensive)
        zone_transfer: Attempt zone transfers
    
    Returns:
        Dict with DNS records, subdomains, and zone transfer results
    """
    print(f"[*] Starting advanced DNS enumeration for: {target}")
    
    try:
        target = target.strip().lower()
        
        results = {
            'status': 'success',
            'target': target,
            'dns_records': {},
            'subdomains': [],
            'zone_transfer': None,
            'nameservers': [],
            'mx_servers': [],
            'intelligence': {},
            'timestamp': time.time()
        }
        
        # 1. Get nameservers
        results['nameservers'] = _get_nameservers(target)
        
        # 2. Enumerate standard DNS records
        results['dns_records'] = _enumerate_dns_records(target)
        
        # 3. Get MX servers
        results['mx_servers'] = _get_mx_records(target)
        
        # 4. Attempt zone transfer
        if zone_transfer and results['nameservers']:
            for ns in results['nameservers'][:3]:  # Try first 3 nameservers
                zt_result = _attempt_zone_transfer(target, ns)
                if zt_result['success']:
                    results['zone_transfer'] = zt_result
                    break
            
            if not results['zone_transfer']:
                results['zone_transfer'] = {'success': False, 'message': 'Zone transfer not allowed'}
        
        # 5. DNS brute-force subdomains
        if bruteforce:
            results['subdomains'] = _bruteforce_subdomains(target)
        
        # 6. Generate intelligence
        results['intelligence'] = _analyze_dns_intel(results)
        
        print(f"[+] DNS enumeration complete: {len(results['subdomains'])} subdomains found")
        return results
        
    except Exception as e:
        return {
            'status': 'error',
            'message': f'DNS enumeration failed: {str(e)}',
            'error': str(e)
        }

def _get_nameservers(domain: str) -> List[str]:
    """Get nameservers for domain"""
    try:
        nameservers = []
        # Use Google's public DNS as resolver
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8', '8.8.4.4']  # Google DNS
        
        ns_records = resolver.resolve(domain, 'NS')
        for ns in ns_records:
            nameservers.append(str(ns).rstrip('.'))
        
        return nameservers
    except Exception as e:
        print(f"[!] Error fetching nameservers: {e}")
        return []

def _enumerate_dns_records(domain: str) -> Dict[str, Any]:
    """Enumerate common DNS record types"""
    records = {
        'A': [],
        'AAAA': [],
        'MX': [],
        'TXT': [],
        'NS': [],
        'CNAME': [],
        'SOA': [],
        'SRV': []
    }
    
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8', '8.8.4.4']
        
        record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'SRV']
        
        for record_type in record_types:
            try:
                query = resolver.resolve(domain, record_type)
                for record in query:
                    records[record_type].append(str(record).rstrip('.'))
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                pass
            except Exception:
                pass
    
    except Exception as e:
        print(f"[!] Error in DNS records enumeration: {e}")
    
    return records

def _get_mx_records(domain: str) -> List[Dict[str, Any]]:
    """Get MX records and mail server information"""
    mx_records = []
    
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8', '8.8.4.4']
        
        mx_answer = resolver.resolve(domain, 'MX')
        
        for mx in mx_answer:
            mx_host = str(mx.exchange).rstrip('.')
            priority = mx.preference
            
            # Try to get A record for MX host
            try:
                a_records = resolver.resolve(mx_host, 'A')
                ips = [str(rr) for rr in a_records]
            except:
                ips = []
            
            mx_records.append({
                'priority': priority,
                'host': mx_host,
                'ips': ips
            })
    
    except Exception as e:
        print(f"[!] Error fetching MX records: {e}")
    
    return sorted(mx_records, key=lambda x: x['priority'])

def _attempt_zone_transfer(domain: str, nameserver: str) -> Dict[str, Any]:
    """Attempt AXFR (zone transfer)"""
    try:
        # Resolve nameserver to IP
        try:
            ns_ip = socket.gethostbyname(nameserver)
        except:
            ns_ip = nameserver
        
        # Attempt zone transfer
        zone_records = {}
        zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain))
        
        for name, node in zone.items():
            zone_records[str(name)] = []
            for rdataset in node:
                zone_records[str(name)].append({
                    'type': str(rdataset.rdtype),
                    'data': [str(rr) for rr in rdataset]
                })
        
        return {
            'success': True,
            'nameserver': nameserver,
            'records_count': len(zone_records),
            'sample_records': list(zone_records.keys())[:20]
        }
    
    except Exception as e:
        return {
            'success': False,
            'message': f'Zone transfer failed: {str(e)}'
        }

def _bruteforce_subdomains(domain: str, max_workers: int = 20) -> List[Dict[str, Any]]:
    """Brute-force common subdomains"""
    
    # Common subdomain wordlist
    common_subdomains = [
        'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns',
        'admin', 'test', 'api', 'dev', 'staging', 'beta', 'demo', 'blog',
        'shop', 'cdn', 'gateway', 'proxy', 'backup', 'database', 'dns',
        'server', 'host', 'mail2', 'mail3', 'mail4', 'web', 'app', 'apps',
        'auth', 'secure', 'vpn', 'git', 'jenkins', 'docker', 'k8s',
        'kubernetes', 'elastic', 'monitoring', 'logs', 'grafana', 'prometheus',
        'api-v1', 'api-v2', 'graphql', 'rest', 'websocket', 'socket',
        'assets', 'static', 'media', 'uploads', 'downloads', 'files',
        'images', 'videos', 'documents', 'archive', 'backup', 'legacy',
        'old', 'new', 'temp', 'testing', 'stage', 'prod', 'production',
    ]
    
    found_subdomains = []
    
    def resolve_subdomain(subdomain: str) -> Dict[str, Any]:
        """Try to resolve a subdomain"""
        try:
            full_domain = f"{subdomain}.{domain}"
            resolver = dns.resolver.Resolver()
            resolver.nameservers = ['8.8.8.8', '8.8.4.4']
            resolver.lifetime = 5
            
            answer = resolver.resolve(full_domain, 'A')
            ips = [str(rr) for rr in answer]
            
            return {
                'subdomain': full_domain,
                'ips': ips,
                'found': True
            }
        except:
            return None
    
    try:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(resolve_subdomain, sub): sub for sub in common_subdomains}
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found_subdomains.append(result)
                    print(f"[+] Found subdomain: {result['subdomain']}")
    
    except Exception as e:
        print(f"[!] Error during subdomain brute-force: {e}")
    
    return found_subdomains

def _analyze_dns_intel(dns_data: Dict[str, Any]) -> Dict[str, Any]:
    """Analyze DNS data for intelligence"""
    intel = {
        'mail_provider': 'Unknown',
        'has_spf': False,
        'has_dmarc': False,
        'has_dkim': False,
        'name_servers_count': len(dns_data['nameservers']),
        'mx_servers_count': len(dns_data['mx_servers']),
        'subdomains_count': len(dns_data['subdomains']),
        'zone_transfer_allowed': False
    }
    
    # Check TXT records for SPF, DMARC
    txt_records = dns_data['dns_records'].get('TXT', [])
    for txt in txt_records:
        if 'v=spf1' in txt:
            intel['has_spf'] = True
        if 'v=DMARC1' in txt:
            intel['has_dmarc'] = True
        if 'DKIM' in txt or 'k=rsa' in txt:
            intel['has_dkim'] = True
    
    # Check zone transfer
    if dns_data['zone_transfer'] and dns_data['zone_transfer'].get('success'):
        intel['zone_transfer_allowed'] = True
    
    # Determine mail provider
    if dns_data['mx_servers']:
        mx_host = dns_data['mx_servers'][0]['host'].lower()
        if 'google' in mx_host:
            intel['mail_provider'] = 'Google Workspace'
        elif 'microsoft' in mx_host or 'outlook' in mx_host:
            intel['mail_provider'] = 'Microsoft 365'
        elif 'protonmail' in mx_host:
            intel['mail_provider'] = 'ProtonMail'
        elif 'zoho' in mx_host:
            intel['mail_provider'] = 'Zoho'
        else:
            intel['mail_provider'] = 'Self-hosted/Other'
    
    return intel

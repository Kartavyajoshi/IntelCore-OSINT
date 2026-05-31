"""
IP Intelligence & Geolocation Module
IP geolocation, ASN information, reputation scoring
Uses free services like IP-API, MaxMind GeoIP (free), AbuseIPDB
"""

import requests
import socket
from typing import Dict, List, Any
import time

def ip_intelligence_free(target: str) -> Dict[str, Any]:
    """
    Get intelligence on IP address or domain
    
    Args:
        target: IP address or domain to analyze
    
    Returns:
        Dict with geolocation, ASN, reputation, and threat info
    """
    print(f"[*] Starting IP intelligence analysis for: {target}")
    
    try:
        # Resolve to IP if domain provided
        if not _is_valid_ip(target):
            try:
                ip_address = socket.gethostbyname(target)
                print(f"[*] Resolved {target} to {ip_address}")
            except socket.gaierror:
                return {
                    'status': 'error',
                    'message': f'Could not resolve {target} to IP'
                }
        else:
            ip_address = target
        
        results = {
            'status': 'success',
            'target': target,
            'ip_address': ip_address,
            'geolocation': None,
            'asn_info': None,
            'reputation': None,
            'threat_intelligence': None,
            'whois_info': None,
            'intelligence': {},
            'timestamp': time.time()
        }
        
        # 1. Get geolocation
        results['geolocation'] = _get_geolocation(ip_address)
        
        # 2. Get ASN info
        results['asn_info'] = _get_asn_info(ip_address)
        
        # 3. Check reputation from multiple sources
        results['reputation'] = _check_ip_reputation(ip_address)
        
        # 4. Threat intelligence
        results['threat_intelligence'] = _get_threat_intel(ip_address)
        
        # 5. WHOIS info
        results['whois_info'] = _get_whois_info(ip_address)
        
        # 6. Generate intelligence summary
        results['intelligence'] = _analyze_ip_intel(results)
        
        print(f"[+] IP intelligence analysis complete")
        return results
        
    except Exception as e:
        return {
            'status': 'error',
            'message': f'IP intelligence analysis failed: {str(e)}',
            'error': str(e)
        }

def _is_valid_ip(target: str) -> bool:
    """Check if target is valid IP address"""
    parts = target.split('.')
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(part) < 256 for part in parts)
    except ValueError:
        return False

def _get_geolocation(ip: str) -> Dict[str, Any]:
    """Get geolocation data for IP"""
    geolocation = {
        'country': None,
        'country_code': None,
        'city': None,
        'latitude': None,
        'longitude': None,
        'timezone': None,
        'isp': None,
        'source': None
    }
    
    try:
        # Use IP-API (free tier available)
        url = f"http://ip-api.com/json/{ip}"
        response = requests.get(url, timeout=15)
        
        if response.status_code == 200:
            data = response.json()
            
            if data.get('status') == 'success':
                geolocation['country'] = data.get('country')
                geolocation['country_code'] = data.get('countryCode')
                geolocation['city'] = data.get('city')
                geolocation['latitude'] = data.get('lat')
                geolocation['longitude'] = data.get('lon')
                geolocation['timezone'] = data.get('timezone')
                geolocation['isp'] = data.get('isp')
                geolocation['source'] = 'ip-api.com'
                
                return geolocation
    except:
        pass
    
    # Fallback to ipinfo.io
    try:
        url = f"https://ipinfo.io/{ip}/json"
        response = requests.get(url, timeout=15)
        
        if response.status_code == 200:
            data = response.json()
            
            geolocation['country_code'] = data.get('country')
            geolocation['city'] = data.get('city')
            geolocation['timezone'] = data.get('timezone')
            geolocation['isp'] = data.get('org')
            geolocation['source'] = 'ipinfo.io'
            
            # Parse coordinates
            if 'loc' in data:
                coords = data['loc'].split(',')
                if len(coords) == 2:
                    geolocation['latitude'] = float(coords[0])
                    geolocation['longitude'] = float(coords[1])
            
            return geolocation
    except:
        pass
    
    return geolocation

def _get_asn_info(ip: str) -> Dict[str, Any]:
    """Get ASN and routing information"""
    asn_info = {
        'asn': None,
        'asn_name': None,
        'prefix': None,
        'source': None
    }
    
    try:
        # Use ASN lookup service
        url = f"https://api.asnlookup.com/api/asn/{ip}"
        response = requests.get(url, timeout=15)
        
        if response.status_code == 200:
            data = response.json()
            
            if 'results' in data and data['results']:
                result = data['results'][0]
                asn_info['asn'] = result.get('asn')
                asn_info['asn_name'] = result.get('asn_name')
                asn_info['prefix'] = result.get('prefix')
                asn_info['source'] = 'asnlookup.com'
                
                return asn_info
    except:
        pass
    
    # Fallback to whois lookups
    try:
        url = f"https://whois.arin.net/rest/ip/{ip}"
        response = requests.get(url, timeout=15, headers={'Accept': 'application/json'})
        
        if response.status_code == 200:
            data = response.json()
            # Parse ARIN response (format may vary)
            asn_info['source'] = 'arin.net'
            
            return asn_info
    except:
        pass
    
    return asn_info

def _check_ip_reputation(ip: str) -> Dict[str, Any]:
    """Check IP reputation from multiple sources"""
    reputation = {
        'is_blacklisted': False,
        'is_proxy': False,
        'is_vpn': False,
        'is_datacenter': False,
        'threat_level': 'unknown',
        'abuse_reports': 0,
        'sources': []
    }
    
    # Check AbuseIPDB
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        params = {
            'ipAddress': ip,
            'maxAgeInDays': 90
        }
        headers = {'Accept': 'application/json'}
        
        response = requests.get(url, params=params, headers=headers, timeout=15)
        
        if response.status_code == 200:
            data = response.json()
            
            if 'data' in data:
                abuse_data = data['data']
                reputation['abuse_reports'] = abuse_data.get('totalReports', 0)
                reputation['threat_level'] = 'high' if reputation['abuse_reports'] > 10 else 'medium' if reputation['abuse_reports'] > 0 else 'low'
                reputation['sources'].append('abuseipdb.com')
                
                if reputation['abuse_reports'] > 0:
                    reputation['is_blacklisted'] = True
    except:
        pass
    
    # Check for proxy/VPN
    try:
        url = f"https://proxycheck.akamai.com/v2/{ip}"
        response = requests.get(url, timeout=15)
        
        if response.status_code == 200:
            data = response.json()
            
            if str(ip) in data:
                ip_data = data[str(ip)]
                if ip_data.get('proxy') == 'yes':
                    reputation['is_proxy'] = True
                if ip_data.get('threat') == 'yes':
                    reputation['is_blacklisted'] = True
                
                reputation['sources'].append('proxycheck.akamai.com')
    except:
        pass
    
    return reputation

def _get_threat_intel(ip: str) -> Dict[str, Any]:
    """Get threat intelligence for IP"""
    threat = {
        'malware_detected': False,
        'c2_associated': False,
        'known_botnet': False,
        'ransomware_associated': False,
        'indicators': [],
        'sources': []
    }
    
    try:
        # Check Against VirusTotal (if cached or from free sources)
        # This would need API key, so we skip for now
        # threat['sources'].append('virustotal.com')
        pass
    except:
        pass
    
    return threat

def _get_whois_info(ip: str) -> Dict[str, Any]:
    """Get WHOIS information for IP"""
    whois_info = {
        'asn': None,
        'description': None,
        'organization': None,
        'country': None,
        'changed': None
    }
    
    try:
        # Query WHOIS via REST API
        url = f"https://rest.db.ripe.net/lookup/ip/{ip}"
        response = requests.get(url, timeout=15, headers={'Accept': 'application/json'})
        
        if response.status_code == 200:
            data = response.json()
            
            if 'objects' in data:
                for obj in data['objects'].get('object', []):
                    attrs = obj.get('attributes', {}).get('attribute', [])
                    
                    for attr in attrs:
                        if attr.get('name') == 'as-num' or attr.get('name') == 'origin':
                            whois_info['asn'] = attr.get('value')
                        elif attr.get('name') == 'descr':
                            whois_info['description'] = attr.get('value')
                        elif attr.get('name') == 'org-name':
                            whois_info['organization'] = attr.get('value')
            
            return whois_info
    except:
        pass
    
    return whois_info

def _analyze_ip_intel(results: Dict[str, Any]) -> Dict[str, Any]:
    """Generate intelligence summary"""
    intel = {
        'risk_level': 'unknown',
        'location_known': False,
        'suspicious_indicators': 0,
        'recommendations': []
    }
    
    try:
        geo = results.get('geolocation', {})
        rep = results.get('reputation', {})
        threat = results.get('threat_intelligence', {})
        
        if geo and geo.get('country'):
            intel['location_known'] = True
        
        # Calculate risk level
        risk_score = 0
        
        if rep.get('is_blacklisted'):
            risk_score += 30
            intel['recommendations'].append('IP is on abuse/blacklist databases')
        
        if rep.get('is_proxy') or rep.get('is_vpn'):
            risk_score += 10
            intel['recommendations'].append('IP is associated with proxy/VPN services')
        
        if rep.get('abuse_reports', 0) > 10:
            risk_score += 20
            intel['recommendations'].append('Multiple abuse reports against this IP')
        
        if threat.get('malware_detected'):
            risk_score += 40
            intel['recommendations'].append('Malware detected')
        
        if threat.get('c2_associated'):
            risk_score += 50
            intel['recommendations'].append('Associated with C2 infrastructure')
        
        if risk_score >= 50:
            intel['risk_level'] = 'high'
        elif risk_score >= 20:
            intel['risk_level'] = 'medium'
        elif risk_score > 0:
            intel['risk_level'] = 'low'
        else:
            intel['risk_level'] = 'none'
        
        intel['suspicious_indicators'] = risk_score // 10
    
    except Exception as e:
        print(f"[!] Error analyzing IP intel: {e}")
    
    return intel

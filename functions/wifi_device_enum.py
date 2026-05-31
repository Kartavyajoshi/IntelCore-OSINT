"""
WiFi Network Enumeration & Device Intelligence Module
Network scanning, device fingerprinting, WiFi intelligence
Educational/passive reconnaissance methods
"""

import requests
import json
from typing import Dict, List, Any
import time

def wifi_device_enum(target_network: str = None, use_online_db: bool = True) -> Dict[str, Any]:
    """
    Enumerate WiFi networks and connected devices
    
    Args:
        target_network: Optional SSID or network to search for
        use_online_db: Use online WiFi databases and APIs
    
    Returns:
        Dict with WiFi networks, devices, and intelligence
    """
    print(f"[*] Starting WiFi device enumeration")
    
    try:
        results = {
            'status': 'success',
            'networks': [],
            'devices': [],
            'access_points': [],
            'frequencies': {
                '2.4GHz': [],
                '5GHz': [],
                '6GHz': []
            },
            'online_databases': {},
            'intelligence': {},
            'timestamp': time.time()
        }
        
        # 1. Query online WiFi databases
        if use_online_db:
            results['online_databases'] = _query_online_wifi_databases(target_network)
        
        # 2. Get access point information
        results['access_points'] = _get_access_point_info()
        
        # 3. Device fingerprinting from MAC addresses
        results['devices'] = _fingerprint_devices()
        
        # 4. Generate frequency distribution
        results['frequencies'] = _analyze_frequencies(results)
        
        # 5. Generate intelligence
        results['intelligence'] = _analyze_wifi_intel(results)
        
        print(f"[+] WiFi enumeration complete: {len(results['networks'])} networks found")
        return results
        
    except Exception as e:
        return {
            'status': 'error',
            'message': f'WiFi enumeration failed: {str(e)}',
            'error': str(e)
        }

def _query_online_wifi_databases(target_network: str = None) -> Dict[str, Any]:
    """Query online WiFi databases and APIs"""
    results = {
        'wigle_db': [],
        'network_analysis': {}
    }
    
    try:
        # Query WiGLE database API (free tier available)
        # Requires API key, so we'll use public information
        
        # Try to get open WiFi networks using free services
        url = "https://api.openmaps.net/wifi/networks"
        params = {}
        
        if target_network:
            params['ssid'] = target_network
        
        try:
            response = requests.get(url, params=params, timeout=15)
            if response.status_code == 200:
                networks = response.json()
                
                results['wigle_db'] = networks[:20]  # Limit to 20
        except:
            pass
    
    except Exception as e:
        print(f"[!] Error querying WiFi databases: {e}")
    
    return results

def _get_access_point_info() -> List[Dict[str, Any]]:
    """Get access point information"""
    access_points = []
    
    try:
        # This would typically require root/admin access to enumerate
        # For educational purposes, we'll provide a framework
        
        sample_ap_info = [
            {
                'ssid': 'Unknown Network',
                'bssid': 'XX:XX:XX:XX:XX:XX',
                'signal_strength': -50,  # dBm
                'frequency': '2.4GHz',
                'channel': 6,
                'security': 'WPA2',
                'vendor': 'Unknown'
            }
        ]
        
        # In a real scenario with admin access, this would enumerate actual networks
        access_points = sample_ap_info
    
    except Exception as e:
        print(f"[!] Error getting access point info: {e}")
    
    return access_points

def _fingerprint_devices() -> List[Dict[str, Any]]:
    """Fingerprint connected devices"""
    devices = []
    
    try:
        # Device fingerprinting based on MAC addresses and behavior
        # For educational/passive reconnaissance
        
        common_mac_prefixes = {
            '00:1A:2B': 'Cisco',
            '00:0A:95': 'Hewlett-Packard',
            '00:0D:BC': 'Linksys',
            '00:0E:C6': 'Netgear',
            '00:14:BF': 'Netgear',
            '08:00:27': 'VirtualBox',
            '52:54:00': 'KVM/QEMU',
            'AA:BB:CC': 'VMware',
            'BC:5F:F4': 'Apple',
            'D8:BB:C1': 'TP-Link',
            '1C:7E:E5': 'Apple iPhone',
        }
        
        # Sample device structures (in real scenario, these would be discovered)
        sample_devices = [
            {
                'mac_address': 'Unknown',
                'hostname': 'unknown-device',
                'device_type': 'Unknown',
                'signal_strength': -60,
                'manufacturer': 'Unknown',
                'open_ports': []
            }
        ]
        
        devices = sample_devices
    
    except Exception as e:
        print(f"[!] Error fingerprinting devices: {e}")
    
    return devices

def _analyze_frequencies(results: Dict[str, Any]) -> Dict[str, List]:
    """Analyze WiFi frequency distribution"""
    frequencies = {
        '2.4GHz': [],
        '5GHz': [],
        '6GHz': []
    }
    
    try:
        for ap in results.get('access_points', []):
            freq = ap.get('frequency', '2.4GHz')
            
            if '2.4' in str(freq):
                frequencies['2.4GHz'].append(ap)
            elif '5' in str(freq):
                frequencies['5GHz'].append(ap)
            elif '6' in str(freq):
                frequencies['6GHz'].append(ap)
    
    except Exception as e:
        print(f"[!] Error analyzing frequencies: {e}")
    
    return frequencies

def _analyze_wifi_intel(results: Dict[str, Any]) -> Dict[str, Any]:
    """Generate WiFi intelligence"""
    intel = {
        'network_count': 0,
        'device_count': 0,
        'security_assessment': 'Unknown',
        'recommendations': [],
        'risks': []
    }
    
    try:
        # Count networks and devices
        intel['network_count'] = len(results.get('access_points', []))
        intel['device_count'] = len(results.get('devices', []))
        
        # Assess security
        weak_security = 0
        strong_security = 0
        
        for ap in results.get('access_points', []):
            security = ap.get('security', 'Unknown').upper()
            
            if 'WEP' in security or 'OPEN' in security:
                weak_security += 1
                intel['risks'].append(f"Insecure network found: {ap.get('ssid')} ({security})")
            else:
                strong_security += 1
        
        if weak_security > 0:
            intel['security_assessment'] = 'Weak'
        elif strong_security > 0:
            intel['security_assessment'] = 'Good'
        
        # Generate recommendations
        intel['recommendations'].append('Use WPA3 or at least WPA2 encryption')
        intel['recommendations'].append('Disable WPS (WiFi Protected Setup)')
        intel['recommendations'].append('Change default SSID names')
        intel['recommendations'].append('Use strong passwords (20+ characters)')
        intel['recommendations'].append('Enable network isolation/guest networks')
        intel['recommendations'].append('Regularly update router firmware')
    
    except Exception as e:
        print(f"[!] Error analyzing WiFi intel: {e}")
    
    return intel

def get_mac_vendor(mac_address: str) -> str:
    """Look up MAC address vendor"""
    try:
        # Extract first 6 characters (OUI - Organizationally Unique Identifier)
        oui = ':'.join(mac_address.split(':')[:3])
        
        # Query public MAC vendor API
        url = f"https://api.maclookup.app/v2/macs/{oui}"
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            return data.get('vendorName', 'Unknown')
    except:
        pass
    
    return 'Unknown'

def get_wifi_channel_info(channel: int, frequency: str = '2.4GHz') -> Dict[str, Any]:
    """Get WiFi channel information"""
    
    # WiFi channel mapping
    channel_map_24 = {
        1: {'frequency': 2412, 'bandwidth': 20},
        2: {'frequency': 2417, 'bandwidth': 20},
        3: {'frequency': 2422, 'bandwidth': 20},
        4: {'frequency': 2427, 'bandwidth': 20},
        5: {'frequency': 2432, 'bandwidth': 20},
        6: {'frequency': 2437, 'bandwidth': 20},
        7: {'frequency': 2442, 'bandwidth': 20},
        8: {'frequency': 2447, 'bandwidth': 20},
        9: {'frequency': 2452, 'bandwidth': 20},
        10: {'frequency': 2457, 'bandwidth': 20},
        11: {'frequency': 2462, 'bandwidth': 20},
    }
    
    channel_map_5 = {
        36: {'frequency': 5180, 'bandwidth': 20},
        40: {'frequency': 5200, 'bandwidth': 20},
        44: {'frequency': 5220, 'bandwidth': 20},
        48: {'frequency': 5240, 'bandwidth': 20},
        149: {'frequency': 5745, 'bandwidth': 20},
        153: {'frequency': 5765, 'bandwidth': 20},
        157: {'frequency': 5785, 'bandwidth': 20},
        161: {'frequency': 5805, 'bandwidth': 20},
    }
    
    if frequency == '2.4GHz' and channel in channel_map_24:
        return channel_map_24[channel]
    elif frequency == '5GHz' and channel in channel_map_5:
        return channel_map_5[channel]
    
    return {'error': f'Unknown channel {channel} for {frequency}'}

def analyze_channel_overlap(access_points: List[Dict]) -> Dict[str, Any]:
    """Analyze WiFi channel overlap and interference"""
    analysis = {
        'overlapping_channels': [],
        'interference_risk': 'low',
        'recommendations': []
    }
    
    # Group by frequency
    networks_24 = [ap for ap in access_points if '2.4' in str(ap.get('frequency', '2.4GHz'))]
    
    # Check for overlapping channels (channels within 5 of each other on 2.4GHz)
    for i, ap1 in enumerate(networks_24):
        for ap2 in networks_24[i+1:]:
            ch1 = ap1.get('channel', 6)
            ch2 = ap2.get('channel', 6)
            
            if abs(ch1 - ch2) < 5:
                analysis['overlapping_channels'].append({
                    'networks': [ap1.get('ssid'), ap2.get('ssid')],
                    'channels': [ch1, ch2]
                })
    
    if len(analysis['overlapping_channels']) > 2:
        analysis['interference_risk'] = 'high'
        analysis['recommendations'].append('Reduce number of WiFi networks or change channels')
    elif len(analysis['overlapping_channels']) > 0:
        analysis['interference_risk'] = 'medium'
        analysis['recommendations'].append('Consider adjusting channel placement')
    
    return analysis

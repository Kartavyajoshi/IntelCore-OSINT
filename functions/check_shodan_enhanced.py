import requests
import socket
import re

def get_shodan_profile(target, api_key, include_history=False):
    """
    Retrieves pure OSINT data from Shodan (Ports, Banners, Vulns, Geo, Device ID).
    
    :param target: IP address or Domain name
    :param api_key: Your Shodan API Key
    :param include_history: Boolean. If True, fetches historical data (costs API credits).
    :return: Dictionary containing the 6 key data categories.
    """
    print(f"[*] Fetching Shodan profile for: {target}")

    # 1. RESOLVE TARGET
    target_ip = target
    try:
        if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target):
            target_ip = socket.gethostbyname(target)
    except Exception as e:
        return {'status': 'error', 'message': f"DNS Resolution Failed: {e}"}

    # 2. QUERY SHODAN API
    try:
        # We use the /host/{ip} endpoint which covers all requested fields
        url = f"https://api.shodan.io/shodan/host/{target_ip}?key="
        if include_history:
            url += "&history=true"
            
        r = requests.get(url, timeout=20)
        
        if r.status_code == 404:
            return {'status': 'empty', 'message': 'Target not found in Shodan.'}
        elif r.status_code != 200:
            return {'status': 'error', 'message': f'Shodan API Error: {r.status_code}'}

        data = r.json()

        # 3. PARSE DATA INTO REQUESTED CATEGORIES

        # Category A: Geolocation and Organizational Data
        geo_org_data = {
            'ip': data.get('ip_str'),
            'organization': data.get('org', 'Unknown'),
            'isp': data.get('isp', 'Unknown'),
            'asn': data.get('asn', 'Unknown'),
            'city': data.get('city', 'Unknown'),
            'country': data.get('country_name', 'Unknown'),
            'country_code': data.get('country_code', 'Unknown'),
            'latitude': data.get('latitude'),
            'longitude': data.get('longitude')
        }

        # Category B: Device Identification
        device_id_data = {
            'os': data.get('os', 'Unknown'),
            'hostnames': data.get('hostnames', []),
            'domains': data.get('domains', []),
            'tags': data.get('tags', []),  # e.g. "cloud", "vpn"
            'last_update': data.get('last_update')
        }

        # Categories C & D: Open Ports, Services, & Banners
        # We iterate through the 'data' list once to build these out
        open_ports = []
        banners_metadata = []

        for service in data.get('data', []):
            # 1. Open Ports & Services
            open_ports.append({
                'port': service.get('port'),
                'protocol': service.get('transport'),
                'service_name': service.get('_shodan', {}).get('module', 'unknown')
            })

            # 2. Service Banners & Metadata
            banners_metadata.append({
                'port': service.get('port'),
                'product': service.get('product', 'Unknown'),
                'version': service.get('version', 'Unknown'),
                'cpe': service.get('cpe', []),  # Common Platform Enumeration (Software ID)
                'raw_banner': service.get('data', '').strip()  # The actual text returned by the service
            })

        # Category E: Vulnerability Information
        # Shodan provides a simple list of CVE strings
        vuln_data = data.get('vulns', [])

        # 4. RETURN STRUCTURED DATA
        return {
            'status': 'success',
            'target_ip': target_ip,
            'geolocation_and_organization': geo_org_data,
            'device_identification': device_id_data,
            'open_ports_and_services': open_ports,
            'service_banners_and_metadata': banners_metadata,
            'vulnerability_information': vuln_data,
            'historical_data_available': include_history # Confirmation flag
        }

    except Exception as e:
        return {'status': 'error', 'message': str(e)}


# #----output example----
# {
#   "geolocation_and_organization": {
#     "organization": "Amazon Data Services",
#     "city": "Ashburn",
#     "country": "United States",
#     "asn": "AS14618"
#   },
#   "device_identification": {
#     "os": "Linux 3.x",
#     "hostnames": ["ec2-54-1-1-1.compute-1.amazonaws.com"],
#     "tags": ["cloud"]
#   },
#   "open_ports_and_services": [
#     { "port": 22, "protocol": "tcp", "service_name": "ssh" },
#     { "port": 80, "protocol": "tcp", "service_name": "http" }
#   ],
#   "service_banners_and_metadata": [
#     {
#       "port": 22,
#       "product": "OpenSSH",
#       "version": "7.4",
#       "raw_banner": "SSH-2.0-OpenSSH_7.4"
#     }
#   ],
#   "vulnerability_information": [
#     "CVE-2018-15473",
#     "CVE-2016-10009"
#   ]
# }
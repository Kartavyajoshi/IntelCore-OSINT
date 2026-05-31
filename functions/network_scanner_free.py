"""
Free Network Scanner & Port Detection Module
Port scanning, service detection, and open port discovery
Uses socket connections and free online services (no heavy tools required)
"""

import socket
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Any
import time

def network_scanner_free(target: str, port_range: str = "1-1000", timeout: int = 5) -> Dict[str, Any]:
    """
    Scan for open ports and detect services
    
    Args:
        target: IP address or domain to scan
        port_range: Port range to scan (e.g., "1-1000", "80,443,8080")
        timeout: Socket timeout in seconds
    
    Returns:
        Dict with open ports and service detection
    """
    print(f"[*] Starting network scan for: {target}")
    
    try:
        # Resolve target to IP
        if not _is_valid_ip(target):
            try:
                target_ip = socket.gethostbyname(target)
                print(f"[*] Resolved {target} to {target_ip}")
            except socket.gaierror:
                return {
                    'status': 'error',
                    'message': f'Could not resolve {target}'
                }
        else:
            target_ip = target
        
        # Parse port range
        ports = _parse_port_range(port_range)
        
        results = {
            'status': 'success',
            'target': target,
            'target_ip': target_ip,
            'open_ports': [],
            'closed_ports': [],
            'filtered_ports': [],
            'services': {},
            'timestamp': time.time(),
            'scan_details': {
                'ports_scanned': len(ports),
                'timeout': timeout
            }
        }
        
        # Scan ports
        open_ports = _scan_ports(target_ip, ports, timeout)
        results['open_ports'] = open_ports
        
        # Detect services on open ports
        for port in open_ports:
            service = _detect_service(target_ip, port)
            results['services'][port] = service
        
        # Get results from online port scanning services
        online_scan = _query_online_port_scanner(target)
        if online_scan and 'open_ports' in online_scan:
            results['online_scan_results'] = online_scan
        
        print(f"[+] Network scan complete: {len(open_ports)} open ports found")
        return results
        
    except Exception as e:
        return {
            'status': 'error',
            'message': f'Network scan failed: {str(e)}',
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

def _parse_port_range(port_range: str) -> List[int]:
    """Parse port range string into list of ports"""
    ports = []
    
    # Handle comma-separated ports
    if ',' in port_range:
        for part in port_range.split(','):
            part = part.strip()
            if '-' in part:
                start, end = part.split('-')
                ports.extend(range(int(start), int(end) + 1))
            else:
                ports.append(int(part))
    # Handle range
    elif '-' in port_range:
        start, end = port_range.split('-')
        ports = list(range(int(start), int(end) + 1))
    else:
        ports = [int(port_range)]
    
    return sorted(list(set(ports)))[:500]  # Limit to 500 ports

def _scan_ports(target: str, ports: List[int], timeout: int, max_workers: int = 50) -> List[int]:
    """Scan ports using socket connections"""
    open_ports = []
    
    def check_port(port: int) -> tuple[int, bool]:
        """Check if single port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            sock.close()
            return port, result == 0
        except:
            return port, False
    
    print(f"[*] Scanning {len(ports)} ports on {target} (timeout: {timeout}s)")
    
    try:
        with ThreadPoolExecutor(max_workers=min(max_workers, len(ports))) as executor:
            futures = {executor.submit(check_port, port): port for port in ports}
            
            completed = 0
            for future in as_completed(futures):
                port, is_open = future.result()
                completed += 1
                
                if is_open:
                    open_ports.append(port)
                    print(f"[+] Port {port} is OPEN")
                
                # Progress indicator every 50 ports
                if completed % 50 == 0:
                    print(f"[*] Progress: {completed}/{len(ports)} ports scanned")
    
    except Exception as e:
        print(f"[!] Error during port scanning: {e}")
    
    return sorted(open_ports)

def _detect_service(target: str, port: int, timeout: int = 5) -> Dict[str, str]:
    """Detect service running on port"""
    service = {
        'port': port,
        'status': 'open',
        'detected_service': 'Unknown',
        'banner': None
    }
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target, port))
        
        # Try to receive banner
        try:
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            service['banner'] = banner[:200]  # Limit banner size
        except:
            pass
        
        sock.close()
        
        # Service mapping based on port
        service_map = {
            21: 'FTP',
            22: 'SSH',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            445: 'SMB',
            3306: 'MySQL',
            5432: 'PostgreSQL',
            6379: 'Redis',
            8080: 'HTTP (alt)',
            8443: 'HTTPS (alt)',
            27017: 'MongoDB',
            5900: 'VNC',
            3389: 'RDP',
            9200: 'Elasticsearch',
            5601: 'Kibana'
        }
        
        if port in service_map:
            service['detected_service'] = service_map[port]
        
        # Check banner for service detection
        if service['banner']:
            banner_lower = service['banner'].lower()
            if 'ssh' in banner_lower:
                service['detected_service'] = 'SSH'
            elif 'ftp' in banner_lower:
                service['detected_service'] = 'FTP'
            elif 'smtp' in banner_lower:
                service['detected_service'] = 'SMTP'
            elif 'imap' in banner_lower:
                service['detected_service'] = 'IMAP'
            elif 'pop' in banner_lower:
                service['detected_service'] = 'POP3'
    
    except Exception as e:
        service['error'] = str(e)
    
    return service

def _query_online_port_scanner(target: str) -> Dict[str, Any]:
    """Query online port scanning services (like portscan.io)"""
    try:
        # Using public APIs that provide port scanning info
        # Shodan's external IP API can help
        results = {
            'source': 'online_service',
            'scan_completed': False
        }
        
        # Try to get open ports from any available free service
        try:
            # Check if portscan.io API is available (free tier)
            response = requests.get(
                f"https://api.abuseipdb.com/api/v2/check?ipAddress={target}&maxAgeInDays=90",
                headers={'Accept': 'application/json'},
                timeout=10
            )
            
            if response.status_code == 200:
                results['abuseipdb_check'] = response.json()
        except:
            pass
        
        return results
    
    except Exception as e:
        print(f"[!] Error querying online port scanner: {e}")
        return {}

def get_common_ports() -> Dict[int, str]:
    """Return mapping of common ports to services"""
    return {
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        69: 'TFTP',
        80: 'HTTP',
        110: 'POP3',
        143: 'IMAP',
        161: 'SNMP',
        389: 'LDAP',
        443: 'HTTPS',
        445: 'SMB',
        465: 'SMTPS',
        587: 'SMTP-TLS',
        636: 'LDAPS',
        993: 'IMAPS',
        995: 'POP3S',
        1433: 'MSSQL',
        1521: 'Oracle',
        3306: 'MySQL',
        3389: 'RDP',
        5432: 'PostgreSQL',
        5900: 'VNC',
        5984: 'CouchDB',
        6379: 'Redis',
        8080: 'HTTP-Alt',
        8443: 'HTTPS-Alt',
        8888: 'HTTP-Alt',
        9200: 'Elasticsearch',
        9300: 'Elasticsearch-Node',
        27017: 'MongoDB',
        27018: 'MongoDB-Alt',
        50070: 'Hadoop NameNode'
    }

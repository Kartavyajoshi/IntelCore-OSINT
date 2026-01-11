# import requests
# import re
# from urllib.parse import urlparse, urljoin
# import urllib3

# urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# # Common directories to test
# COMMON_DIRS = [
#     'admin', 'api', 'assets', 'backup', 'config', 'database', 'debug', 'dist', 'docs',
#     'downloads', 'files', 'public', 'private', 'src', 'static', 'styles', 'templates',
#     'test', 'tmp', 'uploads', 'users', 'vendor', 'wp-admin', 'wp-content', '.git',
#     '.env', '.well-known', 'login', 'register', 'api/v1', 'api/v2', 'swagger', 'graphql',
#     'rest', 'sitemap.xml', 'robots.txt', 'admin-panel', 'panel', 'dashboard', 'phpmyadmin',
#     'cpanel', 'mail', '.gitignore', 'package.json', 'composer.json', 'requirements.txt',
#     '.htaccess', 'web.config', 'config.php', 'settings.py', 'app.py', 'index.php',
#     'index.html', 'index.jsp', 'index.aspx', 'README.md', 'LICENSE', 'VERSION'
# ]

# def get_dir_from_url(url_str):
#     """Extract directory from URL"""
#     try:
#         parsed = urlparse(url_str)
#         path = parsed.path
#         if path and path != '/':
#             return path.rsplit('/', 1)[0] + '/'
#     except:
#         pass
#     return None

# def check_directory_exists(target, path, timeout=5):
#     """
#     Check if directory/file exists with HTTP status code
#     Returns: (exists: bool, status_code: int, title: str)
#     """
#     try:
#         url = f"https://{target}{path}"
#         response = requests.get(url, timeout=timeout, verify=False, allow_redirects=False)
        
#         # Extract title if HTML
#         title = ''
#         if 'text/html' in response.headers.get('content-type', ''):
#             try:
#                 match = re.search(r'<title>(.*?)</title>', response.text, re.IGNORECASE)
#                 title = match.group(1) if match else ''
#             except:
#                 pass
        
#         # Status codes indicating existence
#         exists = response.status_code in [200, 301, 302, 401, 403]
        
#         return {
#             'exists': exists,
#             'status': response.status_code,
#             'size': len(response.content),
#             'title': title[:50],
#             'headers': dict(response.headers)
#         }
#     except requests.exceptions.Timeout:
#         return {'exists': False, 'status': 0, 'reason': 'timeout'}
#     except requests.exceptions.ConnectionError:
#         return {'exists': False, 'status': 0, 'reason': 'connection_error'}
#     except Exception as e:
#         return {'exists': False, 'status': 0, 'reason': str(e)}

# def enumerate_directories_enhanced(domain, subdomains):
#     """
#     Enhanced directory enumeration with HTTP validation
#     """
#     print(f"[*] Starting Enhanced Directory Enumeration for: {domain}...")
    
#     targets = [domain]
#     if subdomains:
#         targets.extend(subdomains)

#     final_results = []
#     global_total_found = 0

#     # PHASE 1: Passive sources (Robots, Sitemap, Wayback)
#     def collect_passive_dirs(target, dir_set, interesting_list):
#         """Collect directories from passive sources"""
        
#         # Check robots.txt
#         try:
#             url = f"https://{target}/robots.txt"
#             r = requests.get(url, timeout=5, verify=False)
#             if r.status_code == 200:
#                 for line in r.text.split('\n'):
#                     if "Disallow:" in line:
#                         path = line.split('Disallow:')[1].strip()
#                         if path and path != '/':
#                             dir_set.add(path)
#                             if any(x in path.lower() for x in ["admin", "backup", "conf", "db", "logs"]):
#                                 interesting_list.append(f"Robots: {path}")
#         except:
#             pass

#         # Check sitemap.xml
#         try:
#             url = f"https://{target}/sitemap.xml"
#             r = requests.get(url, timeout=5, verify=False)
#             if r.status_code == 200:
#                 urls = re.findall(r'<loc>(.*?)</loc>', r.text)
#                 for u in urls:
#                     d = get_dir_from_url(u)
#                     if d:
#                         dir_set.add(d)
#         except:
#             pass

#         # Check Wayback Machine
#         try:
#             api_url = f"http://web.archive.org/cdx/search/cdx?url={target}/*&output=json&fl=original&collapse=urlkey&limit=100"
#             r = requests.get(api_url, timeout=10)
#             if r.status_code == 200:
#                 data = r.json()
#                 for entry in data[1:]:
#                     original_url = entry[0]
#                     d = get_dir_from_url(original_url)
#                     if d:
#                         dir_set.add(d)
#         except:
#             pass

#     # PHASE 2: Active validation with HTTP status codes
#     def validate_directories(target, dir_set):
#         """Validate directories with HTTP requests"""
#         validated = []
        
#         print(f"    [*] Validating {len(dir_set)} directories for {target}...")
        
#         for directory in list(dir_set)[:50]:  # Limit to 50 per target
#             result = check_directory_exists(target, directory)
            
#             if result['exists']:
#                 validated.append({
#                     'path': directory,
#                     'status': result['status'],
#                     'size': result['size'],
#                     'title': result['title'],
#                     'risk': 'CRITICAL' if 'admin' in directory.lower() or 'backup' in directory.lower() else 'MEDIUM' if result['status'] == 403 else 'LOW'
#                 })
        
#         return validated

#     # PHASE 3: Common directory brute-force (faster)
#     def brute_common_dirs(target):
#         """Test common directories"""
#         found = []
        
#         print(f"    [*] Testing common directories for {target}...")
        
#         for directory in COMMON_DIRS[:30]:  # Sample of common dirs
#             path = f"/{directory}"
#             result = check_directory_exists(target, path)
            
#             if result['exists']:
#                 found.append({
#                     'path': path,
#                     'status': result['status'],
#                     'size': result['size'],
#                     'title': result['title'],
#                     'risk': 'CRITICAL' if any(x in directory.lower() for x in ['admin', 'backup', 'config']) else 'HIGH' if result['status'] == 403 else 'MEDIUM'
#                 })
        
#         return found

#     # Main execution loop
#     for target in targets:
#         print(f"\n    [+] Scanning: {target}")
        
#         passive_dirs = set()
#         interesting_finds = []
        
#         # Step 1: Collect from passive sources
#         collect_passive_dirs(target, passive_dirs, interesting_finds)
        
#         # Step 2: Validate collected directories
#         validated_dirs = validate_directories(target, passive_dirs)
        
#         # Step 3: Test common directories
#         common_found = brute_common_dirs(target)
        
#         # Combine and deduplicate
#         all_found = validated_dirs + common_found
#         all_found = {d['path']: d for d in all_found}.values()  # Remove duplicates
#         all_found = sorted(list(all_found), key=lambda x: x['status'], reverse=True)
        
#         count = len(all_found)
#         global_total_found += count
        
#         final_results.append({
#             "target": target,
#             "directories_found": all_found,
#             "total_count": count,
#             "interesting_finds": interesting_finds,
#             "status_codes": {
#                 '200': len([d for d in all_found if d['status'] == 200]),
#                 '301': len([d for d in all_found if d['status'] == 301]),
#                 '302': len([d for d in all_found if d['status'] == 302]),
#                 '401': len([d for d in all_found if d['status'] == 401]),
#                 '403': len([d for d in all_found if d['status'] == 403]),
#             },
#             "critical_findings": [d for d in all_found if d.get('risk') == 'CRITICAL']
#         })
        
#         print(f"    [✓] Found {count} directories on {target}")

#     return {
#         "status": "success",
#         "scan_summary": {
#             "total_targets": len(targets),
#             "global_total_directories": global_total_found,
#             "critical_directories": sum(len(r['critical_findings']) for r in final_results)
#         },
#         "results": final_results,
#         "timestamp": str(__import__('datetime').datetime.now().isoformat())
#     }

import requests
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin
import urllib3
import time

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Expanded critical directories list
CRITICAL_DIRS = [
    '/admin', '/admin-panel', '/administrator', '/wp-admin', '/adminpanel',
    '/api', '/api/v1', '/api/v2', '/api/v3', '/rest', '/rest/api', '/graphql', '/swagger', '/openapi',
    '/backup', '/backups', '/.backup', '/bak',
    '/config', '/configuration', '/configs', '/.config', '/.env', '/env.php',
    '/database', '/db', '/sql', '/database.php', '/db.sql',
    '/debug', '/logs', '/log', '/error_log', '/debug.log',
    '/uploads', '/files', '/documents', '/downloads', '/media',
    '/users', '/members', '/accounts', '/employees', '/staff',
    '/password', '/login', '/signin', '/auth', '/authenticate',
    '/aws', '/azure', '/.git', '/.svn', '/.hg', '/.gitignore',
    '/test', '/testing', '/dev', '/development', '/tests',
    '/temp', '/tmp', '/cache', '/temp_files',
    '/.well-known', '/robots.txt', '/sitemap.xml', '/humans.txt',
    '/health', '/status', '/ping', '/health-check',
    '/private', '/internal', '/secure', '/confidential',
    '/app', '/application', '/src', '/source', '/public',
    '/node_modules', '/vendor', '/packages', '/lib',
    '/assets', '/static', '/css', '/js', '/images', '/img',
    '/wp-content', '/wp-includes', '/wp-json',
    '/phpmyadmin', '/cpanel', '/cPanel', '/webdisk',
    '/.htaccess', '/web.config', '/robots', '/sitemap',
    '/index.php', '/index.html', '/index.jsp', '/index.aspx',
    '/README.md', '/LICENSE', '/VERSION', '/CHANGELOG',
    '/package.json', '/composer.json', '/requirements.txt',
    '/Dockerfile', '/docker-compose.yml',
    '/api/admin', '/admin/api', '/console', '/dashboard',
    '/panel', '/control', '/management', '/settings',
    '/data', '/export', '/import', '/backup-data',
    '/.github', '/.gitlab', '/.bitbucket',
    '/secrets', '/keys', '/certs', '/certificates',
    '/upload', '/form', '/submit', '/contact',
    '/about', '/contact', '/help', '/support',
    '/search', '/find', '/query', '/lookup'
]

def check_directory_fast(target, path, timeout=2):
    """
    Ultra-fast directory check with improved accuracy
    Returns only confirmed results
    """
    try:
        url = f"https://{target}{path}"
        response = requests.get(
            url, 
            timeout=timeout, 
            verify=False, 
            allow_redirects=False,
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'},
            stream=True
        )
        
        status = response.status_code
        
        # Only return if status indicates existence
        if status in [200, 301, 302, 307, 308, 401, 403]:
            try:
                content_length = len(response.content) if response.content else 0
            except:
                content_length = 0
                
            return {
                'path': path,
                'status': status,
                'exists': True,
                'size': content_length,
                'content_type': response.headers.get('Content-Type', 'unknown'),
                'risk': classify_risk(path, status)
            }
        
        return None
        
    except (requests.exceptions.Timeout, requests.exceptions.ConnectionError, requests.exceptions.RequestException):
        return None
    except Exception:
        return None

def classify_risk(path, status):
    """Classify directory risk level based on path and status"""
    path_lower = path.lower()
    
    # CRITICAL paths
    if any(x in path_lower for x in ['.env', '.git', 'backup', 'config', 'password', 'database', 'secret', 'key', 'admin']):
        return 'CRITICAL'
    
    # HIGH risk
    if any(x in path_lower for x in ['api', 'debug', 'internal', 'private', 'secure', 'test', 'logs', 'sql', 'db', 'aws', 'azure']):
        if status == 403:
            return 'HIGH'
        return 'MEDIUM'
    
    # MEDIUM risk
    if any(x in path_lower for x in ['users', 'accounts', 'uploads', 'files', 'documents', 'data']):
        return 'MEDIUM'
    
    # LOW risk
    return 'LOW'

def get_common_headers(target):
    """Detect server info for better directory selection"""
    try:
        response = requests.head(
            f"https://{target}", 
            timeout=3, 
            verify=False,
            headers={'User-Agent': 'Mozilla/5.0'}
        )
        server = response.headers.get('Server', '').lower()
        return server
    except:
        return ''

def get_custom_dirs_from_sources(target):
    """Extract directories from robots.txt and sitemap.xml"""
    custom_dirs = set()
    
    # Check robots.txt
    try:
        response = requests.get(f"https://{target}/robots.txt", timeout=3, verify=False)
        if response.status_code == 200:
            for line in response.text.split('\n'):
                if 'Disallow:' in line or 'Allow:' in line:
                    path = line.split(':')[1].strip()
                    if path and path != '/':
                        custom_dirs.add(path)
    except:
        pass
    
    # Check sitemap.xml
    try:
        response = requests.get(f"https://{target}/sitemap.xml", timeout=3, verify=False)
        if response.status_code == 200:
            urls = re.findall(r'<loc>(.*?)</loc>', response.text)
            for url in urls:
                try:
                    parsed = urlparse(url)
                    if parsed.path and parsed.path != '/':
                        custom_dirs.add(parsed.path)
                except:
                    pass
    except:
        pass
    
    return custom_dirs

def enumerate_directories_optimized(domain, subdomains=None, max_threads=10):
    """
    OPTIMIZED directory enumeration - Shows ALL directories found with speed improvements
    
    Features:
    - Parallel execution with configurable workers
    - All directories displayed (no limiting)
    - Fast timeout configuration
    - Risk classification
    - Multiple data sources (passive + active)
    """
    print(f"\n{'='*70}")
    print(f"[*] OPTIMIZED Directory Enumeration for: {domain}")
    print(f"{'='*70}")
    
    if not subdomains:
        subdomains = []
    
    # Limit subdomains for efficiency
    targets = [domain] + subdomains[:8]
    
    all_results = []
    start_time = time.time()
    
    def scan_target(target):
        """Scan single target for ALL directories"""
        target_start = time.time()
        print(f"\n  [*] Scanning {target}...")
        found = []
        scanned = 0
        
        # Get custom directories from passive sources
        print(f"      [*] Extracting directories from robots.txt & sitemap.xml...")
        custom_dirs = get_custom_dirs_from_sources(target)
        
        # Combine all directories to check
        all_dirs_to_check = list(set(CRITICAL_DIRS + list(custom_dirs)))
        total_to_check = len(all_dirs_to_check)
        
        print(f"      [*] Checking {total_to_check} directories (custom: {len(custom_dirs)}, standard: {len(CRITICAL_DIRS)})")
        
        # Use ThreadPoolExecutor for parallel requests
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = {
                executor.submit(check_directory_fast, target, path): path 
                for path in all_dirs_to_check
            }
            
            for future in as_completed(futures):
                scanned += 1
                if scanned % 20 == 0:
                    print(f"      [*] Progress: {scanned}/{total_to_check} directories checked...")
                    
                try:
                    result = future.result(timeout=5)
                    if result:
                        found.append(result)
                except:
                    pass
        
        # Sort by risk level and status code
        risk_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        found.sort(key=lambda x: (risk_order.get(x['risk'], 4), -x['status']))
        
        elapsed = time.time() - target_start
        print(f"      [✓] Completed in {elapsed:.2f}s - Found {len(found)} directories")
        
        return {
            'target': target,
            'directories_found': found,
            'total_count': len(found),
            'total_scanned': total_to_check,
            'scan_time': elapsed,
            'critical': len([d for d in found if d['risk'] == 'CRITICAL']),
            'high': len([d for d in found if d['risk'] == 'HIGH']),
            'medium': len([d for d in found if d['risk'] == 'MEDIUM']),
            'low': len([d for d in found if d['risk'] == 'LOW']),
        }
    
    # Scan all targets in parallel
    print(f"\n  [*] Starting parallel scans on {len(targets)} target(s)...")
    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = [executor.submit(scan_target, t) for t in targets]
        
        for future in as_completed(futures):
            try:
                result = future.result(timeout=120)
                all_results.append(result)
            except Exception as e:
                print(f"  [!] Scan error: {e}")
    
    # Calculate summary
    total_dirs = sum(r['total_count'] for r in all_results)
    total_critical = sum(r['critical'] for r in all_results)
    total_high = sum(r['high'] for r in all_results)
    total_scanned = sum(r['total_scanned'] for r in all_results)
    total_time = time.time() - start_time
    
    print(f"\n{'='*70}")
    print(f"[✓] SCAN COMPLETE")
    print(f"  Total Directories Found: {total_dirs}")
    print(f"  Critical: {total_critical} | High: {total_high} | Medium: {sum(r['medium'] for r in all_results)}")
    print(f"  Total Checked: {total_scanned} | Time: {total_time:.2f}s")
    print(f"{'='*70}\n")
    
    return {
        'status': 'success',
        'scan_summary': {
            'total_targets': len(targets),
            'total_directories_found': total_dirs,
            'critical_directories': total_critical,
            'high_directories': total_high,
            'total_checked': total_scanned,
            'scan_duration_seconds': round(total_time, 2)
        },
        'results': all_results,
        'timestamp': str(__import__('datetime').datetime.now().isoformat())
    }

# Example usage:
# result = enumerate_directories_optimized('example.com', ['www.example.com', 'api.example.com'], max_threads=12)
# print(result)










# Example usage:
# result = enumerate_directories_fast('example.com', ['www.example.com', 'api.example.com'])
# print(result)




# {
#   "status": "success",
#   "scan_summary": {
#     "total_targets_scanned": 3,
#     "global_total_directories_found": 18
#   },
#   "results": [
#     {
#       "target": "example.com",
#       "unique_directories": [
#         "example.com/about/",
#         "example.com/assets/css/",
#         "example.com/assets/js/",
#         "example.com/contact/",
#         "example.com/login/",
#         "example.com/private_backup/",
#         "example.com/wp-admin/",
#         "example.com/wp-content/uploads/"
#       ],
#       "total_found": 8,
#       "interesting_finds": [
#         "Robots Hidden: example.com/private_backup/",
#         "Robots Hidden: example.com/wp-admin/"
#       ],
#       "sources_used": [
#         "Robots.txt",
#         "Sitemap.xml",
#         "Wayback Machine"
#       ]
#     },
#     {
#       "target": "admin.example.com",
#       "unique_directories": [
#         "admin.example.com/config/",
#         "admin.example.com/dashboard/v2/",
#         "admin.example.com/logs/error_log/",
#         "admin.example.com/signin/"
#       ],
#       "total_found": 4,
#       "interesting_finds": [
#         "Robots Hidden: admin.example.com/config/",
#         "Robots Hidden: admin.example.com/logs/error_log/"
#       ],
#       "sources_used": [
#         "Robots.txt",
#         "Sitemap.xml",
#         "Wayback Machine"
#       ]
#     },
#     {
#       "target": "api.example.com",
#       "unique_directories": [
#         "api.example.com/internal/metrics/",
#         "api.example.com/v1/docs/",
#         "api.example.com/v1/users/",
#         "api.example.com/v1/auth/",
#         "api.example.com/v2/beta/"
#       ],
#       "total_found": 6,
#       "interesting_finds": [
#         "Robots Hidden: api.example.com/internal/metrics/"
#       ],
#       "sources_used": [
#         "Robots.txt",
#         "Sitemap.xml",
#         "Wayback Machine"
#       ]
#     }
#   ]
# }
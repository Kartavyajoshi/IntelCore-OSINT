import requests
import re
from bs4 import BeautifulSoup, Comment
import urllib3
from urllib.parse import urljoin, urlparse

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def extract_forensic_details(domain, subdomains, default_country_code="+91"):
    """
    Advanced Forensic Scraper.
    Extracts: Emails, Normalized Phones, Critical Docs (Backups/Configs), 
    HTML Comments, Meta Data, and Hidden Form Inputs.
    """
    print(f"[*] Starting Deep Forensic Scraping for: {domain}...")

    targets = [domain]
    if subdomains:
        targets.extend(subdomains)

    final_results = []
    
    # --- HELPER: Phone Normalization ---
    def normalize_phone(phone_raw, default_cc):
        clean = re.sub(r'[ \-\(\)\.]', '', phone_raw)
        if clean.startswith('00'): return '+' + clean[2:]
        if clean.startswith('+'): return clean
        return f"{default_cc}{clean}"

    # --- HELPER: Scrape Single Target ---
    def scrape_target(target):
        print(f"    [-] Scanning {target}...")
        target_data = {
            'emails': set(), 
            'phones': set(), 
            'documents': [], 
            'forms': [],
            'comments': [],      # NEW: HTML Comments
            'external_links': [], # NEW: Social/External links
            'metadata': {}       # NEW: Server/Generator info
        }
        
        try:
            url = f"https://{target}"
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
            response = requests.get(url, headers=headers, timeout=8, verify=False)
            
            if response.status_code == 200:
                text = response.text
                soup = BeautifulSoup(text, 'html.parser')

                # 1. METADATA & HEADERS
                # ---------------------
                if 'server' in response.headers:
                    target_data['metadata']['server'] = response.headers['server']
                
                generator = soup.find('meta', attrs={'name': 'generator'})
                if generator:
                    target_data['metadata']['generator'] = generator.get('content')

                # 2. HTML COMMENTS (Often hide secrets)
                # ---------------------
                comments = soup.find_all(string=lambda text: isinstance(text, Comment))
                for c in comments:
                    c_clean = c.strip()
                    # Filter for interesting comments
                    if len(c_clean) > 3 and any(k in c_clean.lower() for k in ['todo', 'fixme', 'admin', 'pass', 'key', 'test', 'v1']):
                        target_data['comments'].append(c_clean[:100]) # Truncate long comments

                # 3. EMAILS (Regex + mailto:)
                # ---------------------
                # Regex
                emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', text)
                target_data['emails'].update(emails)
                
                # Mailto links (often obfuscated in regex)
                for a in soup.select('a[href^=mailto]'):
                    email = a['href'].replace('mailto:', '').split('?')[0]
                    target_data['emails'].add(email)

                # 4. PHONES (Regex + tel:)
                # ---------------------
                phone_pattern = r'(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,9}'
                raw_phones = re.findall(phone_pattern, text)
                for p in raw_phones:
                    clean_check = re.sub(r'\D', '', p)
                    if 7 <= len(clean_check) <= 15:
                        target_data['phones'].add(normalize_phone(p.strip(), default_country_code))

                # 5. CRITICAL DOCUMENTS & EXTERNALS
                # ---------------------
                # Expanded extension list including backups and configs
                crit_exts = (
                    '.pdf', '.docx', '.xlsx', '.pptx', '.txt', '.csv', '.xml', '.json',
                    '.zip', '.rar', '.7z', '.tar', '.gz',  # Archives
                    '.bak', '.old', '.swp', '.sql', '.db', # Backups/DB
                    '.config', '.env', '.log', '.ini'      # Configs
                )
                
                social_domains = ['github.com', 'linkedin.com', 'twitter.com', 'facebook.com', 'instagram.com', 'gitlab.com']

                for link in soup.find_all('a', href=True):
                    href = link['href']
                    full_url = urljoin(url, href)
                    
                    # Check for Critical Docs
                    if any(full_url.lower().endswith(ext) for ext in crit_exts):
                        name = link.get_text(strip=True) or href.split('/')[-1]
                        doc_entry = {"name": name, "link": full_url, "type": full_url.split('.')[-1]}
                        if doc_entry not in target_data['documents']:
                            target_data['documents'].append(doc_entry)
                    
                    # Check for Social/External Links
                    try:
                        parsed = urlparse(full_url)
                        domain_part = parsed.netloc.lower()
                        if any(s in domain_part for s in social_domains):
                             target_data['external_links'].append(full_url)
                    except: pass

                # 6. FORMS & HIDDEN INPUTS
                # ---------------------
                for form in soup.find_all('form'):
                    action = urljoin(url, form.get('action', ''))
                    method = form.get('method', 'GET').upper()
                    
                    # Capture hidden inputs (often contain tokens/context)
                    hidden_inputs = []
                    for inp in form.find_all('input', type='hidden'):
                        if inp.get('name'):
                            hidden_inputs.append(inp.get('name'))
                            
                    target_data['forms'].append({
                        'action': action,
                        'method': method,
                        'inputs_count': len(form.find_all(['input', 'textarea', 'select'])),
                        'hidden_fields': hidden_inputs
                    })
                    
        except Exception as e:
            # print(f"Error scraping {target}: {e}")
            pass

        return target_data

    # --- EXECUTION ---
    total_emails = 0
    
    for t in targets:
        data = scrape_target(t)
        count = len(data['emails'])
        total_emails += count
        
        final_results.append({
            "target": t,
            "emails": list(data['emails']),
            "phones": list(data['phones']),
            "documents": data['documents'],
            "forms": data['forms'],
            "comments": data['comments'],         # Include comments in result
            "external_links": list(set(data['external_links'])), # Deduplicate
            "metadata": data['metadata'],
            "stats": {
                "emails_found": count,
                "docs_found": len(data['documents']),
                "comments_found": len(data['comments'])
            }
        })

    return {
        'status': 'success',
        'scan_summary': {
            'targets_scanned': len(targets),
            'total_emails': total_emails
        },
        'results': final_results,
        'source': 'Deep Web Scraping'
    }

# {
#   "status": "success",
#   "scan_summary": {
#     "targets_scanned": 2,
#     "total_emails": 5
#   },
#   "results": [
#     {
#       "target": "example.com",
#       "emails": [
#         "support@example.com",
#         "contact@example.com",
#         "careers@example.com"
#       ],
#       "phones": [
#         "+91 98765 43210",
#         "+1 (555) 012-3456"
#       ],
#       "documents": [
#         {
#           "name": "Annual Security Report 2024",
#           "link": "https://example.com/assets/reports/security_2024.pdf"
#         },
#         {
#           "name": "Privacy Policy (Updated)",
#           "link": "https://example.com/legal/privacy_v2.docx"
#         },
#         {
#           "name": "budget_sheet.xlsx",
#           "link": "https://example.com/internal/finance/budget_sheet.xlsx"
#         }
#       ],
#       "forms": [
#         {
#           "action": "https://example.com/auth/login.php",
#           "method": "POST",
#           "inputs_count": 3
#         },
#         {
#           "action": "https://example.com/search",
#           "method": "GET",
#           "inputs_count": 1
#         }
#       ],
#       "stats": {
#         "emails_found": 3,
#         "docs_found": 3
#       }
#     },
#     {
#       "target": "files.example.com",
#       "emails": [
#         "admin@example.com",
#         "uploader@example.com"
#       ],
#       "phones": [],
#       "documents": [
#         {
#           "name": "Server Logs",
#           "link": "https://files.example.com/logs/Jan_2025.txt"
#         }
#       ],
#       "forms": [],
#       "stats": {
#         "emails_found": 2,
#         "docs_found": 1
#       }
#     }
#   ],
#   "source": "Web Scraping"
# }
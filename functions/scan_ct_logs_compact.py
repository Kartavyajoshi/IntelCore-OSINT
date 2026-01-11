import requests
import re
import urllib3
from collections import Counter


def scan_ct_logs_compact(target):
    """
    Compact OSINT CT Log Scanner.
    Returns only high-value intelligence: 
    [Risk Score, Issuer, Target Subdomains, Date, Serial]
    """
    print(f"[*] Scanning {target} for critical certificate intel...")
    
    # --- CONFIG ---
    BAD_ACTORS = ["DigiNotar", "Symantec", "WoSign", "StartCom", "CNNIC"]
    
    # --- STORAGE ---
    unique_subdomains = set()
    processed_serials = set()
    raw_entries = []
    issuer_counter = Counter()

    def clean_domain(value):
        if not value: return None
        value = re.sub(r'^https?://', '', value.strip())
        value = value.split('/')[0].split(':')[0]
        return value.lower()

    try:
        # 1. FETCH
        url = f"https://crt.sh/?q=%.{target}&output=json"
        headers = {'User-Agent': 'Mozilla/5.0 (OSINT Tool)'}
        r = requests.get(url, headers=headers, timeout=40, verify=False)
        
        if r.status_code != 200: return {'status': 'error', 'message': f'HTTP {r.status_code}'}
        try: data = r.json()
        except: return {'status': 'error', 'message': 'Invalid JSON'}

        # 2. PARSE
        for entry in data:
            serial = entry.get("serial_number")
            if serial in processed_serials: continue
            processed_serials.add(serial)

            # Extract Short Issuer Name (e.g., "Google Inc")
            raw_issuer = entry.get("issuer_name", "Unknown")
            try:
                issuer_org = re.search(r'O=([^,]+)', raw_issuer).group(1).strip('"')
            except:
                issuer_org = "Unknown"

            # Extract Subdomains
            found_subs = []
            for name in entry.get("name_value", "").split("\n"):
                if target in name:
                    cleaned = clean_domain(name.replace("*.", ""))
                    if cleaned and cleaned != target and target in cleaned:
                        unique_subdomains.add(cleaned)
                        found_subs.append(cleaned)

            # Minimal Storage
            raw_entries.append({
                "org": issuer_org,
                "serial": serial,
                "date": entry.get("not_before", "")[:10], # Just the YYYY-MM-DD
                "subs": found_subs
            })
            issuer_counter[issuer_org] += 1

        # 3. ANALYZE & COMPACT
        if not raw_entries: return {'status': 'empty'}

        dominant_issuer = issuer_counter.most_common(1)[0][0]
        total = len(raw_entries)
        final_output = []

        for cert in raw_entries:
            # Risk Logic
            risk = "LOW"
            note = "Standard"
            
            if any(bad in cert["org"] for bad in BAD_ACTORS):
                risk = "CRITICAL"
                note = "Compromised CA"
            elif cert["org"] != dominant_issuer:
                share = (issuer_counter[cert["org"]] / total) * 100
                if share < 10:
                    risk = "HIGH" if issuer_counter[cert["org"]] == 1 else "MEDIUM"
                    note = "Rare Issuer (Anomaly)"

            # The Compact OSINT Object
            final_output.append({
                "risk": risk,              # The most important field
                "issuer": cert["org"],     # Who signed it?
                "subdomains": cert["subs"],# What are they targeting?
                "date": cert["date"],      # When did this happen?
                "note": note,              # Short context
                "serial": cert["serial"]   # For pivoting/blocking
            })

        # Sort: Critical/High threats first
        risk_map = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        final_output.sort(key=lambda x: risk_map.get(x["risk"], 3))

        return {
            'target': target,
            'subdomain_count': len(unique_subdomains),
            'certificates': final_output
        }

    except Exception as e:
        return {'status': 'error', 'message': str(e)}



#---------Sample Output---------
# {
#   "target": "google.com",
#   "subdomain_count": 5,
#   "certificates": [
#     {
#       "risk": "HIGH",
#       "issuer": "DigiNotar",
#       "subdomains": ["admin.google.com"],
#       "date": "2011-07-10",
#       "note": "Rare Issuer (Anomaly)",
#       "serial": "05e2e6a4cd09ea54d665b075fe22a256"
#     },
#     {
#       "risk": "LOW",
#       "issuer": "Google Inc",
#       "subdomains": [
#         "docs.google.com", 
#         "mail.google.com", 
#         "plus.google.com", 
#         "sites.google.com"
#       ],
#       "date": "2011-07-13",
#       "note": "Standard",
#       "serial": "3e554a12000300002c7f"
#     }
#   ]
# }

import requests
import re

# --- CONFIGURATION ---
MAIL_PROVIDERS = {
    "google.com": "Google Workspace",
    "googlemail.com": "Google Workspace",
    "outlook.com": "Microsoft 365",
    "protection.outlook.com": "Microsoft 365",
    "pphosted.com": "Proofpoint",
    "mimecast.com": "Mimecast",
    "zoho.com": "Zoho Mail",
    "protonmail.ch": "ProtonMail",
    "amazonaws.com": "Amazon SES"
}

def dns_recon_passive(domain):
    """
    PASSIVE DNS Enumeration (API-Based).
    Source: HackerTarget (Zero contact with target).
    Returns: Dashboard-Ready Intelligence.
    """
    print(f"[*] Running PASSIVE DNS Recon for: {domain}...")
    
    # 1. FETCH DATA (From Third-Party API)
    try:
        url = f"https://api.hackertarget.com/dnslookup/?q={domain}"
        response = requests.get(url, timeout=20)
        
        if response.status_code != 200:
            return {'status': 'error', 'message': 'API Unavailable'}
            
        raw_text = response.text
        
    except Exception as e:
        return {'status': 'error', 'message': str(e)}

    # 2. PARSE & ANALYZE (Local Processing)
    
    # Storage
    records = {'A': [], 'MX': [], 'TXT': [], 'NS': [], 'SOA': [], 'CNAME': []}
    
    # Intel Holders
    intel = {
        'mail_provider': "Unknown / Self-Hosted",
        'cloud_host': None,
        'spf_record': None,
        'dmarc_record': None,
        'admin_email': None
    }

    # Regex to parse the "dig-style" output from HackerTarget
    # Example Line: "google.com.  300  IN  MX  10 smtp.google.com."
    lines = raw_text.split('\n')
    
    for line in lines:
        if not line or line.startswith(';'): continue
        
        parts = line.split()
        if len(parts) < 4: continue
        
        # Detected Type (A, MX, etc.) is usually at index 3
        # But sometimes formatting varies, so we look for keywords
        
        # --- MX RECORDS ---
        if 'MX' in parts:
            server = parts[-1].rstrip('.')
            records['MX'].append(server)
            for k, v in MAIL_PROVIDERS.items():
                if k in server: intel['mail_provider'] = v

        # --- TXT RECORDS (SPF/DMARC) ---
        elif 'TXT' in parts:
            # Join everything after 'TXT' to get the full string
            try:
                txt_index = parts.index('TXT')
                txt_val = " ".join(parts[txt_index+1:]).strip('"')
                records['TXT'].append(txt_val)
                
                if "v=spf1" in txt_val: intel['spf_record'] = txt_val
                if "v=DMARC1" in txt_val: intel['dmarc_record'] = txt_val
            except: pass

        # --- NS RECORDS ---
        elif 'NS' in parts:
            ns = parts[-1].rstrip('.')
            records['NS'].append(ns)

        # --- SOA RECORDS ---
        elif 'SOA' in parts:
            # SOA format: mname rname serial ...
            try:
                soa_index = parts.index('SOA')
                mname = parts[soa_index+1].rstrip('.')
                rname = parts[soa_index+2].rstrip('.')
                
                records['SOA'].append(mname)
                
                # Parse Email (rname uses '.' instead of '@')
                if '.' in rname:
                    p = rname.split('.', 1)
                    intel['admin_email'] = f"{p[0]}@{p[1]}"
            except: pass

        # --- CNAME RECORDS ---
        elif 'CNAME' in parts:
            target = parts[-1].rstrip('.')
            records['CNAME'].append(target)
            
            if "amazonaws" in target: intel['cloud_host'] = "AWS"
            elif "azure" in target: intel['cloud_host'] = "Azure"
            elif "akamai" in target: intel['cloud_host'] = "Akamai"
            elif "cloudflare" in target: intel['cloud_host'] = "Cloudflare"

        # --- A RECORDS ---
        elif 'A' in parts and not 'AAAA' in parts:
            ip = parts[-1]
            if re.match(r"^\d{1,3}\.", ip): # Simple IP check
                records['A'].append(ip)

    # 3. GENERATE DASHBOARD HINTS
    hints = []
    if not intel['dmarc_record']: hints.append("Missing DMARC Policy")
    if intel['mail_provider'] == "Unknown / Self-Hosted": hints.append("Self-Hosted Email Detected")
    if intel['cloud_host']: hints.append(f"Uses {intel['cloud_host']} Infrastructure")

    # 4. RETURN STRUCTURED DATA
    return {
        'status': 'success',
        'domain': domain,
        'source': 'Passive API (HackerTarget)',
        
        'identity': {
            'admin_contact': intel['admin_email'],
            'dns_authority': records['SOA'][0] if records['SOA'] else "Unknown",
            'nameservers': records['NS']
        },

        'infrastructure': {
            'ip_addresses': records['A'],
            'mail_provider': intel['mail_provider'],
            'cloud_provider': intel['cloud_host'] if intel['cloud_host'] else "On-Prem/Unknown",
            'mail_servers': records['MX']
        },

        'security': {
            'spf_policy': intel['spf_record'] if intel['spf_record'] else "Missing",
            'dmarc_policy': intel['dmarc_record'] if intel['dmarc_record'] else "Missing",
            'txt_verification': [t for t in records['TXT'] if "v=" not in t]
        },
        
        'dashboard_hints': hints
    }
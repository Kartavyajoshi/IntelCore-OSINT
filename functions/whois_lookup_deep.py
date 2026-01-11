import whois
import datetime

def whois_lookup_deep(domain):
    """
    Deep WHOIS Lookup using python-whois library.
    No API keys required. Direct query to TLD servers.
    """
    print(f"[*] Running Deep WHOIS lookup for: {domain}...")
    
    try:
        # The library does the heavy lifting
        # simple checks if domain exists before detailed parsing
        w = whois.whois(domain)
        
        # WHOIS data is messy. Fields like 'creation_date' can be:
        # - A single datetime object
        # - A list of datetime objects (if multiple registrars exist)
        # - None
        # We need a helper to clean this up.

        def format_date(date_obj):
            if isinstance(date_obj, list):
                # If it's a list, take the first valid date
                return date_obj[0].strftime('%Y-%m-%d') if date_obj else 'N/A'
            elif isinstance(date_obj, datetime.datetime):
                return date_obj.strftime('%Y-%m-%d')
            return 'N/A'

        # Extract & Clean Data
        result = {
            'status': 'success',
            'domain_name': w.domain_name if w.domain_name else domain,
            'registrar': {
                'name': w.registrar,
                'iana_id': w.registrar_iana_id,
                'email': w.emails if w.emails else 'Redacted'
            },
            'dates': {
                'created': format_date(w.creation_date),
                'updated': format_date(w.updated_date),
                'expires': format_date(w.expiration_date)
            },
            'infrastructure': {
                'nameservers': w.name_servers if w.name_servers else [],
                'whois_server': w.whois_server
            },
            'registrant': {
                'org': w.org if w.org else 'Redacted/Privacy Protected',
                'country': w.country,
                'city': w.city,
                'state': w.state
            },
            # Security Flags (Status codes)
            'status': w.status if w.status else ['Unknown']
        }
        
        # Simple Logic to check if domain is locked (ClientTransferProhibited)
        # 'status' can be a list or string, so we normalize it
        status_list = w.status if isinstance(w.status, list) else [str(w.status)]
        is_locked = any('Prohibited' in str(s) for s in status_list)
        
        result['security_check'] = {
            'is_locked': is_locked,
            'note': "Domain is locked from transfer" if is_locked else "Domain Unlocked (Risk of Hijacking)"
        }

        print(f"[+] WHOIS Success. Registrar: {result['registrar']['name']}")
        return result

    except Exception as e:
        print(f"[!] WHOIS Lookup Failed: {e}")
        return {'status': 'error', 'message': str(e)}

# --- Example Test ---
# if __name__ == "__main__":
#     import json
#     data = whois_lookup_deep("google.com")
#     print(json.dumps(data, indent=2))
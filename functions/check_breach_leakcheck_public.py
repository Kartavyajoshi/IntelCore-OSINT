import requests
import time
import urllib3

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def check_breach_leakcheck_public(emails):
    """
    Check email breaches using LeakCheck.io Public API.
    UPDATED: Now extracts 'fields' to show WHAT was stolen (Passwords, IPs, etc.)
    """
    print("[*] Running breach check (Source: LeakCheck Public)...")
    
    if not emails:
        return {'status': 'success', 'results': []}

    unique_emails = list(set(emails))
    results = []
    BASE_URL = "https://leakcheck.io/api/public"

    print(f"[*] Checking {len(unique_emails)} unique emails...")

    for email in unique_emails:
        try:
            params = {'check': email}
            response = requests.get(BASE_URL, params=params, timeout=10, verify=False)
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('success') and data.get('found', 0) > 0:
                    
                    # 1. GET SOURCES (Where it leaked)
                    sources = []
                    for src in data.get('sources', []):
                        sources.append({
                            'name': src.get('name'),
                            'date': src.get('date')
                        })

                    # 2. GET COMPROMISED FIELDS (What leaked)
                    # The public API returns a 'fields' list like ['email', 'password', 'ip']
                    raw_fields = data.get('fields', [])
                    
                    # Calculate Risk Level
                    risk_level = "Low"
                    if 'password' in raw_fields:
                        risk_level = "CRITICAL"
                    elif 'ip' in raw_fields or 'phone' in raw_fields:
                        risk_level = "High"

                    results.append({
                        'email': email,
                        'is_pwned': True,
                        'risk_level': risk_level,
                        'data_leaked': raw_fields,  # <--- NEW FIELD
                        'breach_count': len(sources),
                        'breaches': sources[:5]
                    })
                    print(f"    [!] FOUND: {email} (Risk: {risk_level}) - Leaked: {raw_fields}")
                
                else:
                    results.append({
                        'email': email,
                        'is_pwned': False,
                        'risk_level': "Safe",
                        'data_leaked': [],
                        'breach_count': 0,
                        'breaches': []
                    })
                    print(f"    [+] CLEAN: {email}")

            elif response.status_code == 429:
                print(f"    [!] Rate limited. Sleeping...")
            else:
                print(f"    [!] Error: {response.status_code}")

            time.sleep(1.5) # Respect API limits

        except Exception as e:
            print(f"    [!] Connection error for {email}: {e}")

    return {
        'status': 'success',
        'results': results,
        'source': 'LeakCheck.io (Public)'
    }

# {
#   "status": "success",
#   "results": [
#     {
#       "email": "admin@example.com",
#       "is_pwned": true,
#       "risk_level": "CRITICAL",
#       "data_leaked": [
#         "email",
#         "password",
#         "ip_address",
#         "username"
#       ],
#       "breach_count": 2,
#       "breaches": [
#         {
#           "name": "Exploit.in",
#           "date": "2016-10"
#         },
#         {
#           "name": "Verifications.io",
#           "date": "2019-02"
#         }
#       ]
#     },
#     {
#       "email": "newsletter@example.com",
#       "is_pwned": true,
#       "risk_level": "Low",
#       "data_leaked": [
#         "email"
#       ],
#       "breach_count": 1,
#       "breaches": [
#         {
#           "name": "Marketing List 2020",
#           "date": "2020-05"
#         }
#       ]
#     }
#   ]
# }
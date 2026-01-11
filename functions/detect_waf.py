import requests
import urllib3

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def detect_waf(domain, subdomains):
    """
    Robust WAF detection using Passive (Headers/Cookies) and Active (Provocation) methods.
    """
    print(f"[*] Starting Advanced WAF Detection for: {domain}...")

    targets = [domain]
    if subdomains:
        targets.extend(subdomains)

    # --- WAF SIGNATURE DATABASE ---
    WAF_SIGNATURES = {
        'Cloudflare': {
            'headers': ['cf-ray', 'cf-cache-status'],
            'cookies': ['__cfduid', 'cf_clearance'],
            'server': 'cloudflare'
        },
        'AWS WAF': {
            'headers': ['x-amzn-requestid', 'x-amz-cf-id'],
            'server': 'awselb'
        },
        'Akamai': {
            'headers': ['x-akamai-transformed', 'akamai-origin-hop'],
            'server': 'akamaighost'
        },
        'Imperva Incapsula': {
            'headers': ['x-cdn'],
            'cookies': ['incap_ses', 'visid_incap'],
            'server': 'incapsula'
        },
        'F5 BIG-IP': {
            'cookies': ['BIGipServer', 'TS'],
            'server': 'BigIP'
        },
        'Sucuri': {
            'headers': ['x-sucuri-id'],
            'server': 'sucuri'
        },
        'Barracuda': {
            'cookies': ['barra_counter_session'],
            'server': 'barracuda'
        },
        'Citrix NetScaler': {
            'headers': ['ns_af'],
            'server': 'citrix'
        }
    }

    final_results = []

    def check_target(target):
        print(f"    [-] Scanning {target}...")
        detected_waf = None
        method = "N/A"
        
        try:
            url = f"https://{target}"
            # Standard request (Passive Check)
            r = requests.get(url, timeout=5, headers={'User-Agent': 'Mozilla/5.0'}, verify=False)
            headers_lower = {k.lower(): v.lower() for k, v in r.headers.items()}
            cookies = r.cookies.get_dict()
            server_header = headers_lower.get('server', '').lower()

            # 1. PASSIVE: Check Signatures
            for waf_name, sigs in WAF_SIGNATURES.items():
                # Check Headers
                if 'headers' in sigs:
                    for h in sigs['headers']:
                        if h in headers_lower:
                            return waf_name, "Header Detection"
                
                # Check Cookies
                if 'cookies' in sigs:
                    for c_key in sigs['cookies']:
                        if any(c_key in cookie for cookie in cookies):
                            return waf_name, "Cookie Detection"

                # Check Server Header
                if 'server' in sigs and sigs['server'] in server_header:
                    return waf_name, "Server Header"

            # 2. ACTIVE: Provocation (If passive failed)
            # Send a harmless XSS payload to trigger the WAF
            print(f"    [!] Passive scan failed. Sending provocation payload to {target}...")
            bait_url = f"{url}/?id=<script>alert(1)</script>"
            r_active = requests.get(bait_url, timeout=5, headers={'User-Agent': 'Mozilla/5.0'}, verify=False)

            # Check if we got blocked (403 Forbidden or 406 Not Acceptable are common WAF responses)
            if r_active.status_code in [403, 406, 501]:
                # Analyze the block page text for clues
                page_text = r_active.text.lower()
                
                if "cloudflare" in page_text:
                    return "Cloudflare", "Active Provocation (Block Page)"
                elif "request could not be satisfied" in page_text:
                    return "AWS WAF", "Active Provocation (Block Page)"
                elif "incapsula" in page_text:
                    return "Imperva Incapsula", "Active Provocation (Block Page)"
                else:
                    return "Generic WAF Detected", "Active Provocation (Status Code)"

        except Exception as e:
            # print(f"Error: {e}") 
            pass
        
        return "None Detected", "N/A"

    # --- MAIN LOOP ---
    for t in targets:
        waf_name, method = check_target(t)
        
        final_results.append({
            "target": t,
            "has_waf": waf_name != "None Detected",
            "waf_name": waf_name,
            "detection_method": method
        })

    return {
        "status": "success",
        "results": final_results,
        "source": "Advanced WAF Scanner"
    }


# {
#   "status": "success",
#   "results": [
#     {
#       "target": "example.com",
#       "has_waf": true,
#       "waf_name": "Cloudflare",
#       "detection_method": "Header Detection"
#     },
#     {
#       "target": "api.example.com",
#       "has_waf": true,
#       "waf_name": "AWS WAF",
#       "detection_method": "Active Provocation (Block Page)"
#     },
#     {
#       "target": "legacy.example.com",
#       "has_waf": true,
#       "waf_name": "F5 BIG-IP",
#       "detection_method": "Cookie Detection"
#     },
#     {
#       "target": "dev.example.com",
#       "has_waf": false,
#       "waf_name": "None Detected",
#       "detection_method": "N/A"
#     }
#   ],
#   "source": "Advanced WAF Scanner"
# }
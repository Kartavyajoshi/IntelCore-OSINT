import requests
import datetime
import urllib3

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def check_virustotal_critical(domain, api_key):
    """
    VirusTotal Raw Intelligence (No Risk Scoring).
    Extracts: Vendor Counts, Threat Categories, Community Reputation, and Popularity.
    """
    print(f"[*] Fetching critical VT data for: {domain}...")
    
    try:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {'x-apikey': api_key}
        
        # Timeout set to 15s to prevent hanging
        response = requests.get(url, headers=headers, timeout=15, verify=False)
        
        if response.status_code == 404:
            return {'status': 'empty', 'message': 'Domain not found in VirusTotal.'}
        elif response.status_code != 200:
            return {'status': 'error', 'message': f'API Error {response.status_code}'}

        data = response.json()
        attr = data.get('data', {}).get('attributes', {})
        stats = attr.get('last_analysis_stats', {})

        # --- EXTRACT CRITICAL INFO ONLY ---
        
        # 1. Vendor Detections (The raw numbers)
        detection_summary = {
            'malicious': stats.get('malicious', 0),
            'suspicious': stats.get('suspicious', 0),
            'harmless': stats.get('harmless', 0),
            'undetected': stats.get('undetected', 0),
            'total_engines': sum(stats.values())
        }

        # 2. Threat Categories (What do vendors call this?)
        # We consolidate all vendor tags into a unique list
        # e.g. "phishing", "botnet", "malware"
        raw_cats = attr.get('categories', {}).values()
        threat_tags = list(set(raw_cats))

        # 3. Community Context
        # Reputation is a score calculated by VT user votes (can be negative)
        reputation = attr.get('reputation', 0)
        votes = attr.get('total_votes', {})

        # 4. Legitimacy Indicators (Popularity Ranks)
        # If listed in "Tranco" or "Alexa", it's likely a legitimate site
        popularity = attr.get('popularity_ranks', {})
        rankings = [f"{k}: #{v['rank']}" for k, v in popularity.items()]

        # 5. Timeline (From VT's cached WHOIS)
        # Useful if your direct WHOIS lookup failed
        creation_ts = attr.get('creation_date')
        creation_date = "Unknown"
        if creation_ts:
            creation_date = datetime.datetime.fromtimestamp(creation_ts).strftime('%Y-%m-%d')

        return {
            'status': 'success',
            'target': domain,
            'detections': detection_summary,
            'threat_tags': threat_tags[:10],  # Top 10 tags
            'community_reputation': reputation,
            'community_votes': votes,
            'global_rankings': rankings,      # e.g., ['Tranco: #1', 'Alexa: #1']
            'creation_date_cached': creation_date,
            'last_analysis_date': datetime.datetime.fromtimestamp(attr.get('last_analysis_date', 0)).strftime('%Y-%m-%d')
        }

    except Exception as e:
        return {'status': 'error', 'message': str(e)}



# ---output example---
# {
#   "status": "success",
#   "target": "example.com",
#   "detections": {
#     "malicious": 0,
#     "suspicious": 0,
#     "harmless": 88,
#     "undetected": 2,
#     "total_engines": 90
#   },
#   "threat_tags": [],
#   "community_reputation": 149,
#   "community_votes": {
#     "harmless": 68,
#     "malicious": 3
#   },
#   "global_rankings": [
#     "Tranco: #1024",
#     "Alexa: #500"
#   ],
#   "creation_date_cached": "1995-08-14",
#   "last_analysis_date": "2024-01-09"
# }
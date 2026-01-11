# app.py - FIXED PDF DOWNLOAD (Using Your Existing Report Function)

from flask import Flask, render_template, request, jsonify, send_file
import os
import sys
import json
import datetime
import traceback
from pathlib import Path
from dotenv import load_dotenv
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'functions'))

# ============ IMPORT ALL SCANNING MODULES ============
# ============ FIXED IMPORT SECTION FOR app.py ============
import sys
import os
import traceback

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import Check Breach
try:
    from check_breach_leakcheck_public import check_breach_leakcheck_public
except ImportError:
    print("[!] Failed to import check_breach_leakcheck_public")

# Import Shodan
try:
    from check_shodan_enhanced import get_shodan_profile
except ImportError:
    print("[!] Failed to import check_shodan_enhanced")

# Import VirusTotal
try:
    from check_virustotal_advanced import check_virustotal_critical
except ImportError:
    print("[!] Failed to import check_virustotal_advanced")

# Import WAF Detect
try:
    from detect_waf import detect_waf
except ImportError:
    print("[!] Failed to import detect_waf")

# Import DNS Recon
try:
    from dns_recon_advanced import dns_recon_passive
except ImportError:
    print("[!] Failed to import dns_recon_advanced")

# Import Directories (FIXED NAME)
try:
    from enumerate_directories_optimized import enumerate_directories_optimized
except ImportError:
    print("[!] Failed to import enumerate_directories_optimized")

# Import Forensics
try:
    from extract_forensic_details import extract_forensic_details
except ImportError:
    print("[!] Failed to import extract_forensic_details")

# Import PDF Generator
try:
    from generate_premium_report import generate_premium_report
except ImportError:
    print("[!] Failed to import generate_premium_report")

# Import CT Logs (Newly Created File)
try:
    from scan_ct_logs_compact import scan_ct_logs_compact
except ImportError:
    print("[!] Failed to import scan_ct_logs_compact")

# Import WHOIS (Newly Created File)
try:
    from whois_lookup_deep import whois_lookup_deep
except ImportError:
    print("[!] Failed to import whois_lookup_deep")


try:
    from check_found_emails import  check_found_emails
    from extract_forensic_details import extract_forensic_details
except ImportError as e:
    print(f"[!] Critical Import Error: {e}")

print("[+] Import sequence completed.\n")

app = Flask(__name__)
app.config['JSON_SORT_KEYS'] = False
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024

# Create necessary directories
os.makedirs('reports', exist_ok=True)
os.makedirs('scans', exist_ok=True)

scan_results = {}
scan_history = []


def calculate_risk_score(data):
    """Calculate composite risk score from intelligence"""
    score = 0
    factors = []

    try:
        # 1. WAF Detection
        waf_results = data.get('waf', {}).get('results', [])
        unprotected = sum(1 for r in waf_results if not r.get('has_waf'))
        if unprotected > 0:
            score += 30
            factors.append(f"🚨 {unprotected} endpoint(s) without WAF protection")

        # 2. Breaches
        breaches = data.get('breaches', {}).get('results', [])
        pwned = [b for b in breaches if b.get('is_pwned')]
        if pwned:
            critical_count = sum(1 for b in pwned if b.get('risk_level') == 'CRITICAL')
            score += min(critical_count * 15, 30)
            factors.append(f"🔴 {len(pwned)} compromised credential(s)")

        # 3. Open Directories
        dirs = data.get('directories', {}).get('scan_summary', {})
        critical_dirs = dirs.get('critical_directories', 0)
        if critical_dirs > 0:
            score += min(critical_dirs * 10, 25)
            factors.append(f"📁 {critical_dirs} critical directories exposed")

        # 4. VirusTotal
        vt_data = data.get('virustotal', {})
        detections = vt_data.get('detections', {})
        malicious = detections.get('malicious', 0)
        if malicious > 0:
            score += min(malicious * 10, 25)
            factors.append(f"⚠️ {malicious} vendors flagged this domain")

        # 5. Email Infrastructure Risks
        email_enum = data.get('email_enumeration', {})
        email_risks = email_enum.get('infrastructure_risks', {})
        critical_email_risks = email_risks.get('critical_risks', 0)
        risky_emails = email_enum.get('stats', {}).get('risky_emails', 0)
        
        if critical_email_risks > 0 or risky_emails > 0:
            score += min((critical_email_risks * 5) + (risky_emails * 2), 20)
            factors.append(f"📧 Email infrastructure issues: {critical_email_risks} critical, {risky_emails} risky")

        # 6. Domain Age
        whois_data = data.get('whois', {})
        created_date = whois_data.get('dates', {}).get('created', '')
        if created_date and created_date != 'N/A':
            try:
                created = datetime.datetime.strptime(created_date, '%Y-%m-%d')
                age_days = (datetime.datetime.now() - created).days
                if age_days < 365:
                    score += 10
                    factors.append(f"🆕 Domain is less than 1 year old")
            except:
                pass

        if not factors:
            factors.append("✅ No significant risk factors detected")

        risk_level = 'CRITICAL' if score >= 70 else 'HIGH' if score >= 50 else 'MEDIUM' if score >= 30 else 'LOW'

        return {
            'score': min(score, 100),
            'level': risk_level,
            'factors': factors[:5]
        }
    except Exception as e:
        print(f"Risk calculation error: {e}")
        return {'score': 0, 'level': 'LOW', 'factors': ['Unable to calculate']}


def run_full_scan(domain, api_keys=None):
    """Execute all scanning modules"""
    print(f"\n{'='*70}")
    print(f"[START] FULL OSINT SCAN FOR: {domain}")
    print(f"{'='*70}\n")
    shodan_key = os.getenv('SHODAN_API_KEY')
    vt_key = os.getenv('VT_API_KEY')

    domain = domain.strip().replace('http://', '').replace('https://', '').split('/')[0].lower()

    if api_keys is None:
        api_keys = {}

    results = {
        'target': domain,
        'timestamp': datetime.datetime.now().isoformat(),
        'scan_status': 'running',
        'modules_completed': 0,
        'modules_total': 11
    }

    try:
        # 1. Certificate Transparency
        print("[1/13] Certificate Transparency Logs...")
        try:
            ct_result = scan_ct_logs_compact(domain)
            results['certificates'] = ct_result.get('certificates', [])
            results['subdomain_count'] = ct_result.get('subdomain_count', 0)
            results['modules_completed'] += 1
        except Exception as e:
            print(f"    ✗ Error: {e}")
            results['certificates'] = []
            results['subdomain_count'] = 0

        # 2. DNS Reconnaissance
        print("[2/13] DNS Reconnaissance...")
        try:
            dns_result = dns_recon_passive(domain)
            results['dns'] = dns_result
            results['modules_completed'] += 1
        except Exception as e:
            print(f"    ✗ Error: {e}")
            results['dns'] = {'status': 'error'}

        # 3. WHOIS Lookup
        print("[3/13] WHOIS Lookup...")
        try:
            whois_result = whois_lookup_deep(domain)
            results['whois'] = whois_result
            results['modules_completed'] += 1
        except Exception as e:
            print(f"    ✗ Error: {e}")
            results['whois'] = {'status': 'error'}

        # 4. Shodan
        print("[4/13] Shodan Intelligence...")
        try:
            shodan_key = api_keys.get('shodan', '')
            shodan_result = get_shodan_profile(domain, shodan_key)
            results['shodan'] = shodan_result
            results['modules_completed'] += 1
        except Exception as e:
            print(f"    ✗ Error: {e}")
            results['shodan'] = {'status': 'error'}

        # 5. VirusTotal
        print("[5/13] VirusTotal Reputation...")
        try:
            vt_key = api_keys.get('virustotal', '')
            vt_result = check_virustotal_critical(domain, vt_key)
            results['virustotal'] = vt_result
            results['modules_completed'] += 1
        except Exception as e:
            print(f"    ✗ Error: {e}")
            results['virustotal'] = {'status': 'error'}

        # Get subdomains for next modules
        subdomain_list = []
        for cert in results.get('certificates', []):
            subdomain_list.extend(cert.get('subdomains', []))
        unique_subs = list(set(subdomain_list))[:15]

        # 6. WAF Detection
        print("[6/13] WAF Detection...")
        try:
            waf_result = detect_waf(domain, unique_subs)
            results['waf'] = waf_result
            results['modules_completed'] += 1
        except Exception as e:
            print(f"    ✗ Error: {e}")
            results['waf'] = {'status': 'error', 'results': []}

        # 7. Directory Enumeration
        print("[7/13] Directory Enumeration...")
        try:
            dir_result = enumerate_directories_optimized(domain, unique_subs, max_threads=12)
            results['directories'] = dir_result
            results['modules_completed'] += 1
        except Exception as e:
            print(f"    ✗ Error: {e}")
            results['directories'] = {'status': 'error', 'results': []}

        # 8. Email Enumeration
        # --- [8/13] Email Enumeration ---
       # --- [8/11] Email Analysis ---
        print("[8/11] Email Validation...")
        try:
            # Gather emails from forensics to validate, or pass an empty list if discovery is separate
            raw_emails = []
            if 'forensics' in results:
                for res in results['forensics'].get('results', []):
                    raw_emails.extend(res.get('emails', []))
            
            # Use the new function name
            email_res = check_found_emails(domain, list(set(raw_emails)))
            results['email_enumeration'] = email_res.get('data', {}) 
            results['modules_completed'] += 1
        except Exception as e:
            print(f"    ✗ Email Error: {e}")
            results['email_enumeration'] = {}

            # --- [9/11] Forensic Extraction ---
        print("[9/11] Forensic Extraction...")
        try:
            forensic_result = extract_forensic_details(domain, unique_subs)
            results['forensics'] = forensic_result #
            results['modules_completed'] += 1
        except Exception as e:
            print(f"    ✗ Forensics Error: {e}")
            results['forensics'] = {'results': []} # Initialize with empty results to prevent KeyError

        # --- [10/11] Breach Checking ---
        print("[10/11] Breach Checking...")
        try:
            found_emails = []
            # Using .get() is safer to avoid the KeyError you experienced
            for forensic_res in results.get('forensics', {}).get('results', []):
                found_emails.extend(forensic_res.get('emails', []))
            
            unique_emails = list(set(found_emails))
            results['breaches'] = check_breach_leakcheck_public(unique_emails) #
            results['modules_completed'] += 1
        except Exception as e:
            print(f"    ✗ Breach Check Error: {e}")

        print("[10/13] Breach Checking...")
        try:
            found_emails = []
            
            # Use .get() with an empty dictionary default to avoid KeyError
            forensics_data = results.get('forensics', {})
            for forensic_res in forensics_data.get('results', []):
                found_emails.extend(forensic_res.get('emails', []))
                
            # Also pull from email enumeration if it exists
            email_intel = results.get('email_enumeration', {})
            for email_data in email_intel.get('validation_results', []):
                found_emails.append(email_data.get('email', ''))
            
            unique_emails = list(set(found_emails))
            results['breaches'] = check_breach_leakcheck_public(unique_emails)
            results['modules_completed'] += 1
        except Exception as e:
            print(f"    ✗ Error in Breach Check: {e}")
            results['breaches'] = {'status': 'error', 'results': []}

        # 11. Risk Calculation
        print("[13/13] Risk Calculation...")
        risk_data = calculate_risk_score(results)
        results['risk_score'] = risk_data
        results['modules_completed'] += 1

        # ========== GENERATE PDF REPORT ==========
        print("[PDF] Generating PDF Report...")
        try:
            # Call your existing generate_premium_report function
            pdf_path = generate_premium_report(results)
            
            if pdf_path and os.path.exists(pdf_path):
                results['report_file'] = pdf_path
                print(f"[✓] PDF Generated: {pdf_path}")
            else:
                print(f"[✗] PDF generation returned invalid path: {pdf_path}")
                results['report_file'] = None
                
        except Exception as e:
            print(f"[✗] PDF Generation Failed: {e}")
            traceback.print_exc()
            results['report_file'] = None

        results['scan_status'] = 'completed'
        
        # Save JSON dump
        try:
            timestamp_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            dump_dir = "scans"
            os.makedirs(dump_dir, exist_ok=True)
            dump_filename = os.path.join(dump_dir, f"{domain}_{timestamp_str}_dump.json")
            
            with open(dump_filename, 'w') as f:
                json.dump(results, f, indent=4, default=str)
            
            results['dump_file'] = dump_filename
            print(f"[✓] Dump saved: {dump_filename}")
        except Exception as e:
            print(f"[✗] Failed to save dump: {e}")

        # Save to history
        scan_history.append({
            'target': domain,
            'timestamp': results['timestamp'],
            'risk_score': results['risk_score']['score'],
            'risk_level': results['risk_score']['level']
        })

        print(f"\n{'='*70}")
        print(f"[COMPLETE] Scan finished successfully!")
        print(f"Risk Score: {results['risk_score']['score']}/100 ({results['risk_score']['level']})")
        print(f"Report File: {results.get('report_file', 'Not generated')}")
        print(f"{'='*70}\n")

    except Exception as e:
        print(f"\n[ERROR] Scan failed: {e}")
        traceback.print_exc()
        results['scan_status'] = 'failed'
        results['error'] = str(e)

    scan_results[domain] = results
    return results


# ============ API ROUTES ============

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/passive-scan', methods=['POST'])
def passive_scan():
    """Main scan endpoint"""
    data = request.json
    target = data.get('target', '').strip()
    api_keys = data.get('api_keys', {})

    if not target:
        return jsonify({'error': 'No target domain provided'}), 400

    try:
        results = run_full_scan(target, api_keys)
        return jsonify(results), 200
    except Exception as e:
        print(f"[API Error]: {e}")
        traceback.print_exc()
        return jsonify({
            'error': str(e),
            'target': target,
            'scan_status': 'failed'
        }), 500

@app.route('/api/scan-history', methods=['GET'])
def get_history():
    """Retrieve scan history"""
    return jsonify({
        'status': 'success',
        'count': len(scan_history),
        'history': scan_history[-50:]
    })

@app.route('/api/download-report/<domain>', methods=['GET'])
def download_report(domain):
    """Download PDF report - FIXED VERSION"""
    try:
        print(f"\n[DOWNLOAD] Request for domain: {domain}")
        
        # Step 1: Check if scan exists
        if domain not in scan_results:
            print(f"[✗] Scan not found for domain: {domain}")
            print(f"[DEBUG] Available scans: {list(scan_results.keys())}")
            return jsonify({'error': 'Scan not found'}), 404

        # Step 2: Get report file path from results
        report_file = scan_results[domain].get('report_file')
        print(f"[*] Report file from results: {report_file}")
        
        if not report_file:
            print(f"[✗] No report file path stored in results")
            return jsonify({'error': 'Report not generated'}), 404
        
        # Step 3: Convert to absolute path if needed
        if not os.path.isabs(report_file):
            report_file = os.path.abspath(report_file)
        
        print(f"[*] Absolute path: {report_file}")
        
        # Step 4: Check if file exists
        if not os.path.exists(report_file):
            print(f"[✗] Report file does not exist: {report_file}")
            print(f"[DEBUG] Current working directory: {os.getcwd()}")
            print(f"[DEBUG] Directory contents: {os.listdir('.')}")
            return jsonify({'error': 'Report file not found on server'}), 404

        # Step 5: Check file size
        file_size = os.path.getsize(report_file)
        print(f"[✓] File found! Size: {file_size} bytes")
        
        # Step 6: Send file
        print(f"[✓] Sending file to client...")
        return send_file(
            report_file, 
            as_attachment=True,
            download_name=f"{domain}_security_report.pdf",
            mimetype='application/pdf'
        )
        
    except Exception as e:
        print(f"[✗] Download error: {e}")
        traceback.print_exc()
        return jsonify({'error': f'Download failed: {str(e)}'}), 500

@app.route('/api/scan-status/<domain>', methods=['GET'])
def get_scan_status(domain):
    """Get scan status"""
    if domain in scan_results:
        return jsonify(scan_results[domain])
    return jsonify({'error': 'Scan not found'}), 404

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def server_error(error):
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    print("\n[*] Starting OSINT Intelligence Platform...")
    print("[*] Reports folder: reports/")
    print("[*] Scans folder: scans/")
    print("[*] Server running on http://localhost:5000\n")
    app.run(debug=True, host='0.0.0.0', port=5000, use_reloader=False, threaded=True)
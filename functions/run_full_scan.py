import sys
import datetime
import traceback

# --- 1. IMPORTS (Matching your Image File Names exactly) ---
try:
    print("[*] Importing modules...")
    from scan_ct_logs_compact import scan_ct_logs
    from dns_recon_advanced import dns_recon_advanced
    from check_shodan_enhanced import check_shodan_enhanced
    from check_virustotal_advanced import check_virustotal_advanced
    from whois_lookup_deep import whois_lookup_deep
    from detect_waf import detect_waf
    from enumerate_directories import enumerate_directories
    from extract_forensic_details import extract_forensic_details
    from check_breach_leakcheck_public import check_breach_leakcheck_public
    from def_calculate_risk import calculate_risk_score
    from generate_pdf_report import generate_premium_report
    from run_passive_scan import run_passive_scan
    print("[+] All modules imported successfully.\n")

    
except ImportError as e:
    print(f"[!] CRITICAL ERROR: Missing module. {e}")
    print("Ensure all 11 files are in the same directory.")
    sys.exit(1)


# def run_passive_scan(target):
#     """
#     Executes ALL 11 modules with verbose logging for each step.
#     """
#     print(f"{'='*70}")
#     print(f"[START] FULL OSINT SCAN FOR: {target}")
#     print(f"{'='*70}\n")
    
#     # Clean input
#     domain = target.strip().replace('http://', '').replace('https://', '').split('/')[0].lower()
    
#     # Master Results Dictionary
#     results = {
#         'target': domain,
#         'timestamp': datetime.datetime.now().isoformat(),
#         'status': 'running'
#     }
    
#     try:
#         # ==========================================
#         # PHASE 1: DISCOVERY & RECON
#         # ==========================================
#         print(f"[PHASE 1] Infrastructure Discovery")

#         # 1. Subdomains
#         print(f"[*] Executing: scan_ct_logs (Subdomain Discovery)...")
#         results['subdomains'] = scan_ct_logs(domain).get('subdomains', [])
#         print(f"    > Found {len(results['subdomains'])} subdomains.")
        
#         # 2. DNS
#         print(f"[*] Executing: dns_recon_advanced (DNS Records)...")
#         results['dns'] = dns_recon_advanced(domain)
        
#         # 3. WHOIS
#         print(f"[*] Executing: whois_lookup_deep (Registration Info)...")
#         results['whois'] = whois_lookup_deep(domain)
        
#         # 4. Shodan
#         print(f"[*] Executing: check_shodan_enhanced (Infrastructure)...")
#         results['shodan'] = check_shodan_enhanced(domain)
        
#         # 5. VirusTotal
#         print(f"[*] Executing: check_virustotal_advanced (Reputation)...")
#         results['virustotal'] = check_virustotal_advanced(domain, api_key=None)


#         # ==========================================
#         # PHASE 2: DEEP ENUMERATION
#         # ==========================================
#         print(f"\n[PHASE 2] Deep Enumeration")
        
#         # Create target list (Main Domain + Subdomains)
#         target_list = [domain] + results['subdomains'][:20]
#         print(f"[*] Preparing to scan {len(target_list)} hosts...")

#         # 6. WAF Detection
#         print(f"[*] Executing: detect_waf (Firewall Detection)...")
#         results['waf'] = detect_waf(domain, target_list)
        
#         # 7. Directory Enumeration
#         print(f"[*] Executing: enumerate_directories (Hidden Files)...")
#         results['directories'] = enumerate_directories(domain, target_list)
        
#         # 8. Forensic Extraction
#         print(f"[*] Executing: extract_forensic_details (Web Scraping)...")
#         results['forensics'] = extract_forensic_details(domain, target_list)


#         # ==========================================
#         # PHASE 3: ANALYSIS
#         # ==========================================
#         print(f"\n[PHASE 3] Analysis & Breaches")

#         # Prepare emails
#         found_emails = []
#         for res in results.get('forensics', {}).get('results', []):
#             found_emails.extend(res.get('emails', []))
#         unique_emails = list(set(found_emails))
#         print(f"[*] Found {len(unique_emails)} unique emails to check.")
        
#         # 9. Breach Check
#         print(f"[*] Executing: check_breach_leakcheck_public (Dark Web Check)...")
#         results['breaches'] = check_breach_leakcheck_public(unique_emails)
        
#         # 10. Risk Calculation
#         print(f"[*] Executing: calculate_risk_score (Risk Assessment)...")
#         results['risk_score'] = calculate_risk_score(results)


#         # ==========================================
#         # PHASE 4: REPORTING
#         # ==========================================
#         print(f"\n[PHASE 4] Reporting")

#         # 11. PDF Generation
#         print(f"[*] Executing: generate_premium_report (PDF Generation)...")
#         pdf_path = generate_premium_report(results)
#         results['report_file'] = pdf_path
        
#         results['status'] = 'completed'
#         print(f"\n{'='*70}")
#         print(f"[DONE] Scan Complete.")
#         print(f"Risk Score: {results['risk_score']['score']}/100")
#         print(f"Report Generated: {pdf_path}")
#         print(f"{'='*70}\n")

#     except Exception as e:
#         print(f"\n[ERROR] Execution Failed: {e}")
#         traceback.print_exc()
#         results['error'] = str(e)
    
#     return results



def run_full_scan(domain, api_keys=None):
    """Execute all scanning modules and save dump to file"""
    print(f"\n{'='*70}")
    print(f"[START] FULL OSINT SCAN FOR: {domain}")
    print(f"{'='*70}\n")

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
        print("[1/11] Certificate Transparency Logs...")
        try:
            ct_result = scan_ct_logs_compact(domain)
            results['certificates'] = ct_result.get('certificates', [])
            results['subdomain_count'] = ct_result.get('subdomain_count', 0)
            results['modules_completed'] += 1
            print(f"    ✓ Found {ct_result.get('subdomain_count', 0)} subdomains\n")
        except Exception as e:
            print(f"    ✗ Error: {e}\n")
            results['certificates'] = []
            results['subdomain_count'] = 0

        # 2. DNS Reconnaissance
        print("[2/11] DNS Reconnaissance...")
        try:
            dns_result = dns_recon_passive(domain)
            results['dns'] = dns_result
            results['modules_completed'] += 1
            print(f"    ✓ DNS reconnaissance complete\n")
        except Exception as e:
            print(f"    ✗ Error: {e}\n")
            results['dns'] = {'status': 'error'}

        # 3. WHOIS Lookup
        print("[3/11] WHOIS Lookup...")
        try:
            whois_result = whois_lookup_deep(domain)
            results['whois'] = whois_result
            results['modules_completed'] += 1
            print(f"    ✓ WHOIS lookup complete\n")
        except Exception as e:
            print(f"    ✗ Error: {e}\n")
            results['whois'] = {'status': 'error'}

        # 4. Shodan
        print("[4/11] Shodan Intelligence...")
        try:
            shodan_key = api_keys.get('shodan', 'pHHlgpFt8Ka3Stb5UlTxcaEwciOeF2QM')
            shodan_result = get_shodan_profile(domain, shodan_key)
            results['shodan'] = shodan_result
            results['modules_completed'] += 1
            print(f"    ✓ Shodan scan complete\n")
        except Exception as e:
            print(f"    ✗ Error: {e}\n")
            results['shodan'] = {'status': 'error'}

        # 5. VirusTotal
        print("[5/11] VirusTotal Reputation...")
        try:
            vt_key = api_keys.get('virustotal', '')
            vt_result = check_virustotal_critical(domain, vt_key)
            results['virustotal'] = vt_result
            results['modules_completed'] += 1
            print(f"    ✓ VirusTotal check complete\n")
        except Exception as e:
            print(f"    ✗ Error: {e}\n")
            results['virustotal'] = {'status': 'error'}

        # Get subdomains for deep scans
        subdomain_list = []
        for cert in results.get('certificates', []):
            subdomain_list.extend(cert.get('subdomains', []))
        unique_subs = list(set(subdomain_list))[:20]

        # 6. WAF Detection
        print("[6/11] WAF Detection...")
        try:
            waf_result = detect_waf(domain, unique_subs)
            results['waf'] = waf_result
            results['modules_completed'] += 1
            print(f"    ✓ WAF detection complete\n")
        except Exception as e:
            print(f"    ✗ Error: {e}\n")
            results['waf'] = {'status': 'error', 'results': []}

        # 7. Directory Enumeration
        print("[7/11] Directory Enumeration...")
        try:
            dir_result = enumerate_directories_optimized(domain, unique_subs)
            results['directories'] = dir_result
            results['modules_completed'] += 1
            print(f"    ✓ Directory enumeration complete\n")
        except Exception as e:
            print(f"    ✗ Error: {e}\n")
            results['directories'] = {'status': 'error', 'results': []}

        # 8. Forensic Details
        print("[8/11] Forensic Extraction...")
        try:
            forensic_result = extract_forensic_details(domain, unique_subs)
            results['forensics'] = forensic_result
            results['modules_completed'] += 1
            print(f"    ✓ Forensic extraction complete\n")
        except Exception as e:
            print(f"    ✗ Error: {e}\n")
            results['forensics'] = {'status': 'error', 'results': []}

        # 9. Breach Check
        print("[9/11] Breach Checking...")
        try:
            found_emails = []
            for forensic_res in results.get('forensics', {}).get('results', []):
                found_emails.extend(forensic_res.get('emails', []))
            unique_emails = list(set(found_emails))

            breach_result = check_breach_leakcheck_public(unique_emails)
            results['breaches'] = breach_result
            results['modules_completed'] += 1
            print(f"    ✓ Breach check complete\n")
        except Exception as e:
            print(f"    ✗ Error: {e}\n")
            results['breaches'] = {'status': 'error', 'results': []}

        # 10. Risk Calculation
        print("[10/11] Risk Calculation...")
        risk_data = calculate_risk_score(results)
        results['risk_score'] = risk_data
        results['modules_completed'] += 1
        print(f"    ✓ Risk Score: {risk_data['score']}/100\n")

        # 11. PDF Report
        print("[11/11] PDF Report Generation...")
        try:
            pdf_path = generate_premium_report(results)
            results['report_file'] = pdf_path
            results['modules_completed'] += 1
            print(f"    ✓ Report saved: {pdf_path}\n")
        except Exception as e:
            print(f"    ✗ Error: {e}\n")
            results['report_file'] = None

        results['scan_status'] = 'completed'

        scan_history.append({
            'target': domain,
            'timestamp': results['timestamp'],
            'risk_score': results['risk_score']['score'],
            'risk_level': results['risk_score']['level']
        })

        # ==================================================================
        #  FILE DUMP: SAVE RAW DATA TO JSON
        # ==================================================================
        try:
            # Create a 'scans' directory if it doesn't exist
            dump_dir = "scans"
            if not os.path.exists(dump_dir):
                os.makedirs(dump_dir)

            # Generate a filename with timestamp
            timestamp_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            dump_filename = f"{domain}_{timestamp_str}_dump.json"
            dump_path = os.path.join(dump_dir, dump_filename)

            # Save the JSON data
            with open(dump_path, 'w') as f:
                json.dump(results, f, indent=4, default=str)

            print("\n" + "#" * 80)
            print(f" [SUCCESS] RAW DATA DUMP SAVED TO FILE")
            print(f" Location: {dump_path}")
            print("#" * 80 + "\n")
            
            # Store the dump path in results so the frontend could theoretically access it later
            results['dump_file'] = dump_path

        except Exception as dump_error:
            print(f"[!] Failed to save data dump to file: {dump_error}")
        # ==================================================================

        print(f"\n{'='*70}")
        print(f"[COMPLETE] Scan finished successfully!")
        print(f"{'='*70}\n")

    except Exception as e:
        print(f"\n[ERROR] Scan failed: {e}")
        traceback.print_exc()
        results['scan_status'] = 'failed'
        results['error'] = str(e)

    scan_results[domain] = results
    return results
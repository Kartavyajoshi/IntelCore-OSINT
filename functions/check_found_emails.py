# import requests
# import re
# import dns.resolver
# import socket
# import smtplib
# from concurrent.futures import ThreadPoolExecutor, as_completed
# import urllib3

# urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# def enumerate_emails_enhanced(domain):
#     """
#     Enhanced Email Enumeration with validation and pattern analysis
#     Returns: Comprehensive email intelligence including validity checks
#     """
#     print(f"[*] Starting Enhanced Email Enumeration for: {domain}...")
    
#     results = {
#         'domain': domain,
#         'emails_found': [],
#         'email_patterns': [],
#         'mx_records': [],
#         'validation_results': [],
#         'stats': {
#             'total_emails': 0,
#             'valid_emails': 0,
#             'invalid_emails': 0,
#             'risky_emails': 0
#         }
#     }

#     # ============================================================
#     # PHASE 1: Email Format Pattern Analysis
#     # ============================================================
#     print(f"    [*] Phase 1: Analyzing email patterns...")
    
#     patterns = {
#         'firstname.lastname': r'([a-z]+)\.([a-z]+)@',
#         'firstnamelastname': r'([a-z]+)([a-z]+)@',
#         'first_lastname': r'([a-z]+)_([a-z]+)@',
#         'first_initial': r'([a-z])\.?([a-z]+)@',
#         'firstname_initial': r'([a-z]+)\.?([a-z])@',
#         'full_name': r'([a-z\s]+)@',
#     }
    
#     results['email_patterns'] = list(patterns.keys())

#     # ============================================================
#     # PHASE 2: MX Record Analysis
#     # ============================================================
#     print(f"    [*] Phase 2: Analyzing mail servers...")
    
#     try:
#         mx_records = dns.resolver.resolve(domain, 'MX')
#         for mx in mx_records:
#             priority = mx.preference
#             mail_server = str(mx.exchange).rstrip('.')
            
#             results['mx_records'].append({
#                 'mail_server': mail_server,
#                 'priority': priority,
#                 'type': get_mail_provider_type(mail_server)
#             })
#         print(f"    [✓] Found {len(results['mx_records'])} MX records")
#     except Exception as e:
#         print(f"    [!] MX lookup failed: {e}")
#         results['mx_records'] = []

#     # ============================================================
#     # PHASE 3: Email Discovery from Multiple Sources
#     # ============================================================
#     print(f"    [*] Phase 3: Discovering emails from public sources...")
    
#     discovered_emails = set()
    
#     # Source 1: Google Search (common email patterns)
#     try:
#         search_patterns = [
#             f'site:{domain} inurl:mail OR inurl:contact OR inurl:team',
#             f'"{domain}" email OR contact',
#             f'site:{domain} "admin@" OR "info@" OR "support@" OR "contact@"'
#         ]
        
#         # Common business email formats
#         common_prefixes = [
#             'admin', 'support', 'contact', 'info', 'sales', 'hello', 'team',
#             'noreply', 'postmaster', 'webmaster', 'security', 'abuse',
#             'billing', 'hr', 'jobs', 'career', 'press', 'media', 'marketing'
#         ]
        
#         for prefix in common_prefixes:
#             email = f"{prefix}@{domain}"
#             discovered_emails.add(email)
#     except Exception as e:
#         print(f"    [!] Pattern discovery error: {e}")

#     # Source 2: Hunter.io-like pattern generation (free alternative)
#     try:
#         # Generate likely email patterns based on common formats
#         common_names = ['john', 'jane', 'admin', 'support', 'contact', 'info', 'hello']
#         for name in common_names:
#             for suffix in ['', '1', '2', '3', '_support', '_admin']:
#                 email = f"{name}{suffix}@{domain}"
#                 discovered_emails.add(email)
#     except Exception as e:
#         print(f"    [!] Pattern generation error: {e}")

#     # ============================================================
#     # PHASE 4: Email Validation
#     # ============================================================
#     print(f"    [*] Phase 4: Validating {len(discovered_emails)} emails...")
    
#     def validate_email(email):
#         """Validate single email with multiple checks"""
#         validation = {
#             'email': email,
#             'valid': False,
#             'smtp_check': False,
#             'format_valid': False,
#             'format_score': 0,
#             'risks': []
#         }

#         # Check 1: Format Validation
#         email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
#         if re.match(email_regex, email):
#             validation['format_valid'] = True
#             validation['format_score'] = 95
#         else:
#             validation['format_valid'] = False
#             validation['risks'].append('Invalid email format')
#             return validation

#         # Check 2: Domain Validation
#         try:
#             mail_domain = email.split('@')[1]
#             socket.gethostbyname(mail_domain)
#             validation['format_score'] = 100
#         except socket.gaierror:
#             validation['risks'].append('Domain cannot be resolved')

#         # Check 3: SMTP Validation (optional - slower)
#         try:
#             validation['smtp_check'] = check_smtp_validity(email)
#             if validation['smtp_check']:
#                 validation['valid'] = True
#         except Exception as e:
#             # SMTP check failed, but email might still be valid
#             validation['valid'] = validation['format_valid']

#         # Check 4: Risk Assessment
#         if 'noreply' in email or 'no-reply' in email:
#             validation['risks'].append('Automated/noreply address')
#         if 'test' in email or 'admin' in email:
#             validation['risks'].append('Likely test or admin account')
#         if email.count('.') > 2:
#             validation['risks'].append('Unusual number of dots')

#         return validation

#     def check_smtp_validity(email, timeout=5):
#         """Check email validity via SMTP (be careful with rate limiting)"""
#         try:
#             domain = email.split('@')[1]
            
#             # Get MX records
#             mx_records = dns.resolver.resolve(domain, 'MX')
#             mx_host = str(mx_records[0].exchange)

#             # Connect to SMTP server
#             with smtplib.SMTP(mx_host, timeout=timeout) as server:
#                 server.ehlo()
#                 # Check if server supports verification
#                 try:
#                     code = server.verify(email)
#                     return code == 250
#                 except:
#                     # If verify not supported, assume valid if connected
#                     return True
#         except Exception as e:
#             return False

#     # Validate emails with threading for speed
#     with ThreadPoolExecutor(max_workers=5) as executor:
#         futures = {executor.submit(validate_email, email): email for email in discovered_emails}
        
#         for future in as_completed(futures):
#             try:
#                 validation = future.result()
#                 if validation['format_valid']:
#                     results['validation_results'].append(validation)
#                     results['emails_found'].append(validation['email'])
                    
#                     if validation['valid']:
#                         results['stats']['valid_emails'] += 1
#                     else:
#                         results['stats']['invalid_emails'] += 1
                    
#                     if validation['risks']:
#                         results['stats']['risky_emails'] += 1
#             except Exception as e:
#                 print(f"    [!] Validation error: {e}")

#     results['stats']['total_emails'] = len(results['emails_found'])

#     # ============================================================
#     # PHASE 5: Email Intelligence
#     # ============================================================
#     print(f"    [*] Phase 5: Generating email intelligence...")
    
#     # Group emails by pattern
#     email_groups = {
#         'admin_accounts': [],
#         'support_accounts': [],
#         'personal_accounts': [],
#         'service_accounts': [],
#         'unknown': []
#     }

#     for email_data in results['validation_results']:
#         email = email_data['email']
#         prefix = email.split('@')[0].lower()
        
#         if any(x in prefix for x in ['admin', 'administrator', 'root']):
#             email_groups['admin_accounts'].append(email_data)
#         elif any(x in prefix for x in ['support', 'help', 'contact']):
#             email_groups['support_accounts'].append(email_data)
#         elif any(x in prefix for x in ['noreply', 'no-reply', 'donotreply', 'automated']):
#             email_groups['service_accounts'].append(email_data)
#         elif re.match(r'^[a-z]+\.[a-z]+', prefix):
#             email_groups['personal_accounts'].append(email_data)
#         else:
#             email_groups['unknown'].append(email_data)

#     results['email_groups'] = email_groups

#     # ============================================================
#     # PHASE 6: Risk Assessment
#     # ============================================================
#     print(f"    [*] Phase 6: Assessing email infrastructure risks...")
    
#     risks = {
#         'no_mx_records': len(results['mx_records']) == 0,
#         'single_mx': len(results['mx_records']) == 1,
#         'no_spf': not check_spf_record(domain),
#         'no_dmarc': not check_dmarc_record(domain),
#         'high_risk_emails': results['stats']['risky_emails'] > 0
#     }

#     results['infrastructure_risks'] = {
#         'critical_risks': sum(1 for v in risks.values() if v),
#         'risk_details': risks
#     }

#     print(f"    [✓] Email enumeration complete: {results['stats']['total_emails']} emails found")
    
#     return {
#         'status': 'success',
#         'target': domain,
#         'data': results,
#         'timestamp': str(__import__('datetime').datetime.now().isoformat())
#     }


# def get_mail_provider_type(mail_server):
#     """Identify mail provider type from MX record"""
#     mail_server_lower = mail_server.lower()
    
#     providers = {
#         'Google': ['google', 'gmail'],
#         'Microsoft': ['outlook', 'microsoft', 'hotmail', 'live'],
#         'Protonmail': ['protonmail', 'pm'],
#         'AWS': ['amazonses'],
#         'SendGrid': ['sendgrid'],
#         'Mailgun': ['mailgun'],
#         'Zoho': ['zoho'],
#         'Self-Hosted': ['mail']
#     }
    
#     for provider, keywords in providers.items():
#         if any(keyword in mail_server_lower for keyword in keywords):
#             return provider
    
#     return 'Unknown'


# def check_spf_record(domain):
#     """Check if domain has SPF record"""
#     try:
#         txt_records = dns.resolver.resolve(domain, 'TXT')
#         for record in txt_records:
#             if 'v=spf1' in str(record):
#                 return True
#     except:
#         pass
#     return False


# def check_dmarc_record(domain):
#     """Check if domain has DMARC record"""
#     try:
#         dmarc_domain = f"_dmarc.{domain}"
#         txt_records = dns.resolver.resolve(dmarc_domain, 'TXT')
#         for record in txt_records:
#             if 'v=DMARC1' in str(record):
#                 return True
#     except:
#         pass
#     return False



import re
import dns.resolver
import socket
import smtplib
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib3
import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def check_found_emails(domain, emails_to_check):
    """
    Modified to ONLY check and validate a specific list of emails.
    Removes the discovery/guessing phase.
    """
    print(f"[*] Starting Analysis for {len(emails_to_check)} emails on domain: {domain}...")
    
    results = {
        'domain': domain,
        'emails_analyzed': [],
        'mx_records': [],
        'validation_results': [],
        'stats': {
            'total_input': len(emails_to_check),
            'valid_emails': 0,
            'invalid_emails': 0,
            'risky_emails': 0
        }
    }

    # ============================================================
    # PHASE 1: MX Record Analysis (Required for SMTP Checks)
    # ============================================================
    print(f"    [*] Phase 1: Fetching MX records for validation...")
    
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        for mx in mx_records:
            priority = mx.preference
            mail_server = str(mx.exchange).rstrip('.')
            
            results['mx_records'].append({
                'mail_server': mail_server,
                'priority': priority,
                'type': get_mail_provider_type(mail_server)
            })
        print(f"    [✓] Found {len(results['mx_records'])} MX records")
    except Exception as e:
        print(f"    [!] MX lookup failed: {e}")
        results['mx_records'] = []

    # ============================================================
    # PHASE 2: Validation Logic (Defined Internal Helpers)
    # ============================================================
    
    def check_smtp_validity(email, timeout=5):
        """Check email validity via SMTP"""
        try:
            # Use the already fetched MX records to save time
            if not results['mx_records']:
                return False
                
            mx_host = results['mx_records'][0]['mail_server']

            # Connect to SMTP server
            with smtplib.SMTP(mx_host, timeout=timeout) as server:
                server.ehlo()
                # Check if server supports verification
                try:
                    code = server.verify(email)
                    return code == 250
                except:
                    # If verify not supported, assume valid if connected (catch-all behavior)
                    return True
        except Exception as e:
            return False

    def validate_email(email):
        """Validate single email with multiple checks"""
        validation = {
            'email': email,
            'valid': False,
            'smtp_check': False,
            'format_valid': False,
            'format_score': 0,
            'risks': []
        }

        # Check 1: Format Validation
        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if re.match(email_regex, email):
            validation['format_valid'] = True
            validation['format_score'] = 95
        else:
            validation['format_valid'] = False
            validation['risks'].append('Invalid email format')
            return validation

        # Check 2: Domain Consistency
        if email.split('@')[1] != domain:
             validation['risks'].append('Email domain does not match target domain')

        # Check 3: SMTP Validation
        try:
            validation['smtp_check'] = check_smtp_validity(email)
            if validation['smtp_check']:
                validation['valid'] = True
        except Exception:
            validation['valid'] = validation['format_valid']

        # Check 4: Risk Assessment
        if 'noreply' in email or 'no-reply' in email:
            validation['risks'].append('Automated/noreply address')
        if 'test' in email or 'admin' in email:
            validation['risks'].append('Likely test or admin account')
        
        return validation

    # ============================================================
    # PHASE 3: Execution (Threading)
    # ============================================================
    print(f"    [*] Phase 2: Validating input list...")
    
    # Remove duplicates
    unique_emails = list(set(emails_to_check))
    
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(validate_email, email): email for email in unique_emails}
        
        for future in as_completed(futures):
            try:
                validation = future.result()
                results['validation_results'].append(validation)
                results['emails_analyzed'].append(validation['email'])
                
                if validation['valid']:
                    results['stats']['valid_emails'] += 1
                else:
                    results['stats']['invalid_emails'] += 1
                
                if validation['risks']:
                    results['stats']['risky_emails'] += 1
            except Exception as e:
                print(f"    [!] Validation error for an email: {e}")

    # ============================================================
    # PHASE 4: Intelligence Grouping
    # ============================================================
    print(f"    [*] Phase 3: Categorizing results...")
    
    email_groups = {
        'admin_accounts': [],
        'support_accounts': [],
        'personal_accounts': [],
        'service_accounts': [],
        'unknown': []
    }

    for email_data in results['validation_results']:
        email = email_data['email']
        prefix = email.split('@')[0].lower()
        
        if any(x in prefix for x in ['admin', 'administrator', 'root']):
            email_groups['admin_accounts'].append(email_data)
        elif any(x in prefix for x in ['support', 'help', 'contact']):
            email_groups['support_accounts'].append(email_data)
        elif any(x in prefix for x in ['noreply', 'no-reply', 'donotreply']):
            email_groups['service_accounts'].append(email_data)
        elif re.match(r'^[a-z]+\.[a-z]+', prefix):
            email_groups['personal_accounts'].append(email_data)
        else:
            email_groups['unknown'].append(email_data)

    results['email_groups'] = email_groups

    # ============================================================
    # PHASE 5: Infrastructure Check
    # ============================================================
    print(f"    [*] Phase 4: Checking Domain Security...")
    
    risks = {
        'no_mx_records': len(results['mx_records']) == 0,
        'no_spf': not check_spf_record(domain),
        'no_dmarc': not check_dmarc_record(domain),
    }

    results['infrastructure_risks'] = risks

    print(f"    [✓] Check complete. Validated {results['stats']['valid_emails']} of {results['stats']['total_input']} emails.")
    
    return {
        'status': 'success',
        'target': domain,
        'data': results,
        'timestamp': datetime.datetime.now().isoformat()
    }

# ==========================================
# Helper Functions (Keep these as they were)
# ==========================================

def get_mail_provider_type(mail_server):
    """Identify mail provider type from MX record"""
    mail_server_lower = mail_server.lower()
    providers = {
        'Google': ['google', 'gmail'], 'Microsoft': ['outlook', 'microsoft', 'hotmail', 'live'],
        'Protonmail': ['protonmail', 'pm'], 'AWS': ['amazonses'], 'Zoho': ['zoho']
    }
    for provider, keywords in providers.items():
        if any(keyword in mail_server_lower for keyword in keywords):
            return provider
    return 'Unknown'

def check_spf_record(domain):
    try:
        txt_records = dns.resolver.resolve(domain, 'TXT')
        for record in txt_records:
            if 'v=spf1' in str(record): return True
    except: pass
    return False

def check_dmarc_record(domain):
    try:
        dmarc_domain = f"_dmarc.{domain}"
        txt_records = dns.resolver.resolve(dmarc_domain, 'TXT')
        for record in txt_records:
            if 'v=DMARC1' in str(record): return True
    except: pass
    return False
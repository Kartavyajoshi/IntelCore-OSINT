# functions/phone_osint_platform.py
# Phone number intelligence using google-phonenumbers + reputation checks
# Educational Purpose Only - IntelCore-OSINT Framework

import re
import time
import requests
from typing import Dict, Any, List, Optional
from logger import get_logger

logger = get_logger()

TIMEOUT = 10
USER_AGENT = 'Mozilla/5.0 (compatible; IntelCore-OSINT/1.0)'

# ─────────────────────────────────────────────
# phonenumbers library (google libphonenumber)
# ─────────────────────────────────────────────

def _parse_phone_number(phone: str, default_region: str = 'US') -> Dict[str, Any]:
    """Parse and validate a phone number using google-phonenumbers."""
    result = {
        'raw_input': phone,
        'valid': False,
        'possible': False,
        'formatted_e164': None,
        'formatted_national': None,
        'formatted_international': None,
        'country_code': None,
        'country_name': None,
        'region_code': None,
        'number_type': None,
        'carrier': None,
        'timezone': None,
        'is_toll_free': False,
        'is_premium_rate': False,
        'is_mobile': False,
        'is_fixed_line': False,
        'is_voip': False,
    }

    try:
        import phonenumbers
        from phonenumbers import (
            geocoder, carrier, timezone as pn_timezone,
            NumberParseException, PhoneNumberType,
            PhoneNumberFormat, is_valid_number, is_possible_number
        )

        parsed = phonenumbers.parse(phone, default_region)
        result['valid'] = is_valid_number(parsed)
        result['possible'] = is_possible_number(parsed)

        if result['possible']:
            result['formatted_e164'] = phonenumbers.format_number(parsed, PhoneNumberFormat.E164)
            result['formatted_national'] = phonenumbers.format_number(parsed, PhoneNumberFormat.NATIONAL)
            result['formatted_international'] = phonenumbers.format_number(parsed, PhoneNumberFormat.INTERNATIONAL)
            result['country_code'] = parsed.country_code
            result['region_code'] = phonenumbers.region_code_for_number(parsed)

            try:
                import pycountry
                country = pycountry.countries.get(alpha_2=result['region_code'])
                result['country_name'] = country.name if country else result['region_code']
            except ImportError:
                result['country_name'] = result['region_code']

            # Number type
            num_type = phonenumbers.number_type(parsed)
            type_map = {
                PhoneNumberType.FIXED_LINE: 'FIXED_LINE',
                PhoneNumberType.MOBILE: 'MOBILE',
                PhoneNumberType.FIXED_LINE_OR_MOBILE: 'FIXED_LINE_OR_MOBILE',
                PhoneNumberType.TOLL_FREE: 'TOLL_FREE',
                PhoneNumberType.PREMIUM_RATE: 'PREMIUM_RATE',
                PhoneNumberType.VOIP: 'VOIP',
                PhoneNumberType.PERSONAL_NUMBER: 'PERSONAL_NUMBER',
                PhoneNumberType.PAGER: 'PAGER',
                PhoneNumberType.SHARED_COST: 'SHARED_COST',
                PhoneNumberType.UNKNOWN: 'UNKNOWN',
            }
            result['number_type'] = type_map.get(num_type, 'UNKNOWN')
            result['is_toll_free'] = num_type == PhoneNumberType.TOLL_FREE
            result['is_premium_rate'] = num_type == PhoneNumberType.PREMIUM_RATE
            result['is_mobile'] = num_type in (PhoneNumberType.MOBILE,
                                               PhoneNumberType.FIXED_LINE_OR_MOBILE)
            result['is_fixed_line'] = num_type in (PhoneNumberType.FIXED_LINE,
                                                   PhoneNumberType.FIXED_LINE_OR_MOBILE)
            result['is_voip'] = num_type == PhoneNumberType.VOIP

            # Carrier
            try:
                carrier_name = carrier.name_for_number(parsed, 'en')
                result['carrier'] = carrier_name if carrier_name else None
            except Exception:
                pass

            # Timezone
            try:
                tz = pn_timezone.time_zones_for_number(parsed)
                result['timezone'] = list(tz) if tz else None
            except Exception:
                pass

            # Geocoder
            try:
                geo = geocoder.description_for_number(parsed, 'en')
                result['geo_description'] = geo if geo else None
            except Exception:
                pass

    except ImportError:
        # Fallback if phonenumbers is not installed
        result['error'] = 'phonenumbers library not installed. Install with: pip install phonenumbers'
        result['valid'] = bool(re.match(r'^\+?[\d\s\-().]{7,20}$', phone))
        result['formatted_e164'] = re.sub(r'[^\d+]', '', phone)

    except Exception as e:
        result['error'] = str(e)

    return result


# ─────────────────────────────────────────────
# Reputation check via NumVerify (free tier)
# ─────────────────────────────────────────────

def _check_numverify(phone_e164: str) -> Dict[str, Any]:
    """Check phone number via NumVerify free lookup."""
    result = {'checked': False, 'valid': None, 'carrier': None, 'line_type': None,
              'country': None, 'location': None}
    try:
        # Strip + prefix
        number = phone_e164.lstrip('+')
        url = f"https://api.apilayer.com/number_verification/validate?number={number}"
        headers = {
            'User-Agent': USER_AGENT,
            'apikey': 'public'  # Free tier
        }
        resp = requests.get(url, headers=headers, timeout=TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            result['checked'] = True
            result['valid'] = data.get('valid')
            result['carrier'] = data.get('carrier')
            result['line_type'] = data.get('line_type')
            result['country'] = data.get('country_name')
            result['location'] = data.get('location')
    except Exception as e:
        result['error'] = str(e)
    return result


# ─────────────────────────────────────────────
# Scam/spam reputation via free community sources
# ─────────────────────────────────────────────

def _check_spam_reputation(phone_e164: str) -> Dict[str, Any]:
    """Check if the phone number is reported as spam/scam via community sources."""
    result = {
        'checked': False,
        'is_spam': False,
        'spam_score': 0,
        'report_count': 0,
        'categories': [],
        'sources_checked': []
    }

    # Clean the number
    clean_number = re.sub(r'[^\d]', '', phone_e164)
    if clean_number.startswith('0'):
        clean_number = clean_number[1:]

    # Check shouldianswer.com API (public)
    try:
        url = f"https://www.shouldianswer.com/phone-number/{clean_number}"
        resp = requests.get(url, timeout=TIMEOUT,
                            headers={'User-Agent': USER_AGENT})
        result['sources_checked'].append('shouldianswer.com')
        if resp.status_code == 200:
            result['checked'] = True
            body = resp.text.lower()
            if 'dangerous' in body or 'spam' in body or 'scam' in body:
                result['is_spam'] = True
                result['spam_score'] += 40
                if 'scam' in body:
                    result['categories'].append('Scam')
                if 'telemarketing' in body:
                    result['categories'].append('Telemarketing')
                if 'spam' in body:
                    result['categories'].append('Spam')
    except Exception:
        pass

    # Check callername (public)
    try:
        url = f"https://www.callername.com/{clean_number}"
        resp = requests.get(url, timeout=TIMEOUT,
                            headers={'User-Agent': USER_AGENT})
        result['sources_checked'].append('callername.com')
        if resp.status_code == 200:
            body = resp.text.lower()
            count_match = re.search(r'(\d+)\s*(?:report|complaint)', body)
            if count_match:
                count = int(count_match.group(1))
                result['report_count'] += count
                if count > 5:
                    result['is_spam'] = True
                    result['spam_score'] += min(count * 2, 30)
    except Exception:
        pass

    result['spam_score'] = min(result['spam_score'], 100)
    return result


# ─────────────────────────────────────────────
# Social platform presence checks for phone
# ─────────────────────────────────────────────

def _check_platform_registrations(phone_e164: str) -> List[Dict[str, Any]]:
    """
    Attempt to detect if the phone number is registered on any platforms
    by checking reset/verification endpoints (passive, no account creation).
    """
    results = []
    clean_number = re.sub(r'[^\d+]', '', phone_e164)

    # These checks are limited to platforms that expose this info
    # through their public-facing pages (not intrusive)
    platform_checks = [
        {
            'name': 'WhatsApp',
            'url': f'https://wa.me/{clean_number.lstrip("+")}',
            'check': 'status',
            'status_codes': [200]
        },
        {
            'name': 'Telegram',
            'url': f'https://t.me/{clean_number}',
            'check': 'content',
            'positive_strings': ['telegram', 'send message'],
            'status_codes': [200]
        },
    ]

    session = requests.Session()
    session.headers.update({'User-Agent': USER_AGENT})

    for platform in platform_checks:
        entry = {
            'platform': platform['name'],
            'url': platform['url'],
            'registered': False,
            'status_code': None
        }
        try:
            resp = session.get(platform['url'], timeout=TIMEOUT, allow_redirects=True)
            entry['status_code'] = resp.status_code

            if platform['check'] == 'status' and resp.status_code in platform['status_codes']:
                entry['registered'] = True
            elif platform['check'] == 'content':
                body = resp.text.lower()
                positive = platform.get('positive_strings', [])
                if resp.status_code in platform['status_codes'] and any(s in body for s in positive):
                    entry['registered'] = True
        except Exception:
            pass
        results.append(entry)

    return results


# ─────────────────────────────────────────────
# Main entry point
# ─────────────────────────────────────────────

def phone_osint_platform(phone: str, region: str = 'US') -> Dict[str, Any]:
    """
    Comprehensive OSINT analysis for a phone number.
    
    Checks:
    - Phone number validation and parsing (google-phonenumbers / libphonenumber)
    - Number type identification (mobile, fixed-line, VoIP, toll-free, premium-rate)
    - Carrier and geographic attribution
    - Community spam/scam reputation checks
    - Platform registration detection (WhatsApp, Telegram)
    
    Args:
        phone: Target phone number in any format (e.g. '+1-555-123-4567')
        region: Default region code for parsing (e.g. 'US', 'IN', 'GB')
        
    Returns:
        Comprehensive phone intelligence report
    """
    logger.info(f"[PHONE OSINT] Starting phone OSINT for: {phone}")
    start_time = time.time()

    results = {
        'phone': phone,
        'module': 'phone_osint_platform',
        'status': 'completed',
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'risk_level': 'LOW',
        'risk_score': 0,
        'parsing': {},
        'numverify': {},
        'spam_check': {},
        'platform_presence': [],
        'platforms_found': 0,
        'summary': {}
    }

    # 1. Parse and validate with google-phonenumbers
    results['parsing'] = _parse_phone_number(phone, region)
    phone_e164 = results['parsing'].get('formatted_e164') or re.sub(r'[^\d+]', '', phone)

    if not results['parsing'].get('valid') and not results['parsing'].get('possible'):
        results['status'] = 'invalid_number'
        return results

    # 2. NumVerify check
    if phone_e164:
        results['numverify'] = _check_numverify(phone_e164)

    # 3. Spam/scam reputation
    results['spam_check'] = _check_spam_reputation(phone_e164 or phone)

    # 4. Platform registrations
    results['platform_presence'] = _check_platform_registrations(phone_e164 or phone)
    results['platforms_found'] = sum(
        1 for p in results['platform_presence'] if p.get('registered')
    )

    # Risk scoring
    risk_score = 0

    if results['parsing'].get('is_premium_rate'):
        risk_score += 30

    spam_check = results['spam_check']
    if spam_check.get('is_spam'):
        risk_score += 25
    risk_score += min(spam_check.get('report_count', 0) * 2, 20)
    risk_score += spam_check.get('spam_score', 0) // 3

    if results['parsing'].get('is_voip'):
        risk_score += 10  # VoIP numbers are more easily disposable

    results['risk_score'] = min(risk_score, 100)
    results['risk_level'] = (
        'CRITICAL' if risk_score >= 60 else
        'HIGH'     if risk_score >= 35 else
        'MEDIUM'   if risk_score >= 15 else
        'LOW'
    )

    # Summary
    results['summary'] = {
        'phone': phone,
        'formatted': results['parsing'].get('formatted_international', phone),
        'valid': results['parsing'].get('valid', False),
        'country': results['parsing'].get('country_name', 'Unknown'),
        'carrier': results['parsing'].get('carrier', 'Unknown'),
        'number_type': results['parsing'].get('number_type', 'Unknown'),
        'is_spam': spam_check.get('is_spam', False),
        'spam_reports': spam_check.get('report_count', 0),
        'platforms_found': results['platforms_found'],
        'risk_level': results['risk_level'],
    }

    elapsed = round(time.time() - start_time, 2)
    results['elapsed_seconds'] = elapsed
    logger.info(
        f"[PHONE OSINT] Done in {elapsed}s. "
        f"Valid: {results['parsing'].get('valid')}, "
        f"Spam: {spam_check.get('is_spam')}, "
        f"Risk: {results['risk_level']}"
    )
    return results

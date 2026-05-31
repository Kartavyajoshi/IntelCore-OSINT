# functions/html_report_generator.py
import json
import os
from datetime import datetime

def format_value(val):
    if isinstance(val, (list, dict)):
        return f"<pre><code>{json.dumps(val, indent=2)}</code></pre>"
    return str(val)

def generate_html_report(scan_data: dict) -> str:
    """
    Generates a premium, Wazuh-themed HTML report with dark mode support,
    interactive sidebar, search filtering, overview dashboard, and custom module views.
    """
    target = scan_data.get("target", "Unknown Target")
    timestamp = scan_data.get("timestamp", "")
    if not timestamp:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    risk_score = scan_data.get("risk_score", 0)
    if isinstance(risk_score, dict):
        risk_level = risk_score.get("level", "INFO")
        risk_score = risk_score.get("score", 0)
    else:
        risk_level = scan_data.get("risk_level", "INFO")

    modules = scan_data.get("modules", {})
    if not modules:
        # Fallback if the modules are in the root dictionary (e.g. from tests or save scan structure)
        modules = {k: v for k, v in scan_data.items() if k not in [
            "id", "target", "timestamp", "status", "scan_status", "risk_score", 
            "risk_level", "modules_completed", "modules_total", "report_file", "dump_file"
        ]}

    # Categorize modules & parse findings
    findings = []
    
    # 1. Directory Enumeration findings
    dir_enum_data = modules.get("enumerate_directories_optimized") or modules.get("Directory Enumeration")
    if dir_enum_data and isinstance(dir_enum_data, dict):
        dirs = dir_enum_data.get("directories_found", [])
        for d in dirs:
            if d.get("risk") in ["CRITICAL", "HIGH", "MEDIUM"]:
                findings.append({
                    "source": "Directory Enumeration",
                    "severity": d.get("risk"),
                    "title": f"Exposed Directory: {d.get('path')}",
                    "desc": f"Discovered directory with status code {d.get('status')} and risk level {d.get('risk')}."
                })

    # 2. Email breaches findings
    breach_data = modules.get("check_breach_leakcheck_public") or modules.get("Breach Check (LeakCheck)") or modules.get("breaches")
    if breach_data and isinstance(breach_data, dict):
        results = breach_data.get("results", [])
        for r in results:
            leaked = r.get("sources", r.get("breaches", []))
            fields = r.get("compromised_fields", r.get("data_leaked", []))
            findings.append({
                "source": "LeakCheck Breach Search",
                "severity": "HIGH" if leaked else "MEDIUM",
                "title": f"Email Breached: {r.get('email')}",
                "desc": f"Email has been compromised in {len(leaked)} known breaches. Leaked data: {', '.join(fields)}."
            })
            
    # 3. Port Scanner findings
    port_data = modules.get("network_scanner_free") or modules.get("Port Scanner Free")
    if port_data and isinstance(port_data, dict):
        open_ports = port_data.get("open_ports", [])
        if open_ports:
            findings.append({
                "source": "Port Scanner",
                "severity": "HIGH",
                "title": f"Open Ports Detected on {port_data.get('target_ip', target)}",
                "desc": f"Discovered open ports: {', '.join(map(str, open_ports))} running services: {json.dumps(port_data.get('services', {}))}."
            })

    # 4. Threat Intelligence findings
    threat_intel = modules.get("threat_intel_lookup") or modules.get("Threat Intelligence Lookup")
    if threat_intel and isinstance(threat_intel, dict):
        score = threat_intel.get("threat_score", 0)
        level = threat_intel.get("threat_level", "LOW")
        hits = threat_intel.get("blocklist_hits", 0)
        if hits > 0 or level in ["HIGH", "MEDIUM", "CRITICAL"]:
            findings.append({
                "source": "Threat Intelligence Lookup",
                "severity": level,
                "title": f"Threat Level: {level} (Score: {score}/100)",
                "desc": f"Target hit {hits} security blocklists. AbuseIPDB/OTX blocklist hits detected."
            })

    # 5. DNS Security findings
    dns_sec = modules.get("dns_security_analyzer") or modules.get("DNS Security Analyzer")
    if dns_sec and isinstance(dns_sec, dict):
        missing = dns_sec.get("missing_records", [])
        if missing:
            findings.append({
                "source": "DNS Security Analyzer",
                "severity": "LOW",
                "title": "Missing DNS Security Records",
                "desc": f"Target is missing critical security records: {', '.join(missing)}. DNSSEC enabled: {dns_sec.get('dnssec_enabled', False)}."
            })

    # Sort findings by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda x: severity_order.get(x["severity"], 5))

    # Helper formatters for specific modules
    custom_views = {}

    # DNS records
    dns_data = modules.get("dns_enum_advanced") or modules.get("DNS Enumeration Advanced")
    if dns_data and isinstance(dns_data, dict):
        dns_records = dns_data.get("dns_records", [])
        subdomains = dns_data.get("subdomains", [])
        dns_html = "<h4>DNS Records</h4>"
        if dns_records:
            dns_html += "<table class='report-table'><thead><tr><th>Host</th><th>Type</th><th>Value</th><th>TTL</th></tr></thead><tbody>"
            for r in dns_records:
                dns_html += f"<tr><td>{r.get('host','')}</td><td><span class='badge badge-info'>{r.get('type','')}</span></td><td><code>{r.get('value','')}</code></td><td>{r.get('ttl','')}</td></tr>"
            dns_html += "</tbody></table>"
        else:
            dns_html += "<p class='no-data'>No DNS records resolved.</p>"
        
        dns_html += "<h4 class='mt-4'>Discovered Subdomains</h4>"
        if subdomains:
            dns_html += "<div class='tag-container'>"
            for sd in subdomains:
                dns_html += f"<span class='tag'>{sd}</span>"
            dns_html += "</div>"
        else:
            dns_html += "<p class='no-data'>No subdomains resolved.</p>"
        custom_views["DNS Enumeration Advanced"] = dns_html

    # DNS Security
    if dns_sec and isinstance(dns_sec, dict):
        missing = dns_sec.get("missing_records", [])
        records = dns_sec.get("records", {})
        ds_html = f"<div class='score-badge-large badge-{dns_sec.get('grade','A').lower()}'>Score: {dns_sec.get('score', 90)}/100 (Grade: {dns_sec.get('grade','A')})</div>"
        ds_html += "<h4 class='mt-4'>DNS Security Status</h4>"
        ds_html += f"<p><strong>DNSSEC Enabled:</strong> {'✅ Yes' if dns_sec.get('dnssec_enabled') else '❌ No'}</p>"
        if missing:
            ds_html += "<p><strong>Missing Security Records:</strong></p><div class='tag-container'>"
            for m in missing:
                ds_html += f"<span class='badge badge-critical'>{m}</span>"
            ds_html += "</div>"
        else:
            ds_html += "<p><strong>Missing Security Records:</strong> <span class='badge badge-low'>None</span></p>"
        ds_html += "<h4 class='mt-4'>Resolved Records</h4><table class='report-table'><thead><tr><th>Record</th><th>Status</th><th>Value</th></tr></thead><tbody>"
        for k, v in records.items():
            status = "✅ Present" if v else "❌ Missing"
            status_class = "badge-low" if v else "badge-critical"
            ds_html += f"<tr><td><strong>{k.upper()}</strong></td><td><span class='badge {status_class}'>{status}</span></td><td><code>{v or 'None'}</code></td></tr>"
        ds_html += "</tbody></table>"
        custom_views["DNS Security Analyzer"] = ds_html

    # WHOIS Lookup
    whois_data = modules.get("whois_lookup_deep") or modules.get("WHOIS Lookup Deep") or modules.get("whois_extended") or modules.get("Extended WHOIS")
    if whois_data and isinstance(whois_data, dict):
        wh_html = "<table class='report-table'><thead><tr><th>Property</th><th>Value</th></tr></thead><tbody>"
        for k, v in whois_data.items():
            if k not in ["raw", "status"]:
                wh_html += f"<tr><td><strong>{k.replace('_', ' ').title()}</strong></td><td>{format_value(v)}</td></tr>"
        wh_html += "</tbody></table>"
        if whois_data.get("raw"):
            wh_html += "<h4 class='mt-4'>Raw WHOIS Data</h4>"
            wh_html += f"<pre><code>{whois_data.get('raw')}</code></pre>"
        custom_views["WHOIS Lookup Deep"] = wh_html
        custom_views["Extended WHOIS"] = wh_html

    # SSL Certificate
    ssl_data = modules.get("certificate_analysis_free") or modules.get("SSL Certificate Analysis")
    if ssl_data and isinstance(ssl_data, dict):
        ssl_html = "<div class='grid-2'>"
        ssl_html += "<div><h4>Certificate Info</h4><table class='report-table'><tbody>"
        for prop in ["issuer", "subject", "valid_from", "valid_to", "signature_algorithm", "key_size", "serial_number"]:
            if prop in ssl_data:
                ssl_html += f"<tr><td><strong>{prop.replace('_', ' ').title()}</strong></td><td>{ssl_data[prop]}</td></tr>"
        ssl_html += "</tbody></table></div>"
        
        ssl_html += "<div><h4>Security Analysis</h4><table class='report-table'><tbody>"
        status_color = "badge-low" if ssl_data.get("is_valid") else "badge-critical"
        ssl_html += f"<tr><td><strong>Valid Status</strong></td><td><span class='badge {status_color}'>{'Valid' if ssl_data.get('is_valid') else 'Invalid/Expired'}</span></td></tr>"
        ssl_html += f"<tr><td><strong>Expired</strong></td><td>{'Yes' if ssl_data.get('expired') else 'No'}</td></tr>"
        ssl_html += f"<tr><td><strong>Days to Expiration</strong></td><td>{ssl_data.get('days_left', 0)} days</td></tr>"
        ssl_html += "</tbody></table>"
        if ssl_data.get("warnings"):
            ssl_html += "<h5 class='mt-2 text-danger'>Warnings</h5><ul>"
            for w in ssl_data["warnings"]:
                ssl_html += f"<li>{w}</li>"
            ssl_html += "</ul>"
        ssl_html += "</div></div>"
        custom_views["SSL Certificate Analysis"] = ssl_html

    # IP Intelligence
    ip_data = modules.get("ip_intelligence_free") or modules.get("IP Intelligence Free")
    if ip_data and isinstance(ip_data, dict):
        ip_html = "<div class='grid-2'>"
        ip_html += "<div><h4>Network Details</h4><table class='report-table'><tbody>"
        for k in ["ip", "hostname", "asn", "isp", "org", "country", "city"]:
            if k in ip_data:
                ip_html += f"<tr><td><strong>{k.upper()}</strong></td><td>{ip_data[k]}</td></tr>"
        ip_html += "</tbody></table></div>"
        ip_html += "<div><h4>Threat Intelligence</h4><table class='report-table'><tbody>"
        ip_html += f"<tr><td><strong>Proxy/VPN</strong></td><td>{'Yes' if ip_data.get('is_vpn') or ip_data.get('is_proxy') else 'No'}</td></tr>"
        ip_html += f"<tr><td><strong>Tor Exit Node</strong></td><td>{'Yes' if ip_data.get('is_tor') else 'No'}</td></tr>"
        ip_html += f"<tr><td><strong>Blocklist Score</strong></td><td>{ip_data.get('abuse_score', 0)}/100</td></tr>"
        ip_html += "</tbody></table></div></div>"
        custom_views["IP Intelligence Free"] = ip_html

    # Port Scanner
    if port_data and isinstance(port_data, dict):
        ps_html = f"<p><strong>Scanned IP:</strong> {port_data.get('target_ip', '127.0.0.1')}</p>"
        ps_html += "<table class='report-table'><thead><tr><th>Port</th><th>Service</th><th>Status</th></tr></thead><tbody>"
        services = port_data.get("services", {})
        open_ports = port_data.get("open_ports", [])
        if open_ports:
            for p in open_ports:
                ps_html += f"<tr><td><code>{p}</code></td><td><code>{services.get(str(p), 'unknown')}</code></td><td><span class='badge badge-low'>Open</span></td></tr>"
        else:
            ps_html += "<tr><td colspan='3' class='text-center'>No open ports detected in scope.</td></tr>"
        ps_html += "</tbody></table>"
        custom_views["Port Scanner Free"] = ps_html

    # Directory Enumeration
    if dir_enum_data and isinstance(dir_enum_data, dict):
        dirs = dir_enum_data.get("directories_found", [])
        de_html = f"<p><strong>Total Checked:</strong> {dir_enum_data.get('total_scanned', 0)} | <strong>Found:</strong> {len(dirs)}</p>"
        if dirs:
            de_html += "<table class='report-table'><thead><tr><th>Path</th><th>Status</th><th>Risk Level</th></tr></thead><tbody>"
            for d in dirs:
                risk = d.get("risk", "LOW")
                badge_class = f"badge-{risk.lower()}"
                de_html += f"<tr><td><code>{d.get('path')}</code></td><td><span class='badge badge-info'>{d.get('status')}</span></td><td><span class='badge {badge_class}'>{risk}</span></td></tr>"
            de_html += "</tbody></table>"
        else:
            de_html += "<p class='no-data'>No directory matches found.</p>"
        custom_views["Directory Enumeration"] = de_html

    # Email OSINT / Breach Checks
    email_data = modules.get("email_osint_platform") or modules.get("Email OSINT Platform")
    if email_data and isinstance(email_data, dict):
        em_html = "<div class='grid-2'>"
        em_html += "<div><h4>Email Information</h4><table class='report-table'><tbody>"
        em_html += f"<tr><td><strong>Email</strong></td><td>{email_data.get('email')}</td></tr>"
        em_html += f"<tr><td><strong>Deliverable</strong></td><td>{'Yes' if email_data.get('validation', {}).get('deliverable') else 'No'}</td></tr>"
        em_html += f"<tr><td><strong>Risk Level</strong></td><td><span class='badge badge-{email_data.get('risk_level', 'low').lower()}'>{email_data.get('risk_level', 'LOW')}</span></td></tr>"
        em_html += "</tbody></table></div>"
        em_html += "<div><h4>Platform Presence</h4>"
        platforms = email_data.get("platform_presence", {})
        found_platforms = [p for p, registered in platforms.items() if registered]
        if found_platforms:
            em_html += "<div class='tag-container'>"
            for p in found_platforms:
                em_html += f"<span class='tag tag-blue'>{p}</span>"
            em_html += "</div>"
        else:
            em_html += "<p class='no-data'>No social media accounts associated directly by email.</p>"
        em_html += "</div></div>"
        custom_views["Email OSINT Platform"] = em_html

    # LeakCheck Public Breaches
    if breach_data and isinstance(breach_data, dict):
        results = breach_data.get("results", [])
        lc_html = ""
        if results:
            for r in results:
                lc_html += f"<div class='breach-card mt-3'>"
                lc_html += f"<h5>Email: <code>{r.get('email')}</code> <span class='badge badge-critical'>Risk: {r.get('risk', 'HIGH')}</span></h5>"
                leaks = r.get("sources", r.get("breaches", []))
                fields = r.get("compromised_fields", r.get("data_leaked", []))
                lc_html += f"<p><strong>Compromised Fields:</strong> {', '.join(fields)}</p>"
                lc_html += "<h6>Breached Databases</h6><ul>"
                for l in leaks:
                    if isinstance(l, dict):
                        lc_html += f"<li><strong>{l.get('name', 'Unknown')}</strong> ({l.get('date', 'Unknown Date')})</li>"
                    else:
                        lc_html += f"<li>{l}</li>"
                lc_html += "</ul></div>"
        else:
            lc_html += "<p class='no-data'>No breach leaks detected for the targeted emails.</p>"
        custom_views["Breach Check (LeakCheck)"] = lc_html

    # Phone OSINT
    phone_data = modules.get("phone_osint_platform") or modules.get("Phone OSINT Platform")
    if phone_data and isinstance(phone_data, dict):
        ph_html = "<div class='grid-2'>"
        ph_html += "<div><h4>Phone Details</h4><table class='report-table'><tbody>"
        ph_html += f"<tr><td><strong>Phone</strong></td><td><code>{phone_data.get('phone')}</code></td></tr>"
        parsing = phone_data.get("parsing", {})
        ph_html += f"<tr><td><strong>Format</strong></td><td>{parsing.get('international', '')}</td></tr>"
        ph_html += f"<tr><td><strong>Country</strong></td><td>{parsing.get('country', '')}</td></tr>"
        ph_html += f"<tr><td><strong>Carrier</strong></td><td>{phone_data.get('numverify', {}).get('carrier', 'Unknown')}</td></tr>"
        ph_html += f"<tr><td><strong>Line Type</strong></td><td>{phone_data.get('numverify', {}).get('line_type', 'Unknown')}</td></tr>"
        ph_html += "</tbody></table></div>"
        
        ph_html += "<div><h4>Reputation & Risk</h4><table class='report-table'><tbody>"
        risk = phone_data.get("risk_level", "LOW")
        ph_html += f"<tr><td><strong>Risk Level</strong></td><td><span class='badge badge-{risk.lower()}'>{risk}</span></td></tr>"
        ph_html += f"<tr><td><strong>Spam Check</strong></td><td>{'Spam/Blocked' if phone_data.get('spam_check', {}).get('spam_detected') else 'Clean'}</td></tr>"
        ph_html += "</tbody></table></div></div>"
        custom_views["Phone OSINT Platform"] = ph_html

    # Social Media Enumeration
    sm_data = modules.get("social_media_enum") or modules.get("Social Media Enumeration")
    if sm_data and isinstance(sm_data, dict):
        sm_html = "<div class='tag-container'>"
        verified = sm_data.get("verified_platforms", [])
        if verified:
            for platform in verified:
                sm_html += f"<span class='tag tag-blue'>🔗 Found on {platform}</span>"
        else:
            sm_html += "<p class='no-data'>No profile matches found across social platforms.</p>"
        sm_html += "</div>"
        custom_views["Social Media Enumeration"] = sm_html

    # Threat Intel Lookup view
    if threat_intel and isinstance(threat_intel, dict):
        ti_html = f"<div class='score-badge-large badge-{threat_intel.get('threat_level','LOW').lower()}'>Threat Score: {threat_intel.get('threat_score', 0)}/100 ({threat_intel.get('threat_level', 'LOW')})</div>"
        ti_html += "<h4 class='mt-4'>Threat Details</h4>"
        ti_html += f"<p><strong>Blocklist Hits:</strong> {threat_intel.get('blocklist_hits', 0)} sources</p>"
        
        results_tables = ["dnsbl_results", "domain_dnsbl_results"]
        for tbl in results_tables:
            hits_list = threat_intel.get(tbl, {})
            if hits_list and isinstance(hits_list, dict):
                ti_html += f"<h5 class='mt-3'>{tbl.replace('_', ' ').title()}</h5><table class='report-table'><thead><tr><th>Blacklist Source</th><th>Status</th></tr></thead><tbody>"
                for src, hit in hits_list.items():
                    status_str = "❌ Hit" if hit else "✅ Clean"
                    st_class = "badge-critical" if hit else "badge-low"
                    ti_html += f"<tr><td>{src}</td><td><span class='badge {st_class}'>{status_str}</span></td></tr>"
                ti_html += "</tbody></table>"
        custom_views["Threat Intelligence Lookup"] = ti_html

    # Technology Detection
    tech_data = modules.get("technology_detection") or modules.get("Technology Detection")
    if tech_data and isinstance(tech_data, dict):
        tech_html = "<h4>Detected Technologies</h4>"
        techs = tech_data.get("technologies", [])
        if techs:
            tech_html += "<div class='tag-container'>"
            for t in techs:
                if isinstance(t, dict):
                    name = t.get("name", "Unknown")
                    cat = t.get("categories", ["Unknown"])[0]
                    tech_html += f"<span class='tag tag-blue'>{name} <small style='opacity:0.7'>({cat})</small></span>"
                else:
                    tech_html += f"<span class='tag tag-blue'>{t}</span>"
            tech_html += "</div>"
        else:
            tech_html += "<p class='no-data'>No technology signatures found.</p>"
        custom_views["Technology Detection"] = tech_html

    # Generate Module Sidebar Items & Tab Contents
    sidebar_items_html = ""
    modules_content_html = ""
    
    # Pre-select Overview dashboard
    sidebar_items_html += '<li class="nav-item active" onclick="switchTab(\'overview\')">📊 Overview Dashboard</li>'
    
    # Loop over all modules in sorted order
    sorted_module_names = sorted(list(modules.keys()))
    for idx, m_name in enumerate(sorted_module_names):
        m_data = modules[m_name]
        safe_id = f"module_{idx}"
        
        # Determine status
        is_fail = isinstance(m_data, dict) and m_data.get("status") == "failed"
        icon = "❌" if is_fail else "✅"
        
        sidebar_items_html += f'<li class="nav-item" data-module-name="{m_name.lower()}" onclick="switchTab(\'{safe_id}\')">{icon} {m_name}</li>'
        
        # Build panel HTML
        modules_content_html += f'<div id="{safe_id}" class="tab-pane">'
        modules_content_html += f'  <div class="panel-header">'
        modules_content_html += f'    <h2>{m_name}</h2>'
        modules_content_html += f'    <span class="badge badge-info">Module Report</span>'
        modules_content_html += f'  </div>'
        modules_content_html += f'  <div class="card mt-3">'
        
        # Append custom layout if exists, otherwise pretty JSON
        if m_name in custom_views:
            modules_content_html += custom_views[m_name]
        else:
            # Fallback pretty JSON
            try:
                pretty = json.dumps(m_data, indent=2)
                modules_content_html += f'<p><strong>Raw JSON Results:</strong></p>'
                modules_content_html += f'<pre><code class="language-json">{pretty}</code></pre>'
            except:
                modules_content_html += f'<p>{str(m_data)}</p>'
                
        modules_content_html += f'  </div>'
        modules_content_html += f'</div>'

    # Build findings list
    findings_html = ""
    if findings:
        findings_html += "<table class='report-table'><thead><tr><th>Severity</th><th>Source Module</th><th>Finding</th><th>Description</th></tr></thead><tbody>"
        for f in findings:
            sev = f["severity"].upper()
            sev_class = f"badge-{sev.lower()}"
            findings_html += f"<tr><td><span class='badge {sev_class}'>{sev}</span></td><td><strong>{f['source']}</strong></td><td>{f['title']}</td><td>{f['desc']}</td></tr>"
        findings_html += "</tbody></table>"
    else:
        findings_html += "<p class='no-data'>✅ No critical or high-risk findings detected.</p>"

    # Full HTML template
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>IntelCore OSINT Report - {target}</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=Fira+Code:wght@400;500&display=swap" rel="stylesheet">
  <style>
    :root {{
      --bg-main: #f8fafc;
      --bg-card: #ffffff;
      --bg-sidebar: #0f172a;
      --text-main: #0f172a;
      --text-muted: #64748b;
      --text-sidebar: #94a3b8;
      --border-color: #e2e8f0;
      --accent-color: #0ea5e9;
      --accent-hover: #38bdf8;
      
      --badge-critical-bg: #fee2e2;
      --badge-critical-text: #991b1b;
      --badge-high-bg: #ffedd5;
      --badge-high-text: #c2410c;
      --badge-medium-bg: #fef9c3;
      --badge-medium-text: #854d0e;
      --badge-low-bg: #dcfce7;
      --badge-low-text: #166534;
      --badge-info-bg: #e0f2fe;
      --badge-info-text: #075985;
    }}

    body.dark-theme {{
      --bg-main: #0b0f19;
      --bg-card: #151c2c;
      --bg-sidebar: #0d111d;
      --text-main: #f1f5f9;
      --text-muted: #94a3b8;
      --text-sidebar: #64748b;
      --border-color: #1e293b;
      --accent-color: #38bdf8;
      --accent-hover: #7dd3fc;
      
      --badge-critical-bg: #450a0a;
      --badge-critical-text: #fca5a5;
      --badge-high-bg: #431407;
      --badge-high-text: #fdba74;
      --badge-medium-bg: #422006;
      --badge-medium-text: #fde047;
      --badge-low-bg: #064e3b;
      --badge-low-text: #86efac;
      --badge-info-bg: #0c4a6e;
      --badge-info-text: #7dd3fc;
    }}

    * {{
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }}

    body {{
      font-family: 'Inter', sans-serif;
      background-color: var(--bg-main);
      color: var(--text-main);
      display: flex;
      min-height: 100vh;
      transition: background-color 0.3s, color 0.3s;
    }}

    /* Sidebar Layout */
    .sidebar {{
      width: 320px;
      background-color: var(--bg-sidebar);
      color: #ffffff;
      display: flex;
      flex-direction: column;
      border-right: 1px solid var(--border-color);
      flex-shrink: 0;
    }}

    .sidebar-header {{
      padding: 24px;
      border-bottom: 1px solid rgba(255,255,255,0.08);
    }}

    .sidebar-header h1 {{
      font-size: 20px;
      font-weight: 700;
      color: #ffffff;
      display: flex;
      align-items: center;
      gap: 10px;
    }}

    .sidebar-header h1 span {{
      color: var(--accent-color);
    }}

    .sidebar-meta {{
      padding: 12px 24px;
      font-size: 12px;
      color: var(--text-sidebar);
      border-bottom: 1px solid rgba(255,255,255,0.08);
      background-color: rgba(0, 0, 0, 0.15);
    }}

    .sidebar-search {{
      padding: 12px 16px;
      border-bottom: 1px solid rgba(255,255,255,0.08);
    }}

    .sidebar-search input {{
      width: 100%;
      padding: 8px 12px;
      border-radius: 6px;
      border: 1px solid rgba(255,255,255,0.15);
      background-color: rgba(255,255,255,0.05);
      color: #ffffff;
      font-size: 13px;
      outline: none;
      transition: border-color 0.2s;
    }}

    .sidebar-search input:focus {{
      border-color: var(--accent-color);
    }}

    .nav-list {{
      list-style: none;
      overflow-y: auto;
      flex-grow: 1;
      padding: 12px 0;
    }}

    .nav-item {{
      padding: 10px 24px;
      font-size: 14px;
      cursor: pointer;
      display: flex;
      align-items: center;
      color: var(--text-sidebar);
      transition: all 0.2s;
    }}

    .nav-item:hover {{
      background-color: rgba(255,255,255,0.04);
      color: #ffffff;
    }}

    .nav-item.active {{
      background-color: var(--accent-color);
      color: #ffffff;
      font-weight: 500;
    }}

    .sidebar-footer {{
      padding: 16px 24px;
      border-top: 1px solid rgba(255,255,255,0.08);
      display: flex;
      justify-content: space-between;
      align-items: center;
    }}

    .dark-mode-btn {{
      background: none;
      border: 1px solid rgba(255,255,255,0.2);
      color: #ffffff;
      padding: 6px 12px;
      border-radius: 4px;
      cursor: pointer;
      font-size: 12px;
      transition: background-color 0.2s;
    }}

    .dark-mode-btn:hover {{
      background-color: rgba(255,255,255,0.1);
    }}

    /* Main Panel Layout */
    .main-content {{
      flex-grow: 1;
      overflow-y: auto;
      padding: 40px;
    }}

    .tab-pane {{
      display: none;
    }}

    .tab-pane.active {{
      display: block;
    }}

    .panel-header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 24px;
      border-bottom: 2px solid var(--border-color);
      padding-bottom: 12px;
    }}

    .panel-header h2 {{
      font-size: 24px;
      font-weight: 600;
    }}

    /* Cards & Grids */
    .grid-4 {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 20px;
      margin-bottom: 30px;
    }}

    .grid-2 {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
      gap: 24px;
      margin-top: 20px;
    }}

    .card {{
      background-color: var(--bg-card);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 24px;
      box-shadow: 0 1px 3px rgba(0,0,0,0.05);
      transition: box-shadow 0.3s, transform 0.2s;
    }}

    .card:hover {{
      box-shadow: 0 4px 12px rgba(0,0,0,0.08);
    }}

    .metric-card {{
      text-align: center;
      padding: 20px;
    }}

    .metric-label {{
      font-size: 12px;
      text-transform: uppercase;
      font-weight: 600;
      color: var(--text-muted);
      margin-bottom: 8px;
    }}

    .metric-val {{
      font-size: 28px;
      font-weight: 700;
      color: var(--text-main);
    }}

    /* Badges */
    .badge {{
      display: inline-block;
      padding: 4px 8px;
      border-radius: 4px;
      font-size: 12px;
      font-weight: 600;
      text-transform: uppercase;
    }}

    .badge-critical {{ background-color: var(--badge-critical-bg); color: var(--badge-critical-text); }}
    .badge-high {{ background-color: var(--badge-high-bg); color: var(--badge-high-text); }}
    .badge-medium {{ background-color: var(--badge-medium-bg); color: var(--badge-medium-text); }}
    .badge-low {{ background-color: var(--badge-low-bg); color: var(--badge-low-text); }}
    .badge-info {{ background-color: var(--badge-info-bg); color: var(--badge-info-text); }}

    .score-badge-large {{
      display: inline-block;
      padding: 12px 24px;
      border-radius: 8px;
      font-size: 18px;
      font-weight: 700;
      margin-bottom: 20px;
    }}

    /* Tables */
    .report-table {{
      width: 100%;
      border-collapse: collapse;
      margin-top: 16px;
      text-align: left;
    }}

    .report-table th, .report-table td {{
      padding: 12px 16px;
      border-bottom: 1px solid var(--border-color);
      font-size: 14px;
    }}

    .report-table th {{
      background-color: var(--bg-main);
      font-weight: 600;
      color: var(--text-muted);
      text-transform: uppercase;
      font-size: 11px;
      letter-spacing: 0.5px;
    }}

    .report-table tbody tr:hover {{
      background-color: rgba(14, 165, 233, 0.04);
    }}

    /* Code blocks */
    pre {{
      background-color: var(--bg-main);
      padding: 16px;
      border-radius: 6px;
      overflow-x: auto;
      border: 1px solid var(--border-color);
      margin-top: 12px;
    }}

    code {{
      font-family: 'Fira Code', monospace;
      font-size: 13px;
      color: var(--text-main);
    }}

    /* Tag Cloud */
    .tag-container {{
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-top: 12px;
    }}

    .tag {{
      background-color: var(--bg-main);
      border: 1px solid var(--border-color);
      padding: 6px 12px;
      border-radius: 20px;
      font-size: 13px;
    }}

    .tag-blue {{
      background-color: var(--badge-info-bg);
      color: var(--badge-info-text);
      border-color: transparent;
    }}

    .no-data {{
      color: var(--text-muted);
      font-style: italic;
      padding: 12px 0;
    }}

    .mt-3 {{ margin-top: 16px; }}
    .mt-4 {{ margin-top: 24px; }}
    .text-center {{ text-align: center; }}
    .text-danger {{ color: var(--badge-critical-text); }}

    .breach-card {{
      border-left: 4px solid var(--badge-critical-text);
      padding-left: 16px;
      margin-bottom: 16px;
    }}
  </style>
</head>
<body>

  <!-- Sidebar -->
  <div class="sidebar">
    <div class="sidebar-header">
      <h1>IntelCore <span>OSINT</span></h1>
    </div>
    <div class="sidebar-meta">
      <strong>Target:</strong> {target}<br>
      <strong>Scanned:</strong> {timestamp}
    </div>
    <div class="sidebar-search">
      <input type="text" id="search" placeholder="Search modules..." oninput="filterModules()">
    </div>
    <ul class="nav-list" id="nav-list">
      {sidebar_items_html}
    </ul>
    <div class="sidebar-footer">
      <button class="dark-mode-btn" onclick="toggleDarkMode()">🌓 Toggle Theme</button>
      <span style="font-size: 11px; opacity: 0.6">v1.2.0</span>
    </div>
  </div>

  <!-- Main Content -->
  <div class="main-content">
    
    <!-- Overview Dashboard -->
    <div id="overview" class="tab-pane active">
      <div class="panel-header">
        <h2>Security Dashboard</h2>
        <span class="badge badge-info">Overview</span>
      </div>

      <!-- Quick Metrics -->
      <div class="grid-4">
        <div class="card metric-card">
          <div class="metric-label">Risk Level</div>
          <div class="badge badge-{risk_level.lower()}" style="font-size:16px; padding: 6px 16px;">{risk_level}</div>
        </div>
        <div class="card metric-card">
          <div class="metric-label">Risk Score</div>
          <div class="metric-val" style="color: {'#ef4444' if risk_score > 60 else '#eab308' if risk_score > 25 else '#10b981'}">{risk_score}/100</div>
        </div>
        <div class="card metric-card">
          <div class="metric-label">Modules Executed</div>
          <div class="metric-val">{len(modules)}</div>
        </div>
        <div class="card metric-card">
          <div class="metric-label">Status</div>
          <div class="badge badge-low" style="font-size:16px; padding: 6px 16px;">COMPLETED</div>
        </div>
      </div>

      <!-- Findings Summary -->
      <div class="card">
        <h3>🚨 Threat & Vulnerability Findings</h3>
        <p class="text-muted" style="font-size:13px; margin-bottom:12px;">Aggregated key-risk items found from scan modules.</p>
        {findings_html}
      </div>
    </div>

    <!-- Modules Content -->
    {modules_content_html}

  </div>

  <script>
    // Tab switching logic
    function switchTab(tabId) {{
      // Hide all panes
      const panes = document.querySelectorAll('.tab-pane');
      panes.forEach(p => p.classList.remove('active'));

      // Show target pane
      const targetPane = document.getElementById(tabId);
      if (targetPane) {{
        targetPane.classList.add('active');
      }}

      // Update sidebar highlight
      const navItems = document.querySelectorAll('.nav-item');
      navItems.forEach(item => item.classList.remove('active'));
      
      // Find matching item based on tabId
      if (tabId === 'overview') {{
        navItems[0].classList.add('active');
      }} else {{
        const index = parseInt(tabId.split('_')[1]);
        // Search matches by index (excluding overview)
        navItems[index + 1].classList.add('active');
      }}
    }}

    // Filter list of modules in sidebar
    function filterModules() {{
      const query = document.getElementById('search').value.toLowerCase();
      const items = document.querySelectorAll('.nav-item');
      
      // Skip the first item (Overview Dashboard)
      for (let i = 1; i < items.length; i++) {{
        const item = items[i];
        const moduleName = item.getAttribute('data-module-name') || '';
        if (moduleName.includes(query)) {{
          item.style.display = 'flex';
        }} else {{
          item.style.display = 'none';
        }}
      }}
    }}

    // Theme toggler
    function toggleDarkMode() {{
      document.body.classList.toggle('dark-theme');
      const isDark = document.body.classList.contains('dark-theme');
      localStorage.setItem('dark-mode', isDark ? 'enabled' : 'disabled');
    }}

    // Initialize theme from storage
    document.addEventListener('DOMContentLoaded', () => {{
      const mode = localStorage.getItem('dark-mode');
      if (mode === 'enabled') {{
        document.body.classList.add('dark-theme');
      }}
    }});
  </script>
</body>
</html>
"""
    return html

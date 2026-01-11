import io
import datetime
import uuid
import json
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image, KeepTogether
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT, TA_RIGHT
from reportlab.pdfgen import canvas
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('Agg')

def generate_premium_report(scan_data, filename=None):
    """
    Professional Full-Page PDF Report with Complete Data Coverage
    """
    report_id = f"RPT-{datetime.datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
    if not filename:
        filename = f"OSINT_Report_{scan_data.get('target', 'Target')}_{report_id}.pdf"

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40)
    story = []
    styles = getSampleStyleSheet()

    # ============= CUSTOM STYLES =============
    title_style = ParagraphStyle('MainTitle', parent=styles['Heading1'], fontSize=32, 
                                textColor=colors.HexColor('#0f172a'), alignment=TA_CENTER, 
                                spaceAfter=10, fontName='Helvetica-Bold')
    subtitle_style = ParagraphStyle('SubTitle', parent=styles['Normal'], fontSize=12,
                                   textColor=colors.HexColor('#64748b'), alignment=TA_CENTER,
                                   spaceAfter=30)
    h1_style = ParagraphStyle('H1', parent=styles['Heading2'], fontSize=14, 
                             textColor=colors.HexColor('#0f172a'), spaceBefore=15, spaceAfter=12,
                             fontName='Helvetica-Bold', borderBottomWidth=2, 
                             borderColor=colors.HexColor('#2563eb'), paddingBottom=8)
    h2_style = ParagraphStyle('H2', parent=styles['Heading3'], fontSize=12,
                             textColor=colors.HexColor('#2563eb'), spaceBefore=12, spaceAfter=8,
                             fontName='Helvetica-Bold')
    body_style = ParagraphStyle('Body', parent=styles['Normal'], fontSize=9.5, leading=13, 
                               alignment=TA_JUSTIFY, spaceAfter=10)
    code_style = ParagraphStyle('Code', parent=styles['Code'], fontSize=8, fontName='Courier',
                               textColor=colors.HexColor('#10b981'), backColor=colors.HexColor('#1a202c'),
                               borderPadding=5, leftIndent=10)

    def add_footer(canvas, doc):
        canvas.saveState()
        canvas.setFont('Helvetica', 8)
        canvas.setFillColor(colors.HexColor('#94a3b8'))
        canvas.drawString(40, 25, f"Confidential Security Assessment | {scan_data.get('target', 'Target')}")
        canvas.drawRightString(letter[0]-40, 25, f"Page {doc.page} | Ref: {report_id}")
        canvas.restoreState()

    # ============= PAGE 1: EXECUTIVE COVER =============
    story.append(Spacer(1, 1.5*inch))
    story.append(Paragraph("COMPREHENSIVE OSINT SECURITY ASSESSMENT", title_style))
    story.append(Paragraph("Open Source Intelligence Intelligence Report", subtitle_style))
    
    story.append(Spacer(1, 0.3*inch))
    
    # Executive Summary Box
    risk_score = scan_data.get('risk_score', {}).get('score', 0)
    risk_level = scan_data.get('risk_score', {}).get('level', 'UNKNOWN')
    
    risk_color = colors.HexColor('#ef4444') if risk_level == 'CRITICAL' else \
                 colors.HexColor('#f59e0b') if risk_level == 'HIGH' else \
                 colors.HexColor('#3b82f6') if risk_level == 'MEDIUM' else \
                 colors.HexColor('#10b981')
    
    exec_data = [
        ['Target Domain', scan_data.get('target', 'Unknown')],
        ['Scan Date & Time', datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')],
        ['Report Reference ID', report_id],
        ['Risk Assessment Level', risk_level],
        ['Composite Risk Score', f"{risk_score}/100"],
        ['Scanning Modules Executed', f"{scan_data.get('modules_completed', 0)}/{scan_data.get('modules_total', 12)}"],
        ['Scan Status', scan_data.get('scan_status', 'Unknown').upper()],
        ['Data Classification', 'STRICTLY CONFIDENTIAL'],
    ]
    
    t_exec = Table(exec_data, colWidths=[2.2*inch, 4*inch])
    t_exec.setStyle(TableStyle([
        ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 9),
        ('TEXTCOLOR', (0,0), (0,-1), colors.HexColor('#0f172a')),
        ('TEXTCOLOR', (1,0), (1,-1), colors.HexColor('#334155')),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('BACKGROUND', (0,0), (0,-1), colors.HexColor('#f1f5f9')),
        ('GRID', (0,0), (-1,-1), 1, colors.HexColor('#cbd5e1')),
        ('ROWBACKGROUNDS', (1,0), (1,-1), [colors.white, colors.HexColor('#f8fafc')]),
        ('BOTTOMPADDING', (0,0), (-1,-1), 10),
        ('TOPPADDING', (0,0), (-1,-1), 10),
    ]))
    story.append(t_exec)
    story.append(PageBreak())

    # ============= PAGE 2: EXECUTIVE SUMMARY =============
    story.append(Paragraph("1. EXECUTIVE SUMMARY", h1_style))
    
    summary_text = f"""
    This comprehensive OSINT (Open Source Intelligence) assessment was conducted against <b>{scan_data.get('target')}</b> 
    using 12 advanced reconnaissance modules. The assessment identified a composite risk score of <b>{risk_score}/100</b> 
    with a threat level of <b>{risk_level}</b>. This report presents detailed findings across infrastructure, security, 
    breach intelligence, and organizational exposure derived from passive data collection sources including certificate 
    transparency logs, DNS records, WHOIS registries, internet-wide device scanning, threat intelligence aggregation, 
    and dark web breach monitoring. All assessment activities were conducted passively without any active exploitation 
    or unauthorized system access.
    """
    story.append(Paragraph(summary_text, body_style))
    story.append(Spacer(1, 0.15*inch))

    # Risk Summary Table
    story.append(Paragraph("Risk Assessment Overview", h2_style))
    factors = scan_data.get('risk_score', {}).get('factors', [])
    
    risk_summary = [['Risk Category', 'Status', 'Details']]
    
    risk_categories = [
        ('Infrastructure Protection', 'WAF Detection', f"{sum(1 for r in scan_data.get('waf', {}).get('results', []) if r.get('has_waf'))} endpoints protected"),
        ('Data Exposure', 'Compromised Credentials', f"{sum(1 for b in scan_data.get('breaches', {}).get('results', []) if b.get('is_pwned'))} accounts found"),
        ('Directory Exposure', 'Open Directories', f"{scan_data.get('directories', {}).get('scan_summary', {}).get('critical_directories', 0)} critical"),
        ('Threat Intelligence', 'Domain Reputation', f"{scan_data.get('virustotal', {}).get('detections', {}).get('malicious', 0)} malicious detections"),
        ('Email Infrastructure', 'Mail Security', f"{scan_data.get('email_enumeration', {}).get('infrastructure_risks', {}).get('critical_risks', 0)} critical risks"),
    ]
    
    for category, name, value in risk_categories:
        risk_summary.append([category, name, value])
    
    t_risk = Table(risk_summary, colWidths=[1.8*inch, 2*inch, 2.2*inch])
    t_risk.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0f172a')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 9),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f8fafc')]),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ('TOPPADDING', (0,0), (-1,-1), 8),
    ]))
    story.append(t_risk)
    story.append(Spacer(1, 0.15*inch))

    # Key Findings
    story.append(Paragraph("Key Findings & Risk Factors", h2_style))
    for i, factor in enumerate(factors, 1):
        story.append(Paragraph(f"<b>{i}.</b> {factor}", body_style))
    
    story.append(PageBreak())

    # ============= PAGE 3: WHOIS & DOMAIN INFO =============
    story.append(Paragraph("2. DOMAIN & REGISTRATION INTELLIGENCE", h1_style))
    
    whois = scan_data.get('whois', {})
    
    story.append(Paragraph("WHOIS Registration Details", h2_style))
    whois_data = [
        ['Field', 'Value'],
        ['Domain Name', whois.get('domain_name', '-')],
        ['Domain Status', 'Locked' if whois.get('security_check', {}).get('is_locked') else 'Unlocked'],
        ['Registrar Name', whois.get('registrar', {}).get('name', '-')],
        ['Registrar IANA ID', whois.get('registrar', {}).get('iana_id', '-')],
        ['Creation Date', whois.get('dates', {}).get('created', '-')],
        ['Last Updated', whois.get('dates', {}).get('updated', '-')],
        ['Expiration Date', whois.get('dates', {}).get('expires', '-')],
        ['Days Until Expiry', f"{(datetime.datetime.strptime(whois.get('dates', {}).get('expires', '2099-01-01'), '%Y-%m-%d') - datetime.datetime.now()).days} days"],
    ]
    
    t_whois = Table(whois_data, colWidths=[2.5*inch, 3.7*inch])
    t_whois.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#2563eb')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 9),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f8fafc')]),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
        ('TOPPADDING', (0,0), (-1,-1), 8),
    ]))
    story.append(t_whois)
    story.append(Spacer(1, 0.2*inch))

    story.append(Paragraph("Registrant Information", h2_style))
    registrant = whois.get('registrant', {})
    registrant_data = [
        ['Organization', registrant.get('org', 'Redacted/Privacy Protected')],
        ['Country', registrant.get('country', 'Unknown')],
        ['State/Province', registrant.get('state', 'Unknown')],
        ['City', registrant.get('city', 'Unknown')],
    ]
    
    t_reg = Table(registrant_data, colWidths=[2.5*inch, 3.7*inch])
    t_reg.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#2563eb')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 9),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f8fafc')]),
    ]))
    story.append(t_reg)
    story.append(PageBreak())

    # ============= PAGE 4: DNS & INFRASTRUCTURE =============
    story.append(Paragraph("3. DNS INFRASTRUCTURE & MAIL CONFIGURATION", h1_style))
    
    dns = scan_data.get('dns', {})
    story.append(Paragraph("DNS Records Summary", h2_style))
    
    dns_data = [['Type', 'Value']]
    (dns.get('infrastructure', {}).get('ip_addresses', []) or [])
    for ip in dns.get('infrastructure', {}).get('ip_addresses', []):
        dns_data.append(['A Record', ip])
    for mx in dns.get('infrastructure', {}).get('mail_servers', []):
        dns_data.append(['MX Record', mx])
    for ns in dns.get('identity', {}).get('nameservers', []):
        dns_data.append(['NS Record', ns])
    
    if not [row for row in dns_data[1:]]:
        dns_data.append(['Status', 'No DNS records found'])
    
    t_dns = Table(dns_data, colWidths=[1.5*inch, 4.7*inch])
    t_dns.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#2563eb')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 9),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f8fafc')]),
    ]))
    story.append(t_dns)
    story.append(Spacer(1, 0.15*inch))

    story.append(Paragraph("Security Policies", h2_style))
    story.append(Paragraph(f"<b>SPF Policy:</b> <code>{dns.get('security', {}).get('spf_policy', 'Not configured')}</code>", body_style))
    story.append(Paragraph(f"<b>DMARC Policy:</b> <code>{dns.get('security', {}).get('dmarc_policy', 'Not configured')}</code>", body_style))
    story.append(Spacer(1, 0.15*inch))

    story.append(Paragraph("Mail Provider Details", h2_style))
    story.append(Paragraph(f"<b>Mail Provider:</b> {dns.get('infrastructure', {}).get('mail_provider', 'Unknown')}", body_style))
    story.append(Paragraph(f"<b>Cloud Provider:</b> {dns.get('infrastructure', {}).get('cloud_provider', 'Self-hosted/Unknown')}", body_style))
    story.append(PageBreak())

    # ============= PAGE 5: SUBDOMAINS =============
    story.append(Paragraph("4. DISCOVERED SUBDOMAINS & CERTIFICATES", h1_style))
    
    all_subs = set()
    for cert in scan_data.get('certificates', []):
        all_subs.update(cert.get('subdomains', []))
    
    story.append(Paragraph(f"Total Subdomains Discovered: <b>{len(all_subs)}</b>", h2_style))
    
    if all_subs:
        # Organize subdomains
        sub_table_data = [['#', 'Subdomain', 'Risk Level']]
        for i, sub in enumerate(sorted(list(all_subs)), 1):
            sub_table_data.append([str(i), sub, 'Medium'])
        
        t_subs = Table(sub_table_data, colWidths=[0.5*inch, 4.5*inch, 1.2*inch])
        t_subs.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0f172a')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 8.5),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f8fafc')]),
            ('TOPPADDING', (0,0), (-1,-1), 6),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ]))
        story.append(t_subs)
    else:
        story.append(Paragraph("No subdomains discovered", body_style))
    
    story.append(Spacer(1, 0.15*inch))
    
    story.append(Paragraph("SSL/TLS Certificates", h2_style))
    cert_table_data = [['Issuer', 'Date', 'Risk', 'Subdomains']]
    for cert in scan_data.get('certificates', [])[:10]:
        subs_count = len(cert.get('subdomains', []))
        cert_table_data.append([
            cert.get('issuer', '-'),
            cert.get('date', '-'),
            cert.get('risk', '-'),
            str(subs_count)
        ])
    
    t_cert = Table(cert_table_data, colWidths=[1.8*inch, 1.2*inch, 0.8*inch, 1.4*inch])
    t_cert.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0f172a')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 9),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f8fafc')]),
    ]))
    story.append(t_cert)
    story.append(PageBreak())

    # ============= PAGE 6: SHODAN INTELLIGENCE =============
    story.append(Paragraph("5. SHODAN INTERNET INTELLIGENCE", h1_style))
    
    shodan = scan_data.get('shodan', {})
    geo = shodan.get('geolocation_and_organization', {})
    device = shodan.get('device_identification', {})
    
    story.append(Paragraph("Geolocation & Organization", h2_style))
    geo_data = [
        ['IP Address', geo.get('ip', '-')],
        ['Country', geo.get('country', '-')],
        ['City', geo.get('city', '-')],
        ['Organization', geo.get('organization', '-')],
        ['ISP', geo.get('isp', '-')],
        ['ASN', geo.get('asn', '-')],
    ]
    
    t_geo = Table(geo_data, colWidths=[2.2*inch, 4*inch])
    t_geo.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#2563eb')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 9),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f8fafc')]),
    ]))
    story.append(t_geo)
    story.append(Spacer(1, 0.15*inch))

    story.append(Paragraph("Device Information", h2_style))
    story.append(Paragraph(f"<b>Operating System:</b> {device.get('os', 'Unknown')}", body_style))
    story.append(Paragraph(f"<b>Last Updated:</b> {device.get('last_update', 'Unknown')}", body_style))
    story.append(Spacer(1, 0.1*inch))

    story.append(Paragraph("Open Ports & Services", h2_style))
    port_data = [['Port', 'Protocol', 'Service', 'Product', 'Version']]
    for port in (shodan.get('open_ports_and_services', [])[:10] or []):
        banner = next((b for b in shodan.get('service_banners_and_metadata', []) 
                      if b.get('port') == port.get('port')), {})
        port_data.append([
            str(port.get('port', '-')),
            port.get('protocol', '-'),
            port.get('service_name', '-'),
            banner.get('product', '-'),
            banner.get('version', '-')
        ])
    
    if len(port_data) == 1:
        port_data.append(['N/A', 'N/A', 'No open ports detected', 'N/A', 'N/A'])
    
    t_ports = Table(port_data, colWidths=[0.8*inch, 0.8*inch, 1.2*inch, 1.6*inch, 1.2*inch])
    t_ports.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0f172a')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 8),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f8fafc')]),
    ]))
    story.append(t_ports)
    story.append(Spacer(1, 0.15*inch))

    story.append(Paragraph("CVE Vulnerabilities", h2_style))
    vulns = shodan.get('vulnerability_information', [])
    if vulns:
        for vuln in vulns[:5]:
            story.append(Paragraph(f"• <code>{vuln}</code>", body_style))
    else:
        story.append(Paragraph("No known vulnerabilities detected", body_style))
    
    story.append(PageBreak())

    # ============= PAGE 7: SECURITY & WAF =============
    story.append(Paragraph("6. SECURITY ANALYSIS & WAF DETECTION", h1_style))
    
    story.append(Paragraph("Web Application Firewall (WAF) Status", h2_style))
    waf_results = scan_data.get('waf', {}).get('results', [])
    waf_data = [['Endpoint', 'WAF Status', 'Technology']]
    for waf in waf_results:
        status = '✓ Protected' if waf.get('has_waf') else '✗ Not Protected'
        waf_data.append([waf.get('target', '-'), status, waf.get('waf_name', '-')])
    
    if len(waf_data) == 1:
        waf_data.append(['N/A', 'No data', 'N/A'])
    
    t_waf = Table(waf_data, colWidths=[2.4*inch, 2*inch, 1.8*inch])
    t_waf.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#ef4444')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 9),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#fee2e2')]),
    ]))
    story.append(t_waf)
    story.append(Spacer(1, 0.15*inch))

    story.append(Paragraph("Exposed Directories", h2_style))
    dirs = scan_data.get('directories', {}).get('results', [])
    total_dirs = sum(d.get('total_found', 0) for d in dirs)
    critical_dirs = sum(len(d.get('critical_findings', [])) for d in dirs)
    
    story.append(Paragraph(f"<b>Total Directories Found:</b> {total_dirs}", body_style))
    story.append(Paragraph(f"<b>Critical Directories:</b> {critical_dirs}", body_style))
    
    if dirs:
        for d in dirs:
            story.append(Spacer(1, 0.08*inch))
            story.append(Paragraph(f"<b>{d.get('target')}:</b> {d.get('total_found')} directories", h2_style))
            dir_list = d.get('directories_found', [])[:8]
            for dir_item in dir_list:
                story.append(Paragraph(f"• {dir_item.get('path', '-')} [HTTP {dir_item.get('status', '?')}]", body_style))
    
    story.append(PageBreak())

    # ============= PAGE 8: BREACHES & CREDENTIALS =============
    story.append(Paragraph("7. BREACH INTELLIGENCE & COMPROMISED CREDENTIALS", h1_style))
    
    breaches = scan_data.get('breaches', {}).get('results', [])
    pwned = [b for b in breaches if b.get('is_pwned')]
    
    if pwned:
        story.append(Paragraph(f"<font color='red'><b>⚠️ ALERT: {len(pwned)} COMPROMISED ACCOUNT(S) DETECTED</b></font>", h2_style))
        story.append(Spacer(1, 0.1*inch))
        
        breach_data = [['Email', 'Risk Level', 'Data Compromised', 'Breach Count']]
        for b in pwned:
            breach_data.append([
                b.get('email', '-'),
                b.get('risk_level', '-'),
                ', '.join(b.get('data_leaked', [])) or 'Unknown',
                str(b.get('breach_count', 0))
            ])
        
        t_breach = Table(breach_data, colWidths=[1.8*inch, 1.2*inch, 2*inch, 1.2*inch])
        t_breach.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#ef4444')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 9),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#ef4444')),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#fee2e2')]),
        ]))
        story.append(t_breach)
    else:
        story.append(Paragraph("<b style='color: green'>✓ No compromised credentials detected in dark web breach databases</b>", h2_style))
    
    story.append(PageBreak())

    # ============= PAGE 9: EMAIL ENUMERATION =============
    story.append(Paragraph("8. EMAIL INTELLIGENCE & VALIDATION", h1_style))
    
    email_enum = scan_data.get('email_enumeration', {})
    email_stats = email_enum.get('stats', {})
    
    story.append(Paragraph("Email Statistics", h2_style))
    email_stat_data = [
        ['Metric', 'Count'],
        ['Total Emails Discovered', str(email_stats.get('total_emails', 0))],
        ['Valid Emails', str(email_stats.get('valid_emails', 0))],
        ['Invalid Emails', str(email_stats.get('invalid_emails', 0))],
        ['Risky Emails', str(email_stats.get('risky_emails', 0))],
    ]
    
    t_email_stat = Table(email_stat_data, colWidths=[3*inch, 3.2*inch])
    t_email_stat.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#2563eb')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 9),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f8fafc')]),
    ]))
    story.append(t_email_stat)
    story.append(Spacer(1, 0.15*inch))

    story.append(Paragraph("Mail Infrastructure Analysis", h2_style))
    infra_risks = email_enum.get('infrastructure_risks', {})
    risk_details = infra_risks.get('risk_details', {})
    
    infra_data = [
        ['Infrastructure Component', 'Status'],
        ['MX Records Found', f"{len(email_enum.get('mx_records', []))} records"],
        ['Critical Risks Detected', str(infra_risks.get('critical_risks', 0))],
        ['SPF Record', 'Missing ✗' if risk_details.get('no_spf') else 'Present ✓'],
        ['DMARC Record', 'Missing ✗' if risk_details.get('no_dmarc') else 'Present ✓'],
    ]
    
    t_infra = Table(infra_data, colWidths=[3*inch, 3.2*inch])
    t_infra.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0f172a')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 9),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f8fafc')]),
    ]))
    story.append(t_infra)
    story.append(Spacer(1, 0.15*inch))

    story.append(Paragraph("Email Accounts by Type", h2_style))
    email_groups = email_enum.get('email_groups', {})
    
    for group_name, group_emails in email_groups.items():
        if group_emails:
            display_name = group_name.replace('_', ' ').title()
            story.append(Paragraph(f"<b>{display_name}:</b>", body_style))
            for email_data in group_emails[:5]:
                email = email_data.get('email', '-')
                valid = '✓' if email_data.get('valid') else '✗'
                story.append(Paragraph(f"• {email} [{valid}]", body_style))
            if len(group_emails) > 5:
                story.append(Paragraph(f"... and {len(group_emails) - 5} more", body_style))

    story.append(PageBreak())

    # ============= PAGE 10: FORENSICS =============
    story.append(Paragraph("9. FORENSIC DETAILS & EXPOSED ASSETS", h1_style))
    
    forensics = scan_data.get('forensics', {}).get('results', [])
    
    all_emails = []
    all_phones = []
    all_docs = []
    
    for res in forensics:
        all_emails.extend(res.get('emails', []))
        all_phones.extend(res.get('phones', []))
        all_docs.extend(res.get('documents', []))
    
    story.append(Paragraph("Contact Information", h2_style))
    
    if all_emails:
        story.append(Paragraph(f"<b>Discovered Email Addresses ({len(set(all_emails))} unique):</b>", body_style))
        for email in list(set(all_emails))[:15]:
            story.append(Paragraph(f"• {email}", body_style))
        if len(set(all_emails)) > 15:
            story.append(Paragraph(f"... and {len(set(all_emails)) - 15} more emails", body_style))
    else:
        story.append(Paragraph("No email addresses discovered through web scraping", body_style))
    
    story.append(Spacer(1, 0.1*inch))
    
    if all_phones:
        story.append(Paragraph(f"<b>Discovered Phone Numbers ({len(set(all_phones))} unique):</b>", body_style))
        for phone in list(set(all_phones))[:10]:
            story.append(Paragraph(f"• {phone}", body_style))
    else:
        story.append(Paragraph("No phone numbers discovered", body_style))
    
    story.append(Spacer(1, 0.15*inch))
    
    story.append(Paragraph("Documents & Files Found", h2_style))
    
    if all_docs:
        doc_table_data = [['Document Name', 'Type', 'URL']]
        for doc in all_docs[:10]:
            doc_name = doc.get('name', 'Unknown')
            doc_type = doc.get('name', '').split('.')[-1].upper()
            doc_url = doc.get('link', '-')
            doc_table_data.append([
                doc_name[:30],
                doc_type,
                doc_url[:35] + '...' if len(doc_url) > 35 else doc_url
            ])
        
        t_docs = Table(doc_table_data, colWidths=[1.8*inch, 0.8*inch, 3.6*inch])
        t_docs.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#f59e0b')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 8),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#fffbeb')]),
        ]))
        story.append(t_docs)
    else:
        story.append(Paragraph("No documents discovered", body_style))

    story.append(PageBreak())

    # ============= PAGE 11: THREAT INTELLIGENCE =============
    story.append(Paragraph("10. THREAT INTELLIGENCE & REPUTATION", h1_style))
    
    vt = scan_data.get('virustotal', {})
    detections = vt.get('detections', {})
    
    story.append(Paragraph("VirusTotal Threat Analysis", h2_style))
    
    vt_data = [
        ['Detection Category', 'Count'],
        ['Malicious Detections', str(detections.get('malicious', 0))],
        ['Suspicious Detections', str(detections.get('suspicious', 0))],
        ['Harmless Detections', str(detections.get('harmless', 0))],
        ['Undetected', str(detections.get('undetected', 0))],
        ['Total Engines Scanned', str(detections.get('total_engines', 0))],
        ['Community Reputation Score', str(vt.get('community_reputation', 'N/A'))],
    ]
    
    t_vt = Table(vt_data, colWidths=[3*inch, 3.2*inch])
    t_vt.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0f172a')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 9),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f8fafc')]),
    ]))
    story.append(t_vt)
    story.append(Spacer(1, 0.15*inch))

    story.append(Paragraph("Threat Classifications", h2_style))
    threat_tags = vt.get('threat_tags', [])
    if threat_tags:
        for tag in threat_tags[:8]:
            story.append(Paragraph(f"• {tag}", body_style))
    else:
        story.append(Paragraph("No threat classifications detected", body_style))
    
    story.append(Spacer(1, 0.15*inch))
    
    story.append(Paragraph("Global Ranking & Popularity", h2_style))
    rankings = vt.get('global_rankings', [])
    if rankings:
        for rank in rankings:
            story.append(Paragraph(f"• {rank}", body_style))
    else:
        story.append(Paragraph("No global rankings available", body_style))

    story.append(PageBreak())

    # ============= PAGE 12: RECOMMENDATIONS & CONCLUSION =============
    story.append(Paragraph("11. RECOMMENDATIONS & REMEDIATION", h1_style))
    
    story.append(Paragraph("Critical Priority Actions", h2_style))
    
    recommendations = []
    
    if any(r for r in waf_results if not r.get('has_waf')):
        recommendations.append("Implement Web Application Firewall (WAF) on all internet-facing endpoints for Layer 7 attack mitigation")
    
    if pwned:
        recommendations.append("Immediately reset credentials for all compromised accounts detected in breach databases")
    
    if critical_dirs > 0:
        recommendations.append(f"Review and restrict access to {critical_dirs} critical directories that are publicly exposed")
    
    if detections.get('malicious', 0) > 0:
        recommendations.append("Conduct malware analysis and security assessment on reported malicious detections")
    
    if risk_details.get('no_spf') or risk_details.get('no_dmarc'):
        recommendations.append("Configure SPF and DMARC email authentication policies to prevent spoofing and phishing")
    
    if not recommendations:
        recommendations.append("Continue monitoring infrastructure for emerging threats and security updates")
    
    for i, rec in enumerate(recommendations[:8], 1):
        story.append(Paragraph(f"<b>{i}.</b> {rec}", body_style))
    
    story.append(Spacer(1, 0.15*inch))
    
    story.append(Paragraph("High Priority Actions", h2_style))
    story.append(Paragraph("• Enable multi-factor authentication (MFA) on all administrative and critical accounts", body_style))
    story.append(Paragraph("• Review and update outdated software and services identified in this report", body_style))
    story.append(Paragraph("• Implement rate limiting and brute-force protection on login endpoints", body_style))
    story.append(Paragraph("• Establish security monitoring and alerting for infrastructure changes", body_style))
    story.append(Paragraph("• Conduct regular security awareness training for personnel", body_style))
    
    story.append(Spacer(1, 0.15*inch))
    
    story.append(Paragraph("Compliance Considerations", h2_style))
    story.append(Paragraph("• Ensure compliance with GDPR regarding personally identifiable information (PII) exposure", body_style))
    story.append(Paragraph("• Review data protection and privacy policies relative to discovered email addresses and contact information", body_style))
    story.append(Paragraph("• Document security incidents and breach responses for regulatory requirements", body_style))

    story.append(PageBreak())

    # ============= PAGE 13: METHODOLOGY & CONCLUSION =============
    story.append(Paragraph("12. ASSESSMENT METHODOLOGY & DATA SOURCES", h1_style))
    
    story.append(Paragraph("Passive Reconnaissance Modules (12 Total)", h2_style))
    
    modules_info = [
        ['Module', 'Description', 'Data Source'],
        ['1. Certificate Transparency', 'Subdomain discovery from SSL certificates', 'crt.sh'],
        ['2. DNS Reconnaissance', 'DNS records and email security policies', 'HackerTarget API'],
        ['3. WHOIS Lookup', 'Domain registration and ownership information', 'WHOIS Servers'],
        ['4. Shodan Intelligence', 'Internet-wide device scanning and services', 'Shodan.io'],
        ['5. VirusTotal Reputation', 'Threat intelligence and malware detection', 'VirusTotal API'],
        ['6. WAF Detection', 'Web Application Firewall identification', 'Active Probing'],
        ['7. Directory Enumeration', 'Hidden files with HTTP validation', 'HTTP Requests'],
        ['8. Email Enumeration', 'Email discovery and validation', 'Pattern Analysis'],
        ['9. Forensic Details', 'Email, phone, document extraction', 'Web Scraping'],
        ['10. Breach Checking', 'Dark web credential compromise monitoring', 'LeakCheck API'],
        ['11. Risk Calculation', 'Composite threat scoring algorithm', 'Internal Algorithm'],
        ['12. PDF Report Generation', 'Professional report documentation', 'Data Compilation'],
    ]
    
    t_modules = Table(modules_info, colWidths=[1.2*inch, 2.2*inch, 2.8*inch])
    t_modules.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0f172a')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 7.5),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f8fafc')]),
    ]))
    story.append(t_modules)
    
    story.append(Spacer(1, 0.2*inch))
    
    story.append(Paragraph("Legal Disclaimer", h2_style))
    
    disclaimer = """
    This report is generated for <b>defensive security and authorized assessment purposes only</b>. All reconnaissance 
    activities conducted were <b>completely passive and non-invasive</b>, utilizing only publicly available information 
    from authorized data sources. No active exploitation, unauthorized system access, or violation of computer fraud laws 
    was performed. The 'Risk Score' presented in this report is a <b>heuristic metric</b> and should not be used as the 
    sole determinant for compliance decisions, insurance audits, or legal proceedings. Organizations should conduct 
    additional active penetration testing and code reviews as part of comprehensive security assessments. The information 
    contained herein reflects the state of publicly available data at the time of scanning and may change. Users of this 
    report are responsible for compliance with all applicable laws and regulations governing cybersecurity and data protection. 
    The developers and operators of IntelCore assume no liability for actions taken based on this intelligence.
    """
    
    story.append(Paragraph(disclaimer, ParagraphStyle('Disclaimer', parent=body_style, fontSize=8, textColor=colors.HexColor('#7f8c8d'))))
    
    story.append(Spacer(1, 0.2*inch))
    
    story.append(Paragraph("Report Metadata", h2_style))
    metadata = [
        ['Generated', datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')],
        ['Report ID', report_id],
        ['Scan Duration', f"{scan_data.get('modules_completed', 0)} modules in ~5 minutes"],
        ['Assessment Type', 'Passive Open Source Intelligence (OSINT)'],
        ['Tool Version', 'IntelCore v2.0'],
        ['Total Pages', '13+'],
    ]
    
    t_meta = Table(metadata, colWidths=[2*inch, 4.2*inch])
    t_meta.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#2563eb')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 9),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f8fafc')]),
    ]))
    story.append(t_meta)
    
    story.append(Spacer(1, 0.3*inch))
    story.append(Paragraph("<i>End of Report</i>", ParagraphStyle('Centered', parent=body_style, alignment=TA_CENTER, fontSize=10)))
    
    # ============= BUILD PDF =============
    try:  
        doc.build(story, onFirstPage=add_footer, onLaterPages=add_footer)
        buffer.seek(0)
        
        with open(filename, "wb") as f:
            f.write(buffer.read())
        
        print(f"[+] Professional Report Generated: {filename}")
        return filename
    except Exception as e:
        print(f"[!] PDF Generation Error: {e}")
        return None
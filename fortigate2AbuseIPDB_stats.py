#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FortiGate Security Report - Outlook Compatible Version
Uses table-based layout and inline styles for maximum compatibility
Modified version with IPS/DoS/Brute Force categories
"""

import re
import os
import json
import smtplib
import ipaddress
import time
import pickle
import base64
from datetime import datetime, timedelta
from collections import defaultdict
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

# Configuration
CONFIG = {
    'log_file': '/var/log/fortigate_quarantine.log',
    'fortigate_list': '/opt/FortiGateToAbuseIPDB/fortigate.list',
    'whois_cache_file': '/tmp/fortigate_whois_cache.pkl',
    'smtp_server': 'your.smtp.server',
    'smtp_port': 587,
    'smtp_user': 'your-smtp-user@example.com',
    'smtp_pass': 'your-smtp-password',
    'sender': 'fortigate@example.com',
    'recipient': 'security@example.com',
}

def safe_str(text):
    """Safely convert text"""
    if isinstance(text, bytes):
        text = text.decode('utf-8', errors='replace')
    return ''.join(char if ord(char) < 128 else '?' for char in text)

def load_whois_cache():
    """Load WHOIS cache from file"""
    try:
        if os.path.exists(CONFIG['whois_cache_file']):
            with open(CONFIG['whois_cache_file'], 'rb') as f:
                cache = pickle.load(f)
                current_time = time.time()
                cleaned_cache = {}
                for ip, data in cache.items():
                    if current_time - data.get('timestamp', 0) < 604800:  # 7 days
                        cleaned_cache[ip] = data
                return cleaned_cache
    except:
        pass
    return {}

def save_whois_cache(cache):
    """Save WHOIS cache to file"""
    try:
        with open(CONFIG['whois_cache_file'], 'wb') as f:
            pickle.dump(cache, f)
    except:
        pass

def get_whois_info_cached(ip, cache):
    """Get WHOIS info with caching"""
    import subprocess
    import re
    
    if ip in cache:
        print(f"    Using cached WHOIS for {ip}")
        return cache[ip]['data']
    
    whois_data = {
        'country': 'Unknown',
        'organization': 'Unknown',
        'asn': 'Unknown'
    }
    
    try:
        time.sleep(1)
        
        servers = [None, 'whois.ripe.net', 'whois.arin.net', 'whois.apnic.net']
        
        output = ""
        for server in servers:
            try:
                if server:
                    cmd = ['whois', '-h', server, ip]
                else:
                    cmd = ['whois', ip]
                
                result = subprocess.run(cmd, capture_output=True, text=True, 
                                      timeout=15, encoding='utf-8', errors='replace')
                
                if result.returncode == 0 and result.stdout and len(result.stdout) > 100:
                    output = result.stdout
                    break
            except:
                continue
        
        if output:
            lines = output.split('\n')
            
            for line in lines:
                line = line.strip()
                
                if whois_data['country'] == 'Unknown':
                    country_match = re.search(r'(?i)country.*?:\s*([A-Z]{2})\b', line)
                    if country_match:
                        whois_data['country'] = country_match.group(1).upper()
                
                if whois_data['organization'] == 'Unknown':
                    org_match = re.search(r'(?i)^(org-?name|organization|org|netname|owner|descr):\s*(.+)', line)
                    if org_match:
                        org = org_match.group(2).strip()
                        if org and len(org) > 2 and not org.startswith('%'):
                            if not any(skip in org.lower() for skip in ['ripe', 'arin', 'apnic', 'lacnic', 'afrinic']):
                                whois_data['organization'] = safe_str(org[:100])
                
                if whois_data['asn'] == 'Unknown':
                    asn_match = re.search(r'(?:AS|as)(\d+)', line)
                    if asn_match:
                        whois_data['asn'] = f"AS{asn_match.group(1)}"
        
        # Special handling for known ranges
        if whois_data['organization'] == 'Unknown':
            if ip.startswith(('142.250.', '172.217.', '216.58.', '172.253.')):
                whois_data['organization'] = 'Google LLC'
                whois_data['country'] = 'US'
                whois_data['asn'] = 'AS15169'
            elif ip.startswith(('157.240.', '31.13.', '66.220.', '69.63.', '74.119.76.')):
                whois_data['organization'] = 'Meta Platforms, Inc.'
                whois_data['country'] = 'US'
                whois_data['asn'] = 'AS32934'
            elif ip.startswith(('104.16.', '104.17.', '104.18.', '104.19.', '172.64.', '172.65.', '172.66.', '172.67.')):
                whois_data['organization'] = 'Cloudflare, Inc.'
                whois_data['country'] = 'US'
                whois_data['asn'] = 'AS13335'
                
    except Exception as e:
        print(f"    WHOIS error for {ip}: {str(e)[:30]}")
    
    cache[ip] = {
        'data': whois_data,
        'timestamp': time.time()
    }
    
    return whois_data

def parse_log_file(log_path):
    """Parse log file - Modified to handle IPS/DoS/Administrative categories"""
    stats = defaultdict(lambda: {"IPS": defaultdict(int), "DoS": defaultdict(int), "Brute Force": defaultdict(int)})
    ipv4_count = 0
    ipv6_count = 0
    current_fortigate = "unknown"
    
    print(f"Parsing {log_path}...")
    
    try:
        with open(log_path, 'r', encoding='utf-8', errors='replace') as f:
            lines = f.readlines()
    except Exception as e:
        print(f"Error reading file: {e}")
        return {}
    
    patterns = {
        'fortigate': re.compile(r'Elaborazione FortiGate con ID:\s+(\S+)'),
        'fortigate_v2': re.compile(r'\[INFO\] - Processing FortiGate:\s+([^\s(]+)'),
        'banned_ip': re.compile(r'Found banned IP:\s+([\d.]+|[0-9a-fA-F:]+)\s+\(cause:\s+(\w+)\)', re.IGNORECASE)
    }
    
    # Debug counters
    debug_counts = {"IPS": 0, "DOS": 0, "ADMINISTRATIVE": 0}
    
    for line_num, line in enumerate(lines, 1):
        try:
            line = line.strip()
            
            # Check for FortiGate identification
            for pattern_name in ['fortigate', 'fortigate_v2']:
                match = patterns[pattern_name].search(line)
                if match:
                    current_fortigate = match.group(1)
                    break
            
            # Check ONLY for the current format with cause
            match = patterns['banned_ip'].search(line)
            if match:
                ip = match.group(1)
                cause = match.group(2).upper()
                
                if ':' in ip:
                    ipv6_count += 1
                else:
                    ipv4_count += 1
                
                # Map causes to categories (case-insensitive)
                cause_upper = cause.upper()
                
                # Debug counter
                debug_counts[cause_upper] = debug_counts.get(cause_upper, 0) + 1
                if cause_upper == 'IPS':
                    stats[current_fortigate]["IPS"][ip] += 1
                elif cause_upper == 'DOS':
                    stats[current_fortigate]["DoS"][ip] += 1
                elif cause_upper == 'ADMINISTRATIVE':
                    stats[current_fortigate]["Brute Force"][ip] += 1
                    
        except Exception as e:
            if line_num % 1000 == 0:
                print(f"  Warning: Error processing line {line_num}: {e}")
            continue
    
    print(f"  Parsed {ipv4_count} IPv4 and {ipv6_count} IPv6 events")
    print(f"  Debug - IPS: {debug_counts.get('IPS', 0)}, DOS: {debug_counts.get('DOS', 0)}, ADMINISTRATIVE: {debug_counts.get('ADMINISTRATIVE', 0)}")
    print(f"  FortiGates processed: {len(stats)}")
    
    # Additional debugging
    total_events = sum(debug_counts.values())
    if total_events == 0:
        print(f"  WARNING: No events found! Check log format.")
        print(f"  Expected format: 'Found banned IP: <ip> (cause: <cause>)'")
    return dict(stats)

def load_fortigate_list():
    """Load FortiGate list"""
    fortigates = {}
    
    try:
        with open(CONFIG['fortigate_list'], 'r', encoding='utf-8', errors='replace') as f:
            lines = f.readlines()
        
        for line in lines:
            if line.strip():
                parts = line.strip().split()
                if len(parts) >= 2:
                    fortigates[parts[1]] = parts[0]
    except Exception as e:
        print(f"Error loading FortiGate list: {e}")
    
    print(f"Loaded {len(fortigates)} FortiGate configurations")
    return fortigates

def get_top_attackers_simple(stats):
    """Get top attackers (all categories combined)"""
    attackers = defaultdict(int)
    
    for fw, data in stats.items():
        for category in ["IPS", "DoS", "Brute Force"]:
            for ip, count in data.get(category, {}).items():
                attackers[ip] += count
    
    networks = defaultdict(lambda: {'ips': [], 'count': 0})
    
    for ip, count in attackers.items():
        if ':' not in ip:  # IPv4
            try:
                network = str(ipaddress.IPv4Network(f"{ip}/24", strict=False))
                networks[network]['ips'].append({'ip': ip, 'count': count})
                networks[network]['count'] += count
            except:
                networks[f"{ip}/32"]['ips'].append({'ip': ip, 'count': count})
                networks[f"{ip}/32"]['count'] += count
        else:  # IPv6
            networks[f"{ip}/128"]['ips'].append({'ip': ip, 'count': count})
            networks[f"{ip}/128"]['count'] += count
    
    sorted_networks = sorted(networks.items(), key=lambda x: x[1]['count'], reverse=True)[:10]
    
    result = []
    for cidr, data in sorted_networks:
        data['ips'].sort(key=lambda x: x['count'], reverse=True)
        result.append({
            'cidr': cidr,
            'ips': data['ips'],
            'count': data['count'],
            'is_ipv6': ':' in data['ips'][0]['ip']
        })
    
    return result

def generate_outlook_report(stats, fortigates, top_attackers, whois_cache):
    """Generate Outlook-compatible HTML report using tables only - Modified for 3 attack categories"""
    current_date = datetime.now().strftime("%d/%m/%Y %H:%M")
    
    # Load and encode logo
    logo_base64 = ""
    logo_path = "/opt/FortiGateToAbuseIPDB/logo.png"
    try:
        if os.path.exists(logo_path):
            print(f"Logo found at: {logo_path}")
            with open(logo_path, "rb") as img_file:
                logo_data = img_file.read()
                logo_base64 = base64.b64encode(logo_data).decode('utf-8')
                print(f"Logo loaded successfully, size: {len(logo_data)} bytes")
        else:
            print(f"WARNING: Logo not found at: {logo_path}")
    except Exception as e:
        print(f"ERROR loading logo: {e}")
    
    # Calculate statistics
    total_attacks = 0
    attack_types = defaultdict(int)
    fortigate_stats = {}
    fortigate_detailed_stats = {}
    
    for fw, data in stats.items():
        fw_total = 0
        fw_details = {"IPS": 0, "DoS": 0, "Brute Force": 0}
        for attack_type, ips in data.items():
            for ip, count in ips.items():
                total_attacks += count
                attack_types[attack_type] += count
                fw_total += count
                fw_details[attack_type] += count
        fortigate_stats[fw] = fw_total
        fortigate_detailed_stats[fw] = fw_details
    
    # Calculate cache date range
    cache_dates = []
    if whois_cache:
        for ip, data in whois_cache.items():
            if 'timestamp' in data:
                cache_dates.append(data['timestamp'])
    
    if cache_dates:
        oldest_timestamp = min(cache_dates)
        newest_timestamp = max(cache_dates)
        oldest_cache = datetime.fromtimestamp(oldest_timestamp).strftime("%d/%m/%Y")
        newest_cache = datetime.fromtimestamp(newest_timestamp).strftime("%d/%m/%Y")
        current_time = time.time()
        days_since_oldest = (current_time - oldest_timestamp) / 86400
        days_since_newest = (current_time - newest_timestamp) / 86400
        days_until_expiry = 7 - days_since_newest
        
        if days_until_expiry > 0:
            cache_range = f"{oldest_cache} - {newest_cache} (oldest: {days_since_oldest:.1f} days, expires in {days_until_expiry:.1f} days)"
        else:
            cache_range = f"{oldest_cache} - {newest_cache} (oldest: {days_since_oldest:.1f} days, expired)"
    else:
        cache_range = "No cached data"
    
    # Add WHOIS info
    print("\nLooking up WHOIS information...")
    for i, network in enumerate(top_attackers):
        if network['ips']:
            first_ip = network['ips'][0]['ip']
            print(f"  [{i+1}/{len(top_attackers)}] Checking {first_ip}...")
            whois_info = get_whois_info_cached(first_ip, whois_cache)
            network['whois'] = whois_info
    
    save_whois_cache(whois_cache)
    
    # Outlook-compatible HTML using tables
    html = """<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
    <title>FortiGate Security Report</title>
    <!--[if mso]>
    <noscript>
        <xml>
            <o:OfficeDocumentSettings>
                <o:PixelsPerInch>96</o:PixelsPerInch>
            </o:OfficeDocumentSettings>
        </xml>
    </noscript>
    <![endif]-->
</head>
<body style="margin: 0; padding: 0; background-color: #f0f2f5; font-family: Arial, sans-serif;">
    <table border="0" cellpadding="0" cellspacing="0" width="100%" style="background-color: #f0f2f5;">
        <tr>
            <td align="center" style="padding: 40px 0;">
                <!-- Main Container - INCREASED TO 1100px -->
                <table border="0" cellpadding="0" cellspacing="0" width="1100" style="background-color: #ffffff;">
                    <!-- Header -->
                    <tr>
                        <td>
                            <table border="0" cellpadding="0" cellspacing="0" width="100%" style="background-color: #0a0e27;">
                                <tr>
                                    <td style="padding: 40px 30px; color: #ffffff;">
                                        <table width="100%" border="0" cellpadding="0" cellspacing="0">
                                            <tr>"""
    
    # Add logo if available
    if logo_base64:
        print("Adding logo to HTML report...")
        html += """
                                                <!-- Logo Column -->
                                                <td width="100" valign="top" style="padding-right: 30px;">
                                                    <img src="data:image/png;base64,""" + logo_base64 + """" 
                                                         alt="Goline Logo" 
                                                         style="display: block; border: 0; max-width: 100px; height: auto;">
                                                </td>
                                                <!-- Content Column -->
                                                <td valign="top">
                                                    <h1 style="margin: 0 0 20px 0; font-size: 32px; font-weight: bold; color: #ffffff;">
                                                        FortiGate Security Intelligence Report
                                                    </h1>
                                                    <table border="0" cellpadding="0" cellspacing="0" width="100%">
                                                        <tr>
                                                            <td style="background-color: rgba(255,255,255,0.1); color: #ffffff; padding: 15px;">
                                                                <strong>&#128197; Generated:</strong> """ + current_date + """<br/>
                                                                <strong>&#127760; Network:</strong> Goline Infrastructure<br/>
                                                                <strong>&#127970; Organization:</strong> GOLINE - Security Operations Center<br/>
                                                                <strong>&#128200; WHOIS Cache Period:</strong> """ + cache_range + """
                                                            </td>
                                                        </tr>
                                                    </table>
                                                </td>"""
    else:
        html += """
                                                <td valign="top">
                                                    <h1 style="margin: 0 0 20px 0; font-size: 32px; font-weight: bold; color: #ffffff;">
                                                        FortiGate Security Intelligence Report
                                                    </h1>
                                                    <table border="0" cellpadding="0" cellspacing="0" width="100%">
                                                        <tr>
                                                            <td style="background-color: rgba(255,255,255,0.1); color: #ffffff; padding: 15px;">
                                                                <strong>&#128197; Generated:</strong> """ + current_date + """<br/>
                                                                <strong>&#127760; Network:</strong> Goline Infrastructure<br/>
                                                                <strong>&#127970; Organization:</strong> GOLINE - Security Operations Center<br/>
                                                                <strong>&#128200; WHOIS Cache Period:</strong> """ + cache_range + """
                                                            </td>
                                                        </tr>
                                                    </table>
                                                </td>"""
    
    html += """
                                            </tr>
                                        </table>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>
                    
                    <!-- Statistics Grid - 5 boxes in optimized layout -->
                    <tr>
                        <td style="padding: 30px;">
                            <!-- First row - 2 main boxes -->
                            <table border="0" cellpadding="0" cellspacing="8" width="100%">
                                <tr>
                                    <!-- Total Attacks -->
                                    <td width="49%" valign="top">
                                        <table border="0" cellpadding="0" cellspacing="0" width="100%" style="border: 1px solid #e0e0e0;">
                                            <tr>
                                                <td style="padding: 25px; text-align: center; background-color: #ffffff;">
                                                    <div style="font-size: 40px; font-weight: bold; color: #d32f2f; margin-bottom: 10px; font-family: monospace;">
                                                        """ + f"{total_attacks:,}" + """
                                                    </div>
                                                    <div style="font-size: 13px; color: #666; text-transform: uppercase; letter-spacing: 1px;">
                                                        &#9876; Total Attacks Blocked
                                                    </div>
                                                </td>
                                            </tr>
                                        </table>
                                    </td>
                                    <td width="2%">&nbsp;</td>
                                    <!-- Protected FortiGates -->
                                    <td width="49%" valign="top">
                                        <table border="0" cellpadding="0" cellspacing="0" width="100%" style="border: 1px solid #e0e0e0;">
                                            <tr>
                                                <td style="padding: 25px; text-align: center; background-color: #ffffff;">
                                                    <div style="font-size: 40px; font-weight: bold; color: #388e3c; margin-bottom: 10px;">
                                                        """ + f"{len(fortigates)}" + """
                                                    </div>
                                                    <div style="font-size: 13px; color: #666; text-transform: uppercase; letter-spacing: 1px;">
                                                        &#128737; Protected FortiGates
                                                    </div>
                                                </td>
                                            </tr>
                                        </table>
                                    </td>
                                </tr>
                            </table>
                            
                            <!-- Spacer -->
                            <div style="height: 12px;"></div>
                            
                            <!-- Second row - 3 attack type boxes -->
                            <table border="0" cellpadding="0" cellspacing="8" width="100%">
                                <tr>
                                    <!-- IPS -->
                                    <td width="32%" valign="top">
                                        <table border="0" cellpadding="0" cellspacing="0" width="100%" style="border: 1px solid #e0e0e0;">
                                            <tr>
                                                <td style="padding: 20px 15px; text-align: center; background-color: #ffffff;">
                                                    <div style="font-size: 36px; font-weight: bold; color: #f57c00; margin-bottom: 8px; font-family: monospace;">
                                                        """ + f"{attack_types.get('IPS', 0):,}" + """
                                                    </div>
                                                    <div style="font-size: 11px; color: #666; text-transform: uppercase; letter-spacing: 0.5px;">
                                                        &#128683; IPS
                                                    </div>
                                                </td>
                                            </tr>
                                        </table>
                                    </td>
                                    <td width="2%">&nbsp;</td>
                                    <!-- DoS -->
                                    <td width="32%" valign="top">
                                        <table border="0" cellpadding="0" cellspacing="0" width="100%" style="border: 1px solid #e0e0e0;">
                                            <tr>
                                                <td style="padding: 20px 15px; text-align: center; background-color: #ffffff;">
                                                    <div style="font-size: 36px; font-weight: bold; color: #e91e63; margin-bottom: 8px; font-family: monospace;">
                                                        """ + f"{attack_types.get('DoS', 0):,}" + """
                                                    </div>
                                                    <div style="font-size: 11px; color: #666; text-transform: uppercase; letter-spacing: 0.5px;">
                                                        &#128680; DoS
                                                    </div>
                                                </td>
                                            </tr>
                                        </table>
                                    </td>
                                    <td width="2%">&nbsp;</td>
                                    <!-- BRUTE FORCE - usando AUTH come abbreviazione -->
                                    <td width="32%" valign="top">
                                        <table border="0" cellpadding="0" cellspacing="0" width="100%" style="border: 1px solid #e0e0e0;">
                                            <tr>
                                                <td style="padding: 20px 15px; text-align: center; background-color: #ffffff;">
                                                    <div style="font-size: 36px; font-weight: bold; color: #7b1fa2; margin-bottom: 8px; font-family: monospace;">
                                                        """ + f"{attack_types.get('Brute Force', 0):,}" + """
                                                    </div>
                                                    <div style="font-size: 11px; color: #666; text-transform: uppercase; letter-spacing: 0.5px;">
                                                        &#128272; Brute force
                                                    </div>
                                                </td>
                                            </tr>
                                        </table>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>
                    
                    <!-- Top Attackers Table -->
                    <tr>
                        <td style="padding: 0 30px 30px 30px;">
                            <h2 style="color: #2c3e50; margin: 0 0 20px 0;">&#127919; Top Attacking Networks</h2>
                            <table border="1" cellpadding="0" cellspacing="0" width="100%" style="border-collapse: collapse; border-color: #dee2e6;">
                                <tr style="background-color: #f8f9fa;">
                                    <th style="padding: 15px; text-align: left; font-weight: 600; color: #495057; width: 5%;">#</th>
                                    <th style="padding: 15px; text-align: left; font-weight: 600; color: #495057; width: 30%;">Attacker IPs</th>
                                    <th style="padding: 15px; text-align: left; font-weight: 600; color: #495057; width: 15%;">CIDR to Block</th>
                                    <th style="padding: 15px; text-align: left; font-weight: 600; color: #495057; width: 30%;">WHOIS Info</th>
                                    <th style="padding: 15px; text-align: center; font-weight: 600; color: #495057; width: 10%;">Attacks</th>
                                    <th style="padding: 15px; text-align: center; font-weight: 600; color: #495057; width: 10%;">Severity</th>
                                </tr>
"""
    
    for idx, network in enumerate(top_attackers, 1):
        # Determine severity
        if network['count'] > 1000:
            severity = '<span style="background-color: #dc3545; color: white; padding: 4px 12px; border-radius: 3px;">CRITICAL</span>'
        elif network['count'] > 500:
            severity = '<span style="background-color: #fd7e14; color: white; padding: 4px 12px; border-radius: 3px;">HIGH</span>'
        else:
            severity = '<span style="background-color: #ffc107; color: #212529; padding: 4px 12px; border-radius: 3px;">MEDIUM</span>'
        
        # Format IPs
        ip_display = ''
        for i, item in enumerate(network['ips'][:3]):
            ip_display += f'<span style="font-family: monospace; background-color: #e9ecef; padding: 2px 4px;">{item["ip"]}</span> ({item["count"]} attacks)<br/>'
        if len(network['ips']) > 3:
            ip_display += f'<em>... and {len(network["ips"]) - 3} more IPs</em>'
        
        # WHOIS info
        whois_display = ''
        if 'whois' in network:
            whois = network['whois']
            org_name = whois["organization"]
            if len(org_name) > 50:
                org_name = org_name[:50] + '...'
            whois_display = f"""
                <strong>Country:</strong> {whois["country"]}<br/>
                <strong>Org:</strong> {org_name}<br/>
                <strong>ASN:</strong> {whois["asn"]}
            """
        else:
            whois_display = 'No WHOIS data'
        
        html += f"""
                                <tr>
                                    <td style="padding: 15px; border-color: #dee2e6;">{idx}</td>
                                    <td style="padding: 15px; border-color: #dee2e6;">{ip_display}</td>
                                    <td style="padding: 15px; border-color: #dee2e6;">
                                        <span style="background-color: #28a745; color: white; padding: 4px 8px; font-family: monospace;">
                                            {network['cidr']}
                                        </span>
                                    </td>
                                    <td style="padding: 15px; border-color: #dee2e6; font-size: 13px;">{whois_display}</td>
                                    <td style="padding: 15px; text-align: center; font-weight: bold; color: #dc3545; border-color: #dee2e6;">
                                        {network['count']:,}
                                    </td>
                                    <td style="padding: 15px; text-align: center; border-color: #dee2e6;">{severity}</td>
                                </tr>
"""
    
    html += """
                            </table>
                        </td>
                    </tr>
                    
                    <!-- FortiGate Status - Modified to show attack breakdown -->
                    <tr>
                        <td style="padding: 0 30px 30px 30px;">
                            <h2 style="color: #2c3e50; margin: 20px 0;">&#128274; FortiGate Status</h2>
                            <table border="1" cellpadding="0" cellspacing="0" width="100%" style="border-collapse: collapse; border-color: #dee2e6;">
                                <tr style="background-color: #f8f9fa;">
                                    <th style="padding: 15px; text-align: left; font-weight: 600; color: #495057; width: 5%;">#</th>
                                    <th style="padding: 15px; text-align: left; font-weight: 600; color: #495057; width: 23%;">Name</th>
                                    <th style="padding: 15px; text-align: left; font-weight: 600; color: #495057; width: 15%;">IP Address</th>
                                    <th style="padding: 15px; text-align: center; font-weight: 600; color: #495057; width: 10%;">IPS</th>
                                    <th style="padding: 15px; text-align: center; font-weight: 600; color: #495057; width: 10%;">DoS</th>
                                    <th style="padding: 15px; text-align: center; font-weight: 600; color: #495057; width: 12%; white-space: nowrap;">Brute Force</th>
                                    <th style="padding: 15px; text-align: center; font-weight: 600; color: #495057; width: 10%;">Total</th>
                                    <th style="padding: 15px; text-align: center; font-weight: 600; color: #495057; width: 15%;">Status</th>
                                </tr>
"""
    
    # SORT FORTIGATES BY TOTAL NUMBER OF ATTACKS (DESCENDING)
    sorted_fortigates = sorted(fortigates.items(), key=lambda x: fortigate_stats.get(x[0], 0), reverse=True)
    
    for idx, (name, ip) in enumerate(sorted_fortigates, 1):
        attacks = fortigate_stats.get(name, 0)
        details = fortigate_detailed_stats.get(name, {"IPS": 0, "DoS": 0, "Brute Force": 0})
        
        # Status based on total attacks
        if attacks == 0:
            status = '<span style="color: #6c757d;">&#9679;</span> No Activity'
            row_style = 'background-color: #f8f9fa;'
        elif attacks <= 50:
            status = '<span style="color: #007bff;">&#9679;</span> Low Activity'
            row_style = ''
        elif attacks <= 100:
            status = '<span style="color: #ffc107;">&#9679;</span> Medium Activity'
            row_style = 'background-color: #fff3cd;'
        else:
            status = '<span style="color: #dc3545;">&#9679;</span> High Activity'
            row_style = 'background-color: #e3f2fd;'  # AZZURRO CHIARO invece di rosa
        
        html += f"""
                                <tr style="{row_style}">
                                    <td style="padding: 15px; border-color: #dee2e6;">{idx}</td>
                                    <td style="padding: 15px; border-color: #dee2e6; font-weight: {'bold' if attacks > 100 else 'normal'};">{name}</td>
                                    <td style="padding: 15px; border-color: #dee2e6; font-family: monospace;">
                                        {ip}
                                    </td>
                                    <td style="padding: 15px; text-align: center; border-color: #dee2e6; color: #f57c00; font-family: monospace;">
                                        {details['IPS']:,}
                                    </td>
                                    <td style="padding: 15px; text-align: center; border-color: #dee2e6; color: #e91e63; font-family: monospace;">
                                        {details['DoS']:,}
                                    </td>
                                    <td style="padding: 15px; text-align: center; border-color: #dee2e6; color: #7b1fa2; font-family: monospace;">
                                        {details['Brute Force']:,}
                                    </td>
                                    <td style="padding: 15px; text-align: center; border-color: #dee2e6; font-weight: bold; color: {'#dc3545' if attacks > 100 else '#212529'}; font-family: monospace;">
                                        {attacks:,}
                                    </td>
                                    <td style="padding: 15px; text-align: center; border-color: #dee2e6;">{status}</td>
                                </tr>
"""
    
    html += """
                            </table>
                        </td>
                    </tr>
                    
                    <!-- Footer -->
                    <tr>
                        <td style="background-color: #f8f9fa; padding: 30px; text-align: center; color: #6c757d; font-size: 14px;">
                            <div style="font-size: 32px; margin-bottom: 15px;">&#128737;</div>
                            <strong>FortiGate Security Intelligence System</strong><br/>
                            Goline SA - Security Operations Center<br/>
                            Report generated on """ + datetime.now().strftime("%B %d, %Y at %H:%M:%S") + """<br/>
                            <br/>
                            <span style="font-size: 12px; color: #999;">
                                WHOIS data cached for performance. Cache expires after 7 days.
                            </span>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>
"""
    
    return html

def main():
    """Main function"""
    print("\n" + "="*60)
    print("FortiGate Security Report - IPS/DoS/Brute Force Categories")
    print("="*60 + "\n")
    
    try:
        # Load WHOIS cache
        print("Loading WHOIS cache...")
        whois_cache = load_whois_cache()
        print(f"  Loaded {len(whois_cache)} cached entries")
        
        # Load FortiGates
        print("\nStep 1: Loading FortiGate list...")
        fortigates = load_fortigate_list()
        
        # Parse log
        print("\nStep 2: Parsing log file...")
        stats = parse_log_file(CONFIG['log_file'])
        
        # Get top attackers
        print("\nStep 3: Analyzing top attackers...")
        top_attackers = get_top_attackers_simple(stats)
        
        # Generate report
        print("\nStep 4: Generating Outlook-compatible report...")
        html = generate_outlook_report(stats, fortigates, top_attackers, whois_cache)
        
        # Save report
        report_path = '/tmp/fortigate_report_outlook.html'
        print(f"\nStep 5: Saving report to {report_path}...")
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html)
        print("Report saved successfully!")
        
        # Send email
        print("\nStep 6: Sending email...")
        try:
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"FortiGate Security Report - {datetime.now().strftime('%Y-%m-%d')}"
            msg['From'] = CONFIG['sender']
            msg['To'] = CONFIG['recipient']
            msg.attach(MIMEText(html, 'html', 'utf-8'))
            
            with smtplib.SMTP(CONFIG['smtp_server'], CONFIG['smtp_port']) as server:
                server.starttls()
                server.login(CONFIG['smtp_user'], CONFIG['smtp_pass'])
                server.sendmail(CONFIG['sender'], CONFIG['recipient'], msg.as_string())
            print("Email sent successfully!")
        except Exception as e:
            print(f"Warning: Could not send email: {e}")
            print("But the report was saved successfully to:", report_path)
        
        print("\n" + "="*60)
        print("PROCESS COMPLETED SUCCESSFULLY!")
        print("="*60)
        
        # Print summary
        if top_attackers:
            print(f"\nTop attacker: {top_attackers[0]['cidr']} with {top_attackers[0]['count']} attacks")
            if 'whois' in top_attackers[0]:
                whois = top_attackers[0]['whois']
                print(f"  Country: {whois['country']}")
                print(f"  Organization: {whois['organization']}")
        
        print(f"\nTotal WHOIS cache entries: {len(whois_cache)}")
        
    except Exception as e:
        print(f"\nERROR: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()

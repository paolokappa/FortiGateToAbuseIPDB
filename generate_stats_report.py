#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enhanced FortiGate Security Statistics Report Generator
Generates comprehensive stats with multiple output formats
"""

import re
import os
import json
import ipaddress
import argparse
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from pathlib import Path
from typing import Dict, List, Tuple, Any

# Configuration
CONFIG = {
    'log_file': '/var/log/fortigate_quarantine.log',
    'fortigate_list': '/opt/FortiGateToAbuseIPDB/fortigate.list',
    'ip_whitelist': '/opt/FortiGateToAbuseIPDB/ip_whitelist.txt',
    'attack_history': '/opt/FortiGateToAbuseIPDB/attack_history.json'
}

class FortiGateStatsAnalyzer:
    """Comprehensive statistics analyzer for FortiGate logs"""
    
    def __init__(self):
        self.stats = defaultdict(lambda: {
            "IPS": defaultdict(int), 
            "DoS": defaultdict(int), 
            "Brute Force": defaultdict(int)
        })
        self.timeline = defaultdict(lambda: defaultdict(int))
        self.ipv4_count = 0
        self.ipv6_count = 0
        self.private_ips_skipped = 0
        self.whitelisted_ips_skipped = 0
        self.dns_servers_skipped = 0
        self.fortigates = {}
        self.user_whitelist = set()
        self.attack_history = []
        
    def load_fortigate_list(self):
        """Load FortiGate configurations"""
        try:
            with open(CONFIG['fortigate_list'], 'r') as f:
                for line in f:
                    if line.strip():
                        parts = line.strip().split()
                        if len(parts) >= 2:
                            self.fortigates[parts[1]] = parts[0]
            print(f"✓ Loaded {len(self.fortigates)} FortiGate devices")
        except Exception as e:
            print(f"✗ Error loading FortiGate list: {e}")
    
    def load_user_whitelist(self):
        """Load user-defined IP whitelist"""
        try:
            if os.path.exists(CONFIG['ip_whitelist']):
                with open(CONFIG['ip_whitelist'], 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            try:
                                network = ipaddress.ip_network(line, strict=False)
                                self.user_whitelist.add(network)
                            except ValueError:
                                pass
                print(f"✓ Loaded {len(self.user_whitelist)} user whitelist networks")
        except Exception as e:
            print(f"✗ Error loading whitelist: {e}")
    
    def load_attack_history(self):
        """Load attack history from JSON file"""
        try:
            if os.path.exists(CONFIG['attack_history']):
                with open(CONFIG['attack_history'], 'r') as f:
                    self.attack_history = json.load(f)
                print(f"✓ Loaded {len(self.attack_history)} historical attack records")
        except Exception as e:
            print(f"✗ Error loading attack history: {e}")
    
    def is_private_ip(self, ip: str) -> bool:
        """Check if IP is private"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return (ip_obj.is_private or ip_obj.is_loopback or 
                   ip_obj.is_link_local or ip_obj.is_multicast or 
                   ip_obj.is_reserved or ip_obj.is_unspecified)
        except:
            return False
    
    def is_in_user_whitelist(self, ip: str) -> bool:
        """Check if IP is in user whitelist"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            for network in self.user_whitelist:
                if ip_obj in network:
                    return True
        except:
            pass
        return False
    
    def parse_log_file(self):
        """Parse the log file for statistics"""
        print(f"\n📊 Parsing log file: {CONFIG['log_file']}")
        
        current_fortigate = "unknown"
        patterns = {
            'fortigate': re.compile(r'Processing FortiGate:\s+([^\s(]+)'),
            'banned_ip': re.compile(r'Found banned IP:\s+([\d.]+|[0-9a-fA-F:]+)\s+\(cause:\s+(\w+)\)'),
            'reported': re.compile(r'Successfully reported\s+([\d.]+|[0-9a-fA-F:]+)\s+to AbuseIPDB'),
            'skipped_private': re.compile(r'IP\s+([\d.]+|[0-9a-fA-F:]+)\s+is (?:private|loopback|link-local|multicast|reserved)'),
            'skipped_whitelist': re.compile(r'IP\s+([\d.]+|[0-9a-fA-F:]+)\s+is in user whitelist'),
            'skipped_dns': re.compile(r'IP\s+([\d.]+|[0-9a-fA-F:]+)\s+is whitelisted \(known DNS server\)'),
            'timestamp': re.compile(r'^(\d{2}-\d{2}-\d{4}\s+\d{2}:\d{2}:\d{2})')
        }
        
        try:
            with open(CONFIG['log_file'], 'r', encoding='utf-8', errors='replace') as f:
                for line in f:
                    line = line.strip()
                    
                    # Extract timestamp
                    timestamp_match = patterns['timestamp'].search(line)
                    if timestamp_match:
                        timestamp = timestamp_match.group(1)
                        date_part = timestamp.split()[0]
                    
                    # Check for FortiGate
                    fg_match = patterns['fortigate'].search(line)
                    if fg_match:
                        current_fortigate = fg_match.group(1)
                        continue
                    
                    # Check for banned IP
                    banned_match = patterns['banned_ip'].search(line)
                    if banned_match:
                        ip = banned_match.group(1)
                        cause = banned_match.group(2).upper()
                        
                        # Count IPv4 vs IPv6
                        if ':' in ip:
                            self.ipv6_count += 1
                        else:
                            self.ipv4_count += 1
                        
                        # Map to categories
                        if cause == 'IPS':
                            self.stats[current_fortigate]["IPS"][ip] += 1
                            if timestamp_match:
                                self.timeline[date_part]["IPS"] += 1
                        elif cause == 'DOS':
                            self.stats[current_fortigate]["DoS"][ip] += 1
                            if timestamp_match:
                                self.timeline[date_part]["DoS"] += 1
                        elif cause == 'ADMINISTRATIVE':
                            self.stats[current_fortigate]["Brute Force"][ip] += 1
                            if timestamp_match:
                                self.timeline[date_part]["Brute Force"] += 1
                    
                    # Check for skipped IPs
                    if patterns['skipped_private'].search(line):
                        self.private_ips_skipped += 1
                    elif patterns['skipped_whitelist'].search(line):
                        self.whitelisted_ips_skipped += 1
                    elif patterns['skipped_dns'].search(line):
                        self.dns_servers_skipped += 1
                        
        except Exception as e:
            print(f"✗ Error parsing log file: {e}")
            return
        
        print(f"✓ Parsed {self.ipv4_count} IPv4 and {self.ipv6_count} IPv6 events")
        print(f"✓ Found {len(self.stats)} FortiGate devices with activity")
    
    def get_top_attackers(self, limit=20):
        """Get top attacking IPs/networks"""
        attackers = defaultdict(int)
        
        for fw, data in self.stats.items():
            for category in ["IPS", "DoS", "Brute Force"]:
                for ip, count in data.get(category, {}).items():
                    attackers[ip] += count
        
        # Group by /24 for IPv4 and individual for IPv6
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
                try:
                    network = str(ipaddress.IPv6Network(f"{ip}/64", strict=False))
                    networks[network]['ips'].append({'ip': ip, 'count': count})
                    networks[network]['count'] += count
                except:
                    networks[f"{ip}/128"]['ips'].append({'ip': ip, 'count': count})
                    networks[f"{ip}/128"]['count'] += count
        
        sorted_networks = sorted(networks.items(), key=lambda x: x[1]['count'], reverse=True)[:limit]
        
        result = []
        for cidr, data in sorted_networks:
            data['ips'].sort(key=lambda x: x['count'], reverse=True)
            result.append({
                'cidr': cidr,
                'ips': data['ips'][:5],  # Top 5 IPs in network
                'total_ips': len(data['ips']),
                'count': data['count']
            })
        
        return result
    
    def get_statistics_summary(self):
        """Generate comprehensive statistics summary"""
        total_attacks = 0
        attack_types = defaultdict(int)
        fortigate_stats = {}
        
        for fw, data in self.stats.items():
            fw_total = 0
            fw_details = {"IPS": 0, "DoS": 0, "Brute Force": 0}
            for attack_type, ips in data.items():
                for ip, count in ips.items():
                    total_attacks += count
                    attack_types[attack_type] += count
                    fw_total += count
                    fw_details[attack_type] += count
            fortigate_stats[fw] = {
                'total': fw_total,
                'details': fw_details
            }
        
        # Calculate unique attackers
        unique_ips = set()
        for fw, data in self.stats.items():
            for attack_type, ips in data.items():
                unique_ips.update(ips.keys())
        
        return {
            'total_attacks': total_attacks,
            'attack_types': dict(attack_types),
            'fortigate_stats': fortigate_stats,
            'unique_attackers': len(unique_ips),
            'ipv4_attacks': self.ipv4_count,
            'ipv6_attacks': self.ipv6_count,
            'private_ips_skipped': self.private_ips_skipped,
            'whitelisted_ips_skipped': self.whitelisted_ips_skipped,
            'dns_servers_skipped': self.dns_servers_skipped,
            'total_skipped': self.private_ips_skipped + self.whitelisted_ips_skipped + self.dns_servers_skipped
        }
    
    def print_terminal_report(self):
        """Print formatted report to terminal"""
        summary = self.get_statistics_summary()
        top_attackers = self.get_top_attackers(10)
        
        print("\n" + "="*80)
        print(" "*25 + "FORTIGATE SECURITY REPORT")
        print("="*80)
        
        # Overview
        print("\n📊 ATTACK OVERVIEW")
        print("-"*40)
        print(f"Total Attacks Blocked:     {summary['total_attacks']:,}")
        print(f"Unique Attacking IPs:      {summary['unique_attackers']:,}")
        print(f"IPv4 Attacks:              {summary['ipv4_attacks']:,}")
        print(f"IPv6 Attacks:              {summary['ipv6_attacks']:,}")
        
        # Attack Types
        print("\n🎯 ATTACK CATEGORIES")
        print("-"*40)
        for attack_type, count in summary['attack_types'].items():
            percentage = (count / summary['total_attacks'] * 100) if summary['total_attacks'] > 0 else 0
            bar = "█" * int(percentage / 2)
            print(f"{attack_type:15} {count:8,} ({percentage:5.1f}%) {bar}")
        
        # Filtered IPs
        print("\n🛡️ FILTERING STATISTICS")
        print("-"*40)
        print(f"Private/LAN IPs Skipped:   {summary['private_ips_skipped']:,}")
        print(f"User Whitelist Skipped:    {summary['whitelisted_ips_skipped']:,}")
        print(f"DNS Servers Skipped:       {summary['dns_servers_skipped']:,}")
        print(f"Total IPs Filtered:        {summary['total_skipped']:,}")
        
        # Top FortiGates
        print("\n🔝 TOP 5 FORTIGATES BY ACTIVITY")
        print("-"*40)
        sorted_fgs = sorted(summary['fortigate_stats'].items(), 
                          key=lambda x: x[1]['total'], reverse=True)[:5]
        for i, (fg, stats) in enumerate(sorted_fgs, 1):
            print(f"{i}. {fg:20} {stats['total']:8,} attacks")
            print(f"   └─ IPS: {stats['details']['IPS']:,} | DoS: {stats['details']['DoS']:,} | Auth: {stats['details']['Brute Force']:,}")
        
        # Top Attackers
        print("\n⚠️  TOP ATTACKING NETWORKS")
        print("-"*40)
        for i, network in enumerate(top_attackers[:10], 1):
            print(f"\n{i}. Network: {network['cidr']}")
            print(f"   Total Attacks: {network['count']:,}")
            print(f"   Unique IPs: {network['total_ips']}")
            if network['ips']:
                print("   Top IPs:")
                for ip_data in network['ips'][:3]:
                    print(f"     - {ip_data['ip']:30} ({ip_data['count']:,} attacks)")
        
        # Timeline (last 7 days)
        if self.timeline:
            print("\n📅 ATTACK TIMELINE (Last 7 Days)")
            print("-"*40)
            sorted_dates = sorted(self.timeline.keys())[-7:]
            for date in sorted_dates:
                day_total = sum(self.timeline[date].values())
                print(f"{date}: {day_total:6,} attacks", end="")
                if day_total > 0:
                    print(f" (IPS:{self.timeline[date].get('IPS', 0):,} "
                          f"DoS:{self.timeline[date].get('DoS', 0):,} "
                          f"Auth:{self.timeline[date].get('Brute Force', 0):,})")
                else:
                    print()
        
        print("\n" + "="*80)
        print(f"Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*80 + "\n")
    
    def export_json(self, filename=None):
        """Export statistics to JSON file"""
        if not filename:
            filename = f"/tmp/fortigate_stats_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        summary = self.get_statistics_summary()
        top_attackers = self.get_top_attackers(50)
        
        export_data = {
            'generated': datetime.now().isoformat(),
            'summary': summary,
            'top_attackers': top_attackers,
            'timeline': dict(self.timeline),
            'fortigate_devices': self.fortigates
        }
        
        with open(filename, 'w') as f:
            json.dump(export_data, f, indent=2, default=str)
        
        print(f"✓ JSON report exported to: {filename}")
        return filename
    
    def export_csv(self, filename=None):
        """Export top attackers to CSV file"""
        import csv
        
        if not filename:
            filename = f"/tmp/fortigate_attackers_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        
        top_attackers = self.get_top_attackers(100)
        
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Rank', 'Network_CIDR', 'Total_Attacks', 'Unique_IPs', 'Top_IP', 'Top_IP_Attacks'])
            
            for i, network in enumerate(top_attackers, 1):
                top_ip = network['ips'][0]['ip'] if network['ips'] else 'N/A'
                top_ip_count = network['ips'][0]['count'] if network['ips'] else 0
                writer.writerow([
                    i,
                    network['cidr'],
                    network['count'],
                    network['total_ips'],
                    top_ip,
                    top_ip_count
                ])
        
        print(f"✓ CSV report exported to: {filename}")
        return filename

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Generate FortiGate Security Statistics Report')
    parser.add_argument('--json', action='store_true', help='Export report as JSON')
    parser.add_argument('--csv', action='store_true', help='Export attackers list as CSV')
    parser.add_argument('--output', type=str, help='Output file path')
    parser.add_argument('--quiet', action='store_true', help='Suppress terminal output')
    
    args = parser.parse_args()
    
    print("\n🔐 FortiGate Security Statistics Analyzer")
    print("="*50)
    
    analyzer = FortiGateStatsAnalyzer()
    
    # Load data
    print("\n📁 Loading configuration files...")
    analyzer.load_fortigate_list()
    analyzer.load_user_whitelist()
    analyzer.load_attack_history()
    
    # Parse logs
    analyzer.parse_log_file()
    
    # Generate reports
    if not args.quiet:
        analyzer.print_terminal_report()
    
    if args.json:
        json_file = analyzer.export_json(args.output if args.output and args.output.endswith('.json') else None)
    
    if args.csv:
        csv_file = analyzer.export_csv(args.output if args.output and args.output.endswith('.csv') else None)
    
    print("\n✅ Report generation complete!")

if __name__ == "__main__":
    main()
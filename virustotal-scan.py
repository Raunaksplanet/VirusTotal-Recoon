#!/usr/bin/env python3
"""
VirusTotal Recon Tool for Bug Bounty (Fixed Version)
"""

import requests
import json
import time
import sys
import argparse
import csv
from datetime import datetime

class VirusTotalRecon:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/vtapi/v2"
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'VT-Recon-Tool/1.0'})
        self.last_request_time = 0
        self.min_interval = 15
        
    def _rate_limit(self):
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        if time_since_last < self.min_interval:
            sleep_time = self.min_interval - time_since_last
            print(f"[*] Rate limiting: Sleeping for {sleep_time:.1f} seconds...")
            time.sleep(sleep_time)
        self.last_request_time = time.time()
    
    def _make_request(self, endpoint, params=None):
        self._rate_limit()
        url = f"{self.base_url}/{endpoint}"
        if params:
            params['apikey'] = self.api_key
        
        try:
            response = self.session.get(url, params=params)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"[-] Request failed: {e}")
            return None
    
    def get_domain_report(self, domain):
        print(f"[*] Getting domain report for: {domain}")
        data = self._make_request("domain/report", {'domain': domain})
        return data
    
    def extract_intel(self, domain_data):
        """Extract all intelligence from domain report"""
        intel = {
            'domain': domain_data.get('domain', ''),
            'subdomains': [],
            'ips': [],
            'files': [],
            'urls': [],
            'whois': domain_data.get('whois', '')
        }
        
        # Extract subdomains from BOTH fields
        subdomains = set()
        
        # From 'subdomains' field
        if 'subdomains' in domain_data:
            subdomains.update(domain_data['subdomains'])
        
        # From 'domain_siblings' field
        if 'domain_siblings' in domain_data:
            subdomains.update(domain_data['domain_siblings'])
        
        intel['subdomains'] = list(subdomains)
        
        # Extract IPs
        for resolution in domain_data.get('resolutions', []):
            ip_info = {
                'ip': resolution.get('ip_address'),
                'last_resolved': resolution.get('last_resolved')
            }
            if ip_info['ip']:
                intel['ips'].append(ip_info)
        
        # Extract files from multiple sources
        file_sources = [
            'undetected_referrer_samples',
            'undetected_downloaded_samples',
            'detected_referrer_samples',
            'detected_downloaded_samples'
        ]
        
        for source in file_sources:
            for file_sample in domain_data.get(source, []):
                file_info = {
                    'sha256': file_sample.get('sha256'),
                    'date': file_sample.get('date'),
                    'positives': file_sample.get('positives', 0),
                    'total': file_sample.get('total', 0),
                    'source': source
                }
                if file_info['sha256']:
                    intel['files'].append(file_info)
        
        # Extract URLs
        for url_info in domain_data.get('detected_urls', []):
            if isinstance(url_info, list) and len(url_info) > 0:
                intel['urls'].append(url_info[0])
        
        for url_info in domain_data.get('undetected_urls', []):
            if isinstance(url_info, list) and len(url_info) > 0:
                intel['urls'].append(url_info[0])
        
        return intel
    
    def analyze_findings(self, intel):
        """Analyze findings for bug bounty relevance"""
        findings = {
            'test_subdomains': [],
            'admin_subdomains': [],
            'api_endpoints': [],
            'cloudflare_ips': 0,
            'malicious_files': 0
        }
        
        # Analyze subdomains
        test_keywords = ['test', 'dev', 'staging', 'uat', 'beta', 'alpha', 'qa']
        admin_keywords = ['admin', 'backend', 'api', 'dashboard', 'control', 'manager']
        
        for subdomain in intel['subdomains']:
            subdomain_lower = subdomain.lower()
            
            # Check for test environments
            for keyword in test_keywords:
                if keyword in subdomain_lower:
                    findings['test_subdomains'].append(subdomain)
                    break
            
            # Check for admin/API endpoints
            for keyword in admin_keywords:
                if keyword in subdomain_lower:
                    findings['admin_subdomains'].append(subdomain)
                    break
            
            # Check for API endpoints
            if 'api' in subdomain_lower:
                findings['api_endpoints'].append(subdomain)
        
        # Analyze IPs for Cloudflare
        for ip_info in intel['ips']:
            ip = ip_info.get('ip', '')
            if ip.startswith('104.') or ip.startswith('172.67.'):
                findings['cloudflare_ips'] += 1
        
        # Check for malicious files
        for file_info in intel['files']:
            if file_info.get('positives', 0) > 0:
                findings['malicious_files'] += 1
        
        return findings
    
    def save_outputs(self, intel, findings, output_prefix):
        """Save all outputs to files"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = f"{output_prefix}_{timestamp}"
        import os
        os.makedirs(output_dir, exist_ok=True)
        
        # Save intelligence data
        with open(f"{output_dir}/intel.json", 'w') as f:
            json.dump(intel, f, indent=2, default=str)
        
        # Save subdomains to file
        with open(f"{output_dir}/subdomains.txt", 'w') as f:
            for subdomain in intel['subdomains']:
                f.write(f"{subdomain}\n")
        
        # Save IPs to file
        with open(f"{output_dir}/ips.txt", 'w') as f:
            for ip_info in intel['ips']:
                f.write(f"{ip_info['ip']}\n")
        
        # Save file hashes
        with open(f"{output_dir}/hashes.txt", 'w') as f:
            for file_info in intel['files']:
                f.write(f"{file_info['sha256']}\n")
        
        # Save URLs
        with open(f"{output_dir}/urls.txt", 'w') as f:
            for url in intel['urls']:
                f.write(f"{url}\n")
        
        # Generate summary report
        with open(f"{output_dir}/summary.md", 'w') as f:
            f.write(f"# VirusTotal Recon Report\n\n")
            f.write(f"**Target:** {intel['domain']}\n")
            f.write(f"**Date:** {datetime.now()}\n\n")
            
            f.write("## Summary\n\n")
            f.write(f"- Subdomains found: {len(intel['subdomains'])}\n")
            f.write(f"- IP addresses: {len(intel['ips'])}\n")
            f.write(f"- File samples: {len(intel['files'])}\n")
            f.write(f"- URLs: {len(intel['urls'])}\n\n")
            
            if findings['test_subdomains']:
                f.write("## Test/Dev Environments\n\n")
                for subdomain in findings['test_subdomains']:
                    f.write(f"- `{subdomain}`\n")
                f.write("\n")
            
            if findings['admin_subdomains']:
                f.write("## Admin/API Endpoints\n\n")
                for subdomain in findings['admin_subdomains']:
                    f.write(f"- `{subdomain}`\n")
                f.write("\n")
            
            if findings['cloudflare_ips'] > 0:
                f.write(f"## Infrastructure\n\n")
                f.write(f"- Behind Cloudflare CDN: {findings['cloudflare_ips']} IPs\n\n")
            
            if findings['malicious_files'] > 0:
                f.write(f"## Security Findings\n\n")
                f.write(f"- Potentially malicious files: {findings['malicious_files']}\n\n")
            
            f.write("## Files Generated\n\n")
            f.write("1. `intel.json` - Complete intelligence data\n")
            f.write("2. `subdomains.txt` - List of subdomains\n")
            f.write("3. `ips.txt` - List of IP addresses\n")
            f.write("4. `hashes.txt` - File hashes\n")
            f.write("5. `urls.txt` - URLs\n")
            f.write("6. `summary.md` - This report\n")
        
        print(f"[+] All outputs saved to: {output_dir}/")
        return output_dir

def main():
    parser = argparse.ArgumentParser(description='VirusTotal Recon Tool')
    parser.add_argument('-k', '--api-key', required=True, help='VirusTotal API key')
    parser.add_argument('-d', '--domain', required=True, help='Target domain')
    parser.add_argument('-o', '--output', default='vt_recon', help='Output prefix')
    parser.add_argument('-f', '--full', action='store_true', help='Full reconnaissance')
    
    args = parser.parse_args()
    
    print(f"[*] Starting VirusTotal reconnaissance for: {args.domain}")
    print(f"[*] API Key: {args.api_key[:8]}...\n")
    
    # Initialize tool
    vt = VirusTotalRecon(args.api_key)
    
    # Get domain report
    domain_data = vt.get_domain_report(args.domain)
    if not domain_data or domain_data.get('response_code') != 1:
        print("[-] Failed to get domain data")
        sys.exit(1)
    
    # Extract intelligence
    intel = vt.extract_intel(domain_data)
    
    # Analyze findings
    findings = vt.analyze_findings(intel)
    
    # Print summary
    print(f"\n[+] Intelligence Summary:")
    print(f"    Subdomains: {len(intel['subdomains'])}")
    print(f"    IP addresses: {len(intel['ips'])}")
    print(f"    File samples: {len(intel['files'])}")
    print(f"    URLs: {len(intel['urls'])}")
    
    if intel['subdomains']:
        print(f"\n[*] Sample subdomains (first 10):")
        for i, sub in enumerate(intel['subdomains'][:10]):
            print(f"    {i+1}. {sub}")
    
    # Show interesting findings
    if findings['test_subdomains']:
        print(f"\n[!] Test/Dev subdomains found ({len(findings['test_subdomains'])}):")
        for sub in findings['test_subdomains'][:5]:
            print(f"    • {sub}")
    
    if findings['admin_subdomains']:
        print(f"\n[!] Admin/API subdomains found ({len(findings['admin_subdomains'])}):")
        for sub in findings['admin_subdomains'][:5]:
            print(f"    • {sub}")
    
    if findings['cloudflare_ips'] > 0:
        print(f"\n[!] Cloudflare CDN detected: {findings['cloudflare_ips']} IPs")
    
    if findings['malicious_files'] > 0:
        print(f"\n[!] Potentially malicious files: {findings['malicious_files']}")
    
    # Save outputs
    output_dir = vt.save_outputs(intel, findings, args.output)
    
    # Full reconnaissance if requested
    if args.full and (intel['ips'] or intel['files']):
        print(f"\n[*] Starting full reconnaissance...")
        
        # Investigate IPs (first 2)
        if intel['ips']:
            print(f"[*] Investigating IP addresses...")
            os.makedirs(f"{output_dir}/ip_reports", exist_ok=True)
            for ip_info in intel['ips'][:2]:
                ip_data = vt.get_ip_report(ip_info['ip'])
                if ip_data:
                    with open(f"{output_dir}/ip_reports/{ip_info['ip'].replace('.', '_')}.json", 'w') as f:
                        json.dump(ip_data, f, indent=2)
        
        # Investigate files (first 2)
        if intel['files']:
            print(f"[*] Investigating file samples...")
            os.makedirs(f"{output_dir}/file_reports", exist_ok=True)
            for file_info in intel['files'][:2]:
                file_data = vt.get_file_report(file_info['sha256'])
                if file_data:
                    with open(f"{output_dir}/file_reports/{file_info['sha256'][:16]}.json", 'w') as f:
                        json.dump(file_data, f, indent=2)
    
    print(f"\n[+] Reconnaissance complete!")
    print(f"[+] Check {output_dir}/ for all results")

if __name__ == "__main__":
    main()

# VirusTotal Recon Tool for Bug Bounty

A powerful reconnaissance tool that automates intelligence gathering from VirusTotal API for bug bounty hunters and security researchers.

## Features

- **Domain Intelligence**: Extract subdomains, IP addresses, file samples, and URLs
- **Smart Analysis**: Identify test/dev environments, admin panels, and API endpoints
- **CDN Detection**: Automatically detect Cloudflare-protected infrastructure
- **Threat Hunting**: Find potentially malicious files associated with targets
- **Organized Output**: Generate structured reports in multiple formats
- **Rate Limit Compliant**: Respects VirusTotal API limits (4 requests/minute)

## Installation

1. **Clone/Download** the script:
   ```bash
   wget https://raw.githubusercontent.com/yourusername/vt-recon/main/vt_recon.py
   ```

2. **Install dependencies** (only `requests` required):
   ```bash
   pip install requests
   ```

3. **Make executable** (optional):
   ```bash
   chmod +x vt_recon.py
   ```

## Usage

### Basic Domain Reconnaissance
```bash
python vt_recon.py -k YOUR_API_KEY -d target.com
```

### Full Reconnaissance (IPs + Files)
```bash
python vt_recon.py -k YOUR_API_KEY -d target.com -f -o mytarget
```

### Arguments
- `-k, --api-key`: VirusTotal API key (required)
- `-d, --domain`: Target domain (required)
- `-o, --output`: Output prefix (default: `vt_recon`)
- `-f, --full`: Enable full reconnaissance (investigates IPs and files)

## Example Output

```
[*] Starting VirusTotal reconnaissance for: target.com
[*] API Key: abcdef12...

[+] Intelligence Summary:
    Subdomains: 46
    IP addresses: 9
    File samples: 21
    URLs: 13

[!] Test/Dev subdomains found (8):
    • test-api.target.com
    • staging.target.com
    • dev.target.com

[!] Admin/API subdomains found (5):
    • admin.target.com
    • api.target.com
    • dashboard.target.com

[!] Cloudflare CDN detected: 3 IPs

[+] All outputs saved to: vt_recon_20250101_120000/
```

## Output Structure

```
vt_recon_20250101_120000/
├── intel.json           # Complete intelligence data
├── subdomains.txt       # List of discovered subdomains
├── ips.txt              # IP addresses
├── hashes.txt           # File SHA256 hashes
├── urls.txt             # Extracted URLs
├── summary.md           # Markdown summary report
├── ip_reports/          # Detailed IP reports (full mode)
└── file_reports/        # File analysis reports (full mode)
```

## API Key Requirements

1. **Get a VirusTotal API key** from: [https://www.virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us)
2. **Free tier limitations**:
   - 4 requests per minute
   - 500 requests per day
   - Rate limiting automatically handled by the tool

## Features for Bug Bounty

- **Test/Dev Discovery**: Finds `test-`, `dev-`, `staging-`, `uat-` subdomains
- **Attack Surface Mapping**: Identifies admin panels, APIs, dashboards
- **Infrastructure Analysis**: Detects CDN usage and hosting patterns
- **Historical Data**: Extracts historical files and URLs
- **Threat Correlation**: Links IPs, domains, and malicious files

## Tips for Bug Bounty

1. **Start with root domains** to discover all subdomains
2. **Use `-f` flag** for deeper investigation of interesting targets
3. **Check for exposed files** in the `hashes.txt` output
4. **Look for forgotten subdomains** that might have weaker security
5. **Combine with other tools** like amass, subfinder, or httpx

## Troubleshooting

### Common Issues
- **No subdomains found**: Some domains have limited VirusTotal data
- **API rate limits**: Tool automatically handles delays (15s between requests)
- **Invalid API key**: Verify your key at VirusTotal dashboard

### Debug Mode
Add debug prints by modifying the script:
```python
# Add to _make_request method
print(f"[DEBUG] Request: {url}")
print(f"[DEBUG] Params: {params}")
```

## License

MIT License - Use responsibly and respect API rate limits.

## Disclaimer

This tool is for authorized security testing and bug bounty hunting only. Always obtain proper authorization before testing any systems. The author is not responsible for misuse of this tool.

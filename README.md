# Techsploit

Advanced web application scanner for technology detection, security analysis, and vulnerability assessment.

## Features

- Technology stack detection via Wappalyzer
- CVE vulnerability checking (NVD database)
- SSL/TLS configuration analysis
- HTTP security header analysis
- WAF detection
- Directory enumeration
- Multiple export formats (JSON, CSV, HTML, Markdown)
- Multi-threading support
- Custom wordlist support

## Installation

```bash
# Clone repository
git clone https://github.com/m00s3c/techsploit.git
cd techsploit

# Make installer executable
chmod +x install.sh

# Run installer
sudo ./install.sh
```

## Usage

Basic scan:
```bash
techsploit https://example.com
```

Full scan:
```bash
techsploit https://example.com -c -s -e --check-headers --detect-waf -o report -f md
```

Multiple targets:
```bash
techsploit -t targets.txt -c -s --threads 10
```

### Options

```
-h, --help            Show help message
-t, --targets FILE    File containing target URLs
--threads N           Number of concurrent threads (default: 5)
-c, --check-cve       Check for CVE vulnerabilities
-s, --check-ssl       Analyze SSL/TLS configuration
-e, --enumerate       Perform directory enumeration
-w, --wordlist FILE   Custom wordlist for enumeration
-o, --output PREFIX   Output file prefix
-f, --format FORMAT   Report format (json/csv/html/md)
--check-headers       Analyze HTTP security headers
--detect-waf          Detect Web Application Firewall
--help-full           Show extended help
```

## Project Structure
```
techsploit/
├── install.sh         # Installation script
├── README.md          # Project documentation
└── techsploit/        # Source code directory
    └── main.py        # Main script
```

## Legal Disclaimer

Use responsibly and only against systems you have permission to test.

## Contributing

1. Fork the repository
2. Create feature branch
3. Submit pull request

## License

MIT License

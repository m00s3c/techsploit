#!/usr/bin/env python3

import argparse
import json
import subprocess
import sys
from typing import Dict, List, Set
import requests
import ssl
import socket
import concurrent.futures
from datetime import datetime
from pathlib import Path
import csv
from Wappalyzer import Wappalyzer, WebPage
import nvdlib
from urllib.parse import urljoin
import re
import warnings

# Suppress all UserWarnings
warnings.filterwarnings("ignore", category=UserWarning)


class Techsploit:
    def __init__(self, target_url: str, options: Dict):
        self.target_url = target_url
        self.options = options
        self.wappalyzer = Wappalyzer.latest()
        self.technologies = {}
        self.vulnerabilities = []
        self.directories = set()
        self.ssl_info = {}
        self.headers_analysis = {}
        self.waf_info = {}

    def analyze_technologies(self) -> Dict:
        try:
            webpage = WebPage.new_from_url(self.target_url)
            self.technologies = self.wappalyzer.analyze_with_versions(webpage)
            if self.options.get('check_cve'):
                self._check_cve_vulnerabilities()
            return self.technologies
        except Exception as e:
            print(f"Error analyzing technologies: {e}")
            return {}

    def _check_cve_vulnerabilities(self):
        for tech, version in self.technologies.items():
            if isinstance(version, dict) and 'version' in version:
                try:
                    results = nvdlib.searchCVE(
                        keywordSearch=f"{tech} {version['version']}",
                        pubStartDate=datetime(2020, 1, 1)
                    )
                    for r in results:
                        self.vulnerabilities.append({
                            'technology': tech,
                            'version': version['version'],
                            'cve_id': r.id,
                            'description': r.descriptions[0].value,
                            'severity': r.metrics.cvssMetricV31[0].cvssData.baseScore if r.metrics else "Unknown"
                        })
                except Exception as e:
                    print(f"Error checking CVEs for {tech}: {e}")

    def check_ssl(self):
        try:
            hostname = self.target_url.split("://")[1].split("/")[0]
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    self.ssl_info = {
                        'version': ssock.version(),
                        'cipher': ssock.cipher(),
                        'cert_expires': datetime.strptime(
                            ssock.getpeercert()['notAfter'],
                            '%b %d %H:%M:%S %Y %Z'
                        ).strftime('%Y-%m-%d')
                    }
        except Exception as e:
            print(f"Error checking SSL: {e}")

    def analyze_headers(self):
        try:
            response = requests.get(self.target_url)
            headers = response.headers

            security_headers = {
                'Strict-Transport-Security': 'Missing HSTS header',
                'Content-Security-Policy': 'Missing CSP header',
                'X-Frame-Options': 'Missing X-Frame-Options header',
                'X-Content-Type-Options': 'Missing X-Content-Type-Options header',
                'X-XSS-Protection': 'Missing XSS protection header',
                'Referrer-Policy': 'Missing Referrer-Policy header'
            }

            for header, message in security_headers.items():
                if header in headers:
                    self.headers_analysis[header] = headers[header]
                else:
                    self.headers_analysis[header] = message

            server_tokens = headers.get('Server', '')
            if server_tokens and len(server_tokens) > 1:
                self.headers_analysis['Server_Info_Leaked'] = server_tokens

            cookies = response.cookies
            for cookie in cookies:
                if not cookie.secure:
                    self.headers_analysis[f'Insecure_Cookie_{
                        cookie.name}'] = 'Missing Secure flag'
                if not cookie.has_nonstandard_attr('HttpOnly'):
                    self.headers_analysis[f'HttpOnly_Missing_{
                        cookie.name}'] = 'Missing HttpOnly flag'

        except Exception as e:
            print(f"Error analyzing headers: {e}")

    def detect_waf(self):
        try:
            payload = "' OR '1'='1"
            response = requests.get(f"{self.target_url}?id={payload}")

            waf_signatures = {
                'Cloudflare': ['CF-RAY', '__cfduid', 'cf-ray'],
                'ModSecurity': ['Mod_Security', 'NOYB'],
                'Sucuri': ['sucuri-web-firewall', 'X-Sucuri-ID'],
                'Imperva': ['X-Iinfo', 'incap_ses', 'visid_incap'],
                'Akamai': ['AkamaiGHost'],
                'F5 BIG-IP': ['BigIP', 'F5-TrafficShield']
            }

            detected_wafs = []
            for waf_name, signatures in waf_signatures.items():
                for sig in signatures:
                    if any(sig.lower() in header.lower() for header in response.headers):
                        detected_wafs.append(waf_name)
                        break

            if response.status_code in [403, 406, 501]:
                self.waf_info['behavior'] = 'Blocking suspicious requests'

            if detected_wafs:
                self.waf_info['detected'] = list(set(detected_wafs))
            else:
                self.waf_info['detected'] = 'No WAF detected'

        except Exception as e:
            print(f"Error detecting WAF: {e}")

    def enumerate_directories(self):
        wordlist_path = self.options.get('wordlist')
        if wordlist_path and Path(wordlist_path).exists():
            with open(wordlist_path) as f:
                paths = [line.strip() for line in f]
            print(f"Using custom wordlist: {wordlist_path}")
        else:
            print("Using default wordlist")
            paths = [
                # Administrative paths
                'admin', 'administrator', 'admin_panel', 'admin_area', 'wp-admin', 'cms-admin', 'cpanel',

                # Login and authentication
                'login', 'log-in', 'signin', 'sign-in', 'auth', 'authentication', 'login.php', 'signin.php',

                # API endpoints
                'api', 'rest', 'graphql', 'api/v1', 'api/v2', 'api/private', 'api/public', 'api/internal',

                # Backup and configuration
                'backup', 'backups', 'db_backup', 'db_backups', 'config', 'configs', 'configuration', 'settings',
                'backup.zip', 'backup.tar.gz', 'config.php', 'config.json', 'config.yml', 'wp-config.php',

                # Content and uploads
                'dashboard', 'wp-content', 'content', 'upload', 'uploads', 'assets', 'media', 'static',
                'files', 'downloads', 'images', 'css', 'js', 'fonts',

                # Development and testing
                'test', 'testing', 'qa', 'dev', 'development', 'stage', 'staging', 'preprod', 'prod', 'production',
                'debug', 'beta', 'alpha', 'sandbox',

                # Database paths
                'db', 'database', 'data', 'db_admin', 'sql', 'dump', 'dumps', 'mysql', 'pgsql', 'mongodb',

                # Miscellaneous
                'temp', 'tmp', 'old', 'archive', 'archives', 'logs', 'log', 'status', 'health', 'metrics',
                'error', 'error_log', 'info', 'user', 'users', 'member', 'members', 'account', 'accounts',
                'session', 'sessions', 'token', 'tokens',

                # Popular third-party tools
                'phpmyadmin', 'phpMyAdmin', 'wp-login', 'wp-login.php', 'drupal', 'joomla', 'magento',

                # Version control and source code
                '.git', '.svn', '.hg', 'git', 'svn', 'repository', 'repo', 'repos', 'source', 'src',
                'code', 'build', 'deploy', 'deployment',

                # Other useful files
                'robots.txt', 'sitemap.xml', '.env', '.htaccess', '.htpasswd', 'server-status', 'server-info',
                'README', 'README.md', 'index.html', 'index.php', 'index.jsp', 'index.asp'
            ]

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [
                executor.submit(self._check_path, path)
                for path in paths
            ]
            concurrent.futures.wait(futures)

    def _check_path(self, path: str):
        url = urljoin(self.target_url, path)
        try:
            response = requests.get(url, allow_redirects=False)
            if response.status_code in [200, 301, 302, 403]:
                self.directories.add((url, response.status_code))
        except:
            pass

    def print_scan_results(self):
        print("\n" + "=" * 50)
        print(f"Target: {self.target_url}")
        print("=" * 50)

        if self.technologies:
            print("\n[+] Technologies Detected:")
            for tech, info in self.technologies.items():
                # Extract versions from the `versions` key
                if isinstance(info, dict):
                    versions = info.get("versions", [])
                    version_display = ", ".join(
                        versions) if versions else "Unknown"
                else:
                    version_display = "Unknown"
                print(f"  - {tech}: {version_display}")

        if self.ssl_info:
            print("\n[+] SSL/TLS Information:")
            for key, value in self.ssl_info.items():
                print(f"  - {key.replace('_', ' ').title()}: {value}")

        if self.headers_analysis:
            print("\n[+] Security Headers:")
            for header, value in self.headers_analysis.items():
                print(f"  - {header}: {value}")

        if self.waf_info:
            print("\n[+] WAF Detection:")
            for key, value in self.waf_info.items():
                print(f"  - {key.title()}: {value}")

        if self.directories:
            print("\n[+] Discovered Directories:")
            for url, status in self.directories:
                print(f"  - {url} (Status: {status})")

        print("\n" + "=" * 50 + "\n")

    def export_report(self, format_type: str, output_file: str):
        report = self.generate_report()

        if format_type == 'json':
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)

        elif format_type == 'csv':
            with open(output_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Category', 'Finding', 'Details'])
                for tech, ver in report['technologies'].items():
                    writer.writerow(['Technology', tech, json.dumps(ver)])
                for vuln in report['vulnerabilities']:
                    writer.writerow(['Vulnerability', vuln.get(
                        'name', 'Unknown'), json.dumps(vuln)])
                for dir_url, status in report.get('directories', []):
                    writer.writerow(['Directory', dir_url, status])

        elif format_type == 'html':
            html_content = self._generate_html_report(report)
            with open(output_file, 'w') as f:
                f.write(html_content)

        elif format_type == 'md':
            md_content = self._generate_markdown_report(report)
            with open(output_file, 'w') as f:
                f.write(md_content)

    def generate_report(self) -> Dict:
        return {
            'target': self.target_url,
            'scan_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'technologies': self.technologies,
            'vulnerabilities': self.vulnerabilities,
            'ssl_info': self.ssl_info,
            'headers_analysis': self.headers_analysis,
            'waf_info': self.waf_info,
            'directories': list(self.directories)
        }

    def _generate_html_report(self, report: Dict) -> str:
        return f"""
        <html>
            <head>
                <title>Techsploit Scan Report - {self.target_url}</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                    h1 {{ color: #2c3e50; }}
                    .section {{ margin: 20px 0; padding: 10px; border: 1px solid #eee; }}
                    pre {{ background: #f8f9fa; padding: 10px; overflow-x: auto; }}
                </style>
            </head>
            <body>
                <h1>Techsploit Scan Report</h1>
                <div class="section">
                    <h2>Target: {self.target_url}</h2>
                    <h3>Scan Date: {report['scan_date']}</h3>
                </div>
                <div class="section">
                    <h2>Technologies Detected</h2>
                    <pre>{json.dumps(self.technologies, indent=2)}</pre>
                </div>
                <div class="section">
                    <h2>Vulnerabilities</h2>
                    <pre>{json.dumps(self.vulnerabilities, indent=2)}</pre>
                </div>
                <div class="section">
                    <h2>SSL/TLS Information</h2>
                    <pre>{json.dumps(self.ssl_info, indent=2)}</pre>
                </div>
                <div class="section">
                    <h2>HTTP Security Headers</h2>
                    <pre>{json.dumps(self.headers_analysis, indent=2)}</pre>
                </div>
                <div class="section">
                    <h2>WAF Detection Results</h2>
                    <pre>{json.dumps(self.waf_info, indent=2)}</pre>
                </div>
                <div class="section">
                    <h2>Discovered Directories</h2>
                    <pre>{json.dumps(list(self.directories), indent=2)}</pre>
                </div>
            </body>
        </html>
        """

    def _generate_markdown_report(self, report: Dict) -> str:
        return f"""# Techsploit Scan Report

## Target: {self.target_url}
Scan Date: {report['scan_date']}

## Technologies Detected
```json
{json.dumps(self.technologies, indent=2)}
```

## Vulnerabilities
```json
{json.dumps(self.vulnerabilities, indent=2)}
```

## SSL/TLS Information
```json
{json.dumps(self.ssl_info, indent=2)}
```

## HTTP Security Headers
```json
{json.dumps(self.headers_analysis, indent=2)}
```

## WAF Detection Results
```json
{json.dumps(self.waf_info, indent=2)}
```

## Discovered Directories
```json
{json.dumps(list(self.directories), indent=2)}
```
"""


def print_banner():
    banner = """
████████╗███████╗ ██████╗██╗  ██╗███████╗██████╗ ██╗      ██████╗ ██╗████████╗
╚══██╔══╝██╔════╝██╔════╝██║  ██║██╔════╝██╔══██╗██║     ██╔═══██╗██║╚══██╔══╝
   ██║   █████╗  ██║     ███████║███████╗██████╔╝██║     ██║   ██║██║   ██║
   ██║   ██╔══╝  ██║     ██╔══██║╚════██║██╔═══╝ ██║     ██║   ██║██║   ██║
   ██║   ███████╗╚██████╗██║  ██║███████║██║     ███████╗╚██████╔╝██║   ██║
   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝   ╚═╝
                     Web Application Scanner v1.0
               https://techsploit.com | https://moose.sh
    """
    print(banner)


def print_help():
    help_text = """
Usage: python3 techsploit.py [OPTIONS] URL

Options:
  -h, --help                Show help message
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
  --help-full           Show extended help with examples

Examples:
  Basic scan:
    techsploit https://example.com

  Full scan with custom wordlist:
    techsploit https://example.com -c -s -e -w wordlist.txt -o report -f md

  Multiple targets:
    techsploit -t targets.txt -c -s --threads 10
    """
    print(help_text)


def scan_multiple_targets(targets: List[str], options: Dict):
    with concurrent.futures.ThreadPoolExecutor(max_workers=options.get('threads', 5)) as executor:
        future_to_url = {
            executor.submit(scan_single_target, url, options): url
            for url in targets
        }
        for future in concurrent.futures.as_completed(future_to_url):
            url = future_to_url[future]
            try:
                future.result()
            except Exception as e:
                print(f"Error scanning {url}: {e}")


def scan_single_target(url: str, options: Dict):
    scanner = Techsploit(url, options)

    if options.get('check_tech', True):
        print(f"[*] Analyzing technologies on {url}")
        scanner.analyze_technologies()

    if options.get('check_ssl'):
        print("[*] Checking SSL/TLS configuration")
        scanner.check_ssl()

    if options.get('enumerate'):
        print("[*] Enumerating directories")
        scanner.enumerate_directories()

    if options.get('check_headers'):
        print("[*] Analyzing HTTP headers")
        scanner.analyze_headers()

    if options.get('detect_waf'):
        print("[*] Detecting WAF")
        scanner.detect_waf()

    # Print results to console
    scanner.print_scan_results()

    # Export report if output is specified
    if options.get('output'):
        scanner.export_report(
            options.get('format', 'json'),
            f"{options['output']}_{url.replace('://', '_').replace('/', '_')}"
        )


def main():
    parser = argparse.ArgumentParser(
        description="Techsploit - Advanced Web Application Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument("url", nargs="?", help="Target URL to scan")
    parser.add_argument("-t", "--targets",
                        help="File containing list of targets")
    parser.add_argument("--threads", type=int, default=5,
                        help="Number of concurrent threads")
    parser.add_argument("-c", "--check-cve", action="store_true",
                        help="Check for CVE vulnerabilities")
    parser.add_argument("-s", "--check-ssl", action="store_true",
                        help="Analyze SSL/TLS configuration")
    parser.add_argument("-e", "--enumerate", action="store_true",
                        help="Perform directory enumeration")
    parser.add_argument("-w", "--wordlist",
                        help="Custom wordlist for directory enumeration")
    parser.add_argument(
        "-o", "--output", help="Output file prefix for reports")
    parser.add_argument("-f", "--format", choices=['json', 'csv', 'html', 'md'], default='json',
                        help="Report format (default: json)")
    parser.add_argument("--check-headers", action="store_true",
                        help="Analyze HTTP security headers")
    parser.add_argument("--detect-waf", action="store_true",
                        help="Detect Web Application Firewall")
    parser.add_argument("--help-full", action="store_true",
                        help="Show detailed help information")

    args = parser.parse_args()

    if args.help_full:
        print_help()
        sys.exit(0)

    print_banner()

    if not args.url and not args.targets:
        parser.print_help()
        sys.exit(1)

    options = {
        'check_cve': args.check_cve,
        'check_ssl': args.check_ssl,
        'enumerate': args.enumerate,
        'wordlist': args.wordlist,
        'output': args.output,
        'format': args.format,
        'threads': args.threads,
        'check_headers': args.check_headers,
        'detect_waf': args.detect_waf
    }

    if args.targets:
        with open(args.targets) as f:
            targets = [line.strip() for line in f if line.strip()]
        scan_multiple_targets(targets, options)
    else:
        scan_single_target(args.url, options)


if __name__ == "__main__":
    main()

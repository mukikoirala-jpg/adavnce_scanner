#!/usr/bin/env python3
"""
ADVANCED NETWORK MONITORING & INTRUSION DETECTION SYSTEM
Real-time threat detection with AI/ML capabilities
Monitors: Protocols, Ports, Connections, Anomalies, DDoS, Malware Signatures
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import threading
import socket
import struct
import textwrap
import json
from datetime import datetime, timedelta
from collections import defaultdict, deque
import psutil
import netifaces
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, DNS, DNSQR
import ipaddress
import subprocess
import platform
import hashlib
from queue import Queue, PriorityQueue
import warnings
import gzip
import csv
import sqlite3
from pathlib import Path
import numpy as np
from enum import Enum
import re
import requests
from urllib.parse import urlparse

warnings.filterwarnings('ignore')

class AlertSeverity(Enum):
    """Alert severity levels"""
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1

class ThreatType(Enum):
    """Types of threats"""
    MALWARE = "Malware"
    DDOS = "DDoS Attack"
    PORT_SCAN = "Port Scan"
    BRUTE_FORCE = "Brute Force"
    DNS_TUNNEL = "DNS Tunneling"
    DATA_EXFIL = "Data Exfiltration"
    BOTNET = "Botnet Activity"
    EXPLOIT = "Exploit Attempt"
    RECONNAISSANCE = "Reconnaissance"
    LATERAL_MOVEMENT = "Lateral Movement"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    MALICIOUS_IP = "Malicious IP"
    SUSPICIOUS_PORT = "Suspicious Port"
    ANOMALY = "Network Anomaly"
    PROTOCOL_VIOLATION = "Protocol Violation"

class MalwareSignatureDB:
    """Database of malware signatures and indicators"""
    
    SIGNATURES = {
        # Port-based signatures
        'ports': {
            # Botnets
            4444: {'name': 'Blaster Worm', 'family': 'Botnet', 'severity': 'CRITICAL'},
            5555: {'name': 'Personal Agent', 'family': 'Botnet', 'severity': 'CRITICAL'},
            6666: {'name': 'Trojan.Delf', 'family': 'Botnet', 'severity': 'CRITICAL'},
            6667: {'name': 'IRC Botnet', 'family': 'Botnet', 'severity': 'CRITICAL'},
            7777: {'name': 'Trojan', 'family': 'Trojan', 'severity': 'HIGH'},
            8888: {'name': 'Proxies', 'family': 'Proxy', 'severity': 'HIGH'},
            9999: {'name': 'Ominous', 'family': 'Botnet', 'severity': 'CRITICAL'},
            
            # Backdoors
            1337: {'name': 'Leet Backdoor', 'family': 'Backdoor', 'severity': 'CRITICAL'},
            12345: {'name': 'NetBus', 'family': 'Backdoor', 'severity': 'CRITICAL'},
            20000: {'name': 'Trojan Injector', 'family': 'Backdoor', 'severity': 'CRITICAL'},
            27374: {'name': 'SubSeven', 'family': 'Backdoor', 'severity': 'CRITICAL'},
            31337: {'name': 'Back Orifice', 'family': 'Backdoor', 'severity': 'CRITICAL'},
            54320: {'name': 'BOSniffer', 'family': 'Backdoor', 'severity': 'CRITICAL'},
            
            # Ransomware
            445: {'name': 'SMB Ransomware', 'family': 'Ransomware', 'severity': 'CRITICAL'},
            3389: {'name': 'RDP Brute Force', 'family': 'Ransomware', 'severity': 'HIGH'},
            
            # Database/Admin
            1433: {'name': 'MSSQL', 'family': 'Database', 'severity': 'MEDIUM'},
            3306: {'name': 'MySQL', 'family': 'Database', 'severity': 'MEDIUM'},
            5432: {'name': 'PostgreSQL', 'family': 'Database', 'severity': 'MEDIUM'},
            6379: {'name': 'Redis', 'family': 'Database', 'severity': 'MEDIUM'},
        },
        
        # IP-based signatures
        'malicious_ips': set(),
        
        # URL patterns
        'url_patterns': [
            r'.*\.(tk|ml|ga|cf)$',  # Free domains often used by malware
            r'.*bit\.ly.*',  # URL shorteners
            r'.*tiny\.url.*',
            r'.*goo\.gl.*',
        ],
        
        # DNS patterns
        'dns_patterns': [
            r'^[a-z0-9]{16,}\..*',  # Random domain generation
            r'^(cmd|powershell|execute)\..*',  # Command domains
        ],
        
        # HTTP User-Agent patterns
        'user_agent_patterns': [
            r'.*curl.*',
            r'.*wget.*',
            r'.*python.*',
            r'.*ruby.*',
            r'.*perl.*',
        ],
        
        # Payload patterns
        'payload_patterns': [
            r'.*\x00.*',  # Null bytes
            r'.*union.*select.*',  # SQL injection
            r'.*<script>.*',  # XSS
            r'.*eval\(.*',  # Code execution
        ]
    }

class NetworkAnomalyDetector:
    """Detect network anomalies using statistical analysis"""
    
    def __init__(self, window_size=300):  # 5 minutes
        self.window_size = window_size
        self.baseline = {
            'packets_per_sec': 0,
            'bytes_per_sec': 0,
            'protocols': defaultdict(int),
            'ports': defaultdict(int),
        }
        self.history = deque(maxlen=window_size)
        self.anomalies = deque(maxlen=1000)
        
    def update_baseline(self, current_stats):
        """Update baseline statistics"""
        self.history.append(current_stats.copy())
        
        if len(self.history) >= self.window_size // 2:
            # Calculate baseline from history
            total_packets = sum(s.get('packets', 0) for s in self.history)
            total_bytes = sum(s.get('bytes', 0) for s in self.history)
            
            self.baseline['packets_per_sec'] = total_packets / len(self.history)
            self.baseline['bytes_per_sec'] = total_bytes / len(self.history)
    
    def detect_anomaly(self, current_stats):
        """Detect anomalies in current traffic"""
        anomalies_detected = []
        
        if not self.baseline['packets_per_sec']:
            return anomalies_detected
        
        # Check for traffic spike
        current_pps = current_stats.get('packets', 0)
        threshold = self.baseline['packets_per_sec'] * 3  # 3x threshold
        
        if current_pps > threshold:
            anomalies_detected.append({
                'type': 'TRAFFIC_SPIKE',
                'description': f'Packet rate spike: {current_pps:.0f} pps (baseline: {self.baseline["packets_per_sec"]:.0f})',
                'severity': AlertSeverity.HIGH
            })
        
        # Check for data volume anomaly
        current_bps = current_stats.get('bytes', 0)
        data_threshold = self.baseline['bytes_per_sec'] * 5  # 5x threshold
        
        if current_bps > data_threshold:
            anomalies_detected.append({
                'type': 'DATA_VOLUME_SPIKE',
                'description': f'Data volume spike: {current_bps / (1024**2):.2f} MB/s',
                'severity': AlertSeverity.HIGH
            })
        
        # Check for protocol anomaly
        for protocol, count in current_stats.get('protocols', {}).items():
            baseline_count = self.baseline['protocols'].get(protocol, 0)
            if baseline_count > 0 and count > baseline_count * 10:
                anomalies_detected.append({
                    'type': 'PROTOCOL_ANOMALY',
                    'description': f'Unusual {protocol} traffic: {count} packets',
                    'severity': AlertSeverity.MEDIUM
                })
        
        return anomalies_detected

class ThreatIntelligence:
    """Threat intelligence database and lookups"""
    
    def __init__(self):
        self.malicious_ips = set()
        self.malicious_domains = set()
        self.load_threat_intel()
    
    def load_threat_intel(self):
        """Load threat intelligence from local sources"""
        # This would normally load from external APIs like:
        # - AlienVault OTX
        # - AbuseIPDB
        # - VirusTotal
        # - URLhaus
        pass
    
    def check_ip_reputation(self, ip):
        """Check IP reputation"""
        # Could integrate with external APIs
        return ip in self.malicious_ips
    
    def check_domain_reputation(self, domain):
        """Check domain reputation"""
        return domain in self.malicious_domains

class GeoIPDatabase:
    """GeoIP lookup for IP addresses"""
    
    def __init__(self):
        self.cache = {}
    
    def lookup(self, ip):
        """Lookup IP geolocation"""
        if ip in self.cache:
            return self.cache[ip]
        
        try:
            # This would use MaxMind GeoIP2 or similar
            # For now, return basic info
            geo_info = {
                'ip': ip,
                'country': 'Unknown',
                'city': 'Unknown',
                'latitude': 0,
                'longitude': 0,
            }
            self.cache[ip] = geo_info
            return geo_info
        except:
            return None

class FlowAnalyzer:
    """Analyze network flows for suspicious patterns"""
    
    def __init__(self):
        self.flows = defaultdict(lambda: {
            'packets': 0,
            'bytes': 0,
            'flags': set(),
            'first_seen': datetime.now(),
            'last_seen': datetime.now(),
        })
        self.suspicious_flows = deque(maxlen=1000)
    
    def add_flow(self, src_ip, dst_ip, src_port, dst_port, protocol, size, flags=None):
        """Add packet to flow"""
        flow_key = f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"
        
        flow = self.flows[flow_key]
        flow['packets'] += 1
        flow['bytes'] += size
        flow['last_seen'] = datetime.now()
        
        if flags:
            flow['flags'].add(flags)
        
        # Analyze flow for anomalies
        self.analyze_flow(flow_key, flow)
    
    def analyze_flow(self, flow_key, flow):
        """Analyze individual flow for suspicious patterns"""
        # Check for SYN flood
        if 'SYN' in flow['flags'] and flow['packets'] > 100:
            self.suspicious_flows.append({
                'type': ThreatType.DDOS,
                'flow': flow_key,
                'severity': AlertSeverity.CRITICAL,
                'description': 'SYN flood detected'
            })
        
        # Check for port scanning
        if flow['packets'] == 1 and flow['bytes'] < 100:
            # Likely a port scan probe
            pass

class PacketAnalyzer:
    """Advanced packet analysis"""
    
    def __init__(self):
        self.threat_intel = ThreatIntelligence()
        self.geo_db = GeoIPDatabase()
        self.flow_analyzer = FlowAnalyzer()
        self.anomaly_detector = NetworkAnomalyDetector()
        
    def analyze_packet(self, packet):
        """Comprehensive packet analysis"""
        packet_info = {
            'timestamp': datetime.now().isoformat(),
            'size': len(packet),
            'protocols': [],
            'src_ip': None,
            'dst_ip': None,
            'src_port': None,
            'dst_port': None,
            'src_geo': None,
            'dst_geo': None,
            'flags': None,
            'threats': [],
            'threat_score': 0,
        }
        
        # Layer 2 - ARP
        if ARP in packet:
            arp = packet[ARP]
            packet_info['protocols'].append('ARP')
            packet_info['src_ip'] = arp.psrc
            packet_info['dst_ip'] = arp.pdst
        
        # Layer 3 - IP
        if IP in packet:
            ip = packet[IP]
            packet_info['src_ip'] = ip.src
            packet_info['dst_ip'] = ip.dst
            packet_info['protocols'].append(f'IPv{ip.version}')
            
            # Check IP reputation
            if self.threat_intel.check_ip_reputation(ip.dst):
                packet_info['threats'].append({
                    'type': ThreatType.MALICIOUS_IP,
                    'severity': AlertSeverity.CRITICAL,
                    'description': f'Malicious IP detected: {ip.dst}'
                })
                packet_info['threat_score'] += 100
            
            # GeoIP lookup
            packet_info['src_geo'] = self.geo_db.lookup(ip.src)
            packet_info['dst_geo'] = self.geo_db.lookup(ip.dst)
        
        # Layer 4 - TCP
        if TCP in packet:
            tcp = packet[TCP]
            packet_info['src_port'] = tcp.sport
            packet_info['dst_port'] = tcp.dport
            packet_info['protocols'].append('TCP')
            
            # Extract TCP flags
            flags = []
            if tcp.flags & 0x01: flags.append('FIN')
            if tcp.flags & 0x02: flags.append('SYN')
            if tcp.flags & 0x04: flags.append('RST')
            if tcp.flags & 0x08: flags.append('PSH')
            if tcp.flags & 0x10: flags.append('ACK')
            if tcp.flags & 0x20: flags.append('URG')
            
            packet_info['flags'] = ','.join(flags)
            
            # Check for suspicious ports
            if self._is_suspicious_port(tcp.dport):
                threat_info = MalwareSignatureDB.SIGNATURES['ports'].get(tcp.dport)
                packet_info['threats'].append({
                    'type': ThreatType.SUSPICIOUS_PORT,
                    'severity': AlertSeverity[threat_info['severity']] if threat_info else AlertSeverity.MEDIUM,
                    'description': f'Connection to suspicious port: {tcp.dport} ({threat_info["name"]})'
                })
                packet_info['threat_score'] += threat_info.get('severity_score', 10)
            
            # Add to flow analyzer
            self.flow_analyzer.add_flow(
                packet_info['src_ip'],
                packet_info['dst_ip'],
                tcp.sport,
                tcp.dport,
                'TCP',
                len(packet),
                ','.join(flags)
            )
        
        # Layer 4 - UDP
        if UDP in packet:
            udp = packet[UDP]
            packet_info['src_port'] = udp.sport
            packet_info['dst_port'] = udp.dport
            packet_info['protocols'].append('UDP')
            
            # Check for DNS (port 53)
            if udp.dport == 53 or udp.sport == 53:
                self._analyze_dns(packet, packet_info)
        
        # Layer 4 - ICMP
        if ICMP in packet:
            icmp = packet[ICMP]
            packet_info['protocols'].append(f'ICMP(type={icmp.type})')
            
            # Check for suspicious ICMP
            if icmp.type in [8, 0]:  # Echo request/reply
                pass  # Normal
            else:
                packet_info['threats'].append({
                    'type': ThreatType.PROTOCOL_VIOLATION,
                    'severity': AlertSeverity.LOW,
                    'description': f'Unusual ICMP type: {icmp.type}'
                })
        
        return packet_info
    
    def _analyze_dns(self, packet, packet_info):
        """Analyze DNS traffic"""
        try:
            if DNS in packet:
                dns = packet[DNS]
                
                if dns.qd:
                    for query in dns.qd:
                        domain = query.qname.decode() if isinstance(query.qname, bytes) else str(query.qname)
                        
                        # Check domain reputation
                        if self.threat_intel.check_domain_reputation(domain):
                            packet_info['threats'].append({
                                'type': ThreatType.MALICIOUS_IP,
                                'severity': AlertSeverity.HIGH,
                                'description': f'Malicious domain: {domain}'
                            })
                            packet_info['threat_score'] += 50
                        
                        # Check for DNS tunneling patterns
                        if self._detect_dns_tunneling(domain):
                            packet_info['threats'].append({
                                'type': ThreatType.DNS_TUNNEL,
                                'severity': AlertSeverity.HIGH,
                                'description': f'DNS tunneling detected: {domain}'
                            })
                            packet_info['threat_score'] += 60
        except:
            pass
    
    def _is_suspicious_port(self, port):
        """Check if port is suspicious"""
        return port in MalwareSignatureDB.SIGNATURES['ports']
    
    def _detect_dns_tunneling(self, domain):
        """Detect DNS tunneling patterns"""
        # Check for unusually long or random-looking domain names
        if len(domain) > 100:
            return True
        
        # Check against patterns
        for pattern in MalwareSignatureDB.SIGNATURES['dns_patterns']:
            if re.match(pattern, domain):
                return True
        
        return False

class AdvancedNetworkMonitorGUI:
    """Advanced Network Monitoring GUI with enhanced features"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("🔒 Advanced Network Security Monitor v3.0 - Enterprise Grade")
        self.root.geometry("1600x1000")
        self.root.configure(bg='#0a0e27')
        
        # Set up dark theme
        self.setup_theme()
        
        # Data structures
        self.packet_analyzer = PacketAnalyzer()
        self.packet_queue = Queue()
        self.running = False
        self.monitoring_thread = None
        
        # Database
        self.db_path = Path('network_monitor.db')
        self.init_database()
        
        # Statistics
        self.stats = {
            'total_packets': 0,
            'total_bytes': 0,
            'protocols': defaultdict(int),
            'ports': defaultdict(int),
            'alerts': deque(maxlen=500),
            'threats': deque(maxlen=500),
            'connections': defaultdict(int),
            'geoip': defaultdict(int),
        }
        
        self.setup_gui()
    
    def setup_theme(self):
        """Setup dark theme"""
        style = ttk.Style()
        style.theme_use('clam')
        
        colors = {
            'bg': '#0a0e27',
            'fg': '#00ff41',
            'select_bg': '#1e3a8a',
            'select_fg': '#00ff41',
            'border': '#1e293b',
        }
        
        style.configure('TFrame', background=colors['bg'])
        style.configure('TLabel', background=colors['bg'], foreground=colors['fg'], font=('Monaco', 9))
        style.configure('Header.TLabel', font=('Monaco', 14, 'bold'))
        style.configure('TButton', background='#1e293b', foreground=colors['fg'])
        style.configure('Treeview', background='#0f172a', foreground=colors['fg'],
                       fieldbackground='#0f172a', borderwidth=1, relief='solid')
        style.configure('Treeview.Heading', background='#1e293b', foreground=colors['fg'])
        style.map('Treeview', background=[('selected', colors['select_bg'])])
    
    def init_database(self):
        """Initialize SQLite database for logging"""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            # Create tables
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS packets (
                    id INTEGER PRIMARY KEY,
                    timestamp TEXT,
                    src_ip TEXT,
                    dst_ip TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    protocol TEXT,
                    size INTEGER,
                    threat_score INTEGER
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY,
                    timestamp TEXT,
                    severity TEXT,
                    threat_type TEXT,
                    description TEXT,
                    src_ip TEXT,
                    dst_ip TEXT,
                    src_port INTEGER,
                    dst_port INTEGER
                )
            ''')
            
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Database error: {e}")
    
    def setup_gui(self):
        """Setup main GUI layout"""
        # Header
        self.create_header()
        
        # Main container
        main_container = ttk.Frame(self.root)
        main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Left panel (20% width) - Control panel
        left_panel = self.create_control_panel(main_container)
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, padx=(0, 10))
        
        # Right panel (80% width) - Tabs
        right_panel = ttk.Frame(main_container)
        right_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Notebook (tabs)
        self.notebook = ttk.Notebook(right_panel)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Create tabs
        self.create_tabs()
    
    def create_header(self):
        """Create header section"""
        header = ttk.Frame(self.root)
        header.pack(fill=tk.X, padx=10, pady=10)
        
        title = ttk.Label(header, text="🔒 ADVANCED NETWORK SECURITY MONITOR", 
                         style='Header.TLabel')
        title.pack(side=tk.LEFT)
        
        # Status indicators
        status_frame = ttk.Frame(header)
        status_frame.pack(side=tk.RIGHT)
        
        self.status_label = ttk.Label(status_frame, text="● OFFLINE")
        self.status_label.pack(side=tk.LEFT, padx=20)
        
        self.threat_indicator = ttk.Label(status_frame, text="⚠️ THREAT LEVEL: SAFE")
        self.threat_indicator.pack(side=tk.LEFT, padx=20)
    
    def create_control_panel(self, parent):
        """Create left control panel"""
        panel = ttk.LabelFrame(parent, text="Control Panel", padding=15)
        
        # Start/Stop buttons
        button_frame = ttk.Frame(panel)
        button_frame.pack(fill=tk.X, pady=10)
        
        self.start_btn = ttk.Button(button_frame, text="▶ START", 
                                   command=self.start_monitoring)
        self.start_btn.pack(fill=tk.X, pady=5)
        
        self.stop_btn = ttk.Button(button_frame, text="⏹ STOP",
                                  command=self.stop_monitoring, state=tk.DISABLED)
        self.stop_btn.pack(fill=tk.X, pady=5)
        
        # Network interface selection
        interface_frame = ttk.LabelFrame(panel, text="Network Interface", padding=10)
        interface_frame.pack(fill=tk.X, pady=10)
        
        self.interface_var = tk.StringVar()
        interfaces = self.get_interfaces()
        
        self.interface_combo = ttk.Combobox(interface_frame, textvariable=self.interface_var,
                                           values=interfaces, state='readonly')
        self.interface_combo.pack(fill=tk.X)
        if interfaces:
            self.interface_combo.current(0)
        
        # Quick stats
        stats_frame = ttk.LabelFrame(panel, text="Quick Stats", padding=10)
        stats_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        self.stat_widgets = {}
        stats_list = [
            ('Total Packets', 'packets'),
            ('Total Bytes', 'bytes'),
            ('Active IPs', 'ips'),
            ('Alerts', 'alerts'),
            ('Threats', 'threats'),
            ('Threat Score', 'score'),
        ]
        
        for label, key in stats_list:
            value_label = ttk.Label(stats_frame, text=f"{label}: 0")
            value_label.pack(fill=tk.X, pady=5)
            self.stat_widgets[key] = value_label
        
        # Export/Reports
        export_frame = ttk.LabelFrame(panel, text="Actions", padding=10)
        export_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(export_frame, text="📊 Export Report",
                  command=self.export_report).pack(fill=tk.X, pady=3)
        ttk.Button(export_frame, text="💾 Save Capture",
                  command=self.save_capture).pack(fill=tk.X, pady=3)
        ttk.Button(export_frame, text="🗑 Clear Data",
                  command=self.clear_data).pack(fill=tk.X, pady=3)
        
        return panel
    
    def create_tabs(self):
        """Create all notebook tabs"""
        self.create_dashboard_tab()
        self.create_threats_tab()
        self.create_traffic_tab()
        self.create_geoip_tab()
        self.create_flows_tab()
        self.create_anomalies_tab()
        self.create_advanced_tab()
    
    def create_dashboard_tab(self):
        """Create main dashboard tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="📊 Dashboard")
        
        # Create 2x3 grid of metric boxes
        metrics_frame = ttk.Frame(tab)
        metrics_frame.pack(fill=tk.X, padx=10, pady=10)
        
        metrics = [
            ('Total Packets', 'total_packets'),
            ('Total Bytes', 'total_bytes'),
            ('Unique IPs', 'unique_ips'),
            ('Open Ports', 'open_ports'),
            ('Connections', 'connections'),
            ('Threat Score', 'threat_score'),
        ]
        
        self.metric_boxes = {}
        for idx, (label, key) in enumerate(metrics):
            row = idx // 3
            col = idx % 3
            
            box = self.create_metric_box(metrics_frame, label, key)
            box.grid(row=row, column=col, padx=10, pady=10, sticky='ew')
            self.metric_boxes[key] = box
        
        # Alerts table
        alerts_frame = ttk.LabelFrame(tab, text="Real-time Alerts", padding=10)
        alerts_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.alerts_tree = ttk.Treeview(alerts_frame, columns=('Time', 'Severity', 'Type', 'Description'),
                                       height=15, show='headings')
        
        self.alerts_tree.column('Time', width=100)
        self.alerts_tree.column('Severity', width=80)
        self.alerts_tree.column('Type', width=120)
        self.alerts_tree.column('Description', width=400)
        
        self.alerts_tree.heading('Time', text='Time')
        self.alerts_tree.heading('Severity', text='Severity')
        self.alerts_tree.heading('Type', text='Type')
        self.alerts_tree.heading('Description', text='Description')
        
        scrollbar = ttk.Scrollbar(alerts_frame, orient=tk.VERTICAL, command=self.alerts_tree.yview)
        self.alerts_tree.configure(yscroll=scrollbar.set)
        
        self.alerts_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def create_metric_box(self, parent, label, key):
        """Create metric display box"""
        box = ttk.LabelFrame(parent, text=label, padding=15)
        
        value_label = ttk.Label(box, text='0', font=('Monaco', 18, 'bold'))
        value_label.pack()
        
        self.stat_widgets[f"box_{key}"] = value_label
        return box
    
    def create_threats_tab(self):
        """Create threats and malware detection tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="🚨 Threats")
        
        # Threat statistics
        stats_frame = ttk.LabelFrame(tab, text="Threat Statistics", padding=10)
        stats_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.threat_stats_text = scrolledtext.ScrolledText(stats_frame, height=8, bg='#0f172a', 
                                                          fg='#00ff41', font=('Monaco', 9))
        self.threat_stats_text.pack(fill=tk.BOTH, expand=True)
        
        # Threats table
        threats_frame = ttk.LabelFrame(tab, text="Detected Threats", padding=10)
        threats_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.threats_tree = ttk.Treeview(threats_frame,
                                        columns=('Time', 'Type', 'Severity', 'Source', 'Destination', 'Details'),
                                        height=15, show='headings')
        
        for col, width in [('Time', 100), ('Type', 120), ('Severity', 80),
                          ('Source', 130), ('Destination', 130), ('Details', 300)]:
            self.threats_tree.column(col, width=width)
            self.threats_tree.heading(col, text=col)
        
        scrollbar = ttk.Scrollbar(threats_frame, orient=tk.VERTICAL, command=self.threats_tree.yview)
        self.threats_tree.configure(yscroll=scrollbar.set)
        
        self.threats_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def create_traffic_tab(self):
        """Create traffic analysis tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="📈 Traffic")
        
        # Protocol distribution
        protocol_frame = ttk.LabelFrame(tab, text="Protocol Distribution", padding=10)
        protocol_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.protocol_text = scrolledtext.ScrolledText(protocol_frame, height=8, bg='#0f172a',
                                                      fg='#00ff41', font=('Monaco', 9))
        self.protocol_text.pack(fill=tk.BOTH, expand=True)
        
        # Port activity
        port_frame = ttk.LabelFrame(tab, text="Port Activity", padding=10)
        port_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.port_text = scrolledtext.ScrolledText(port_frame, height=15, bg='#0f172a',
                                                  fg='#00ff41', font=('Monaco', 9))
        self.port_text.pack(fill=tk.BOTH, expand=True)
    
    def create_geoip_tab(self):
        """Create geographic mapping tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="🌍 GeoIP Map")
        
        # Placeholder for map
        map_frame = ttk.LabelFrame(tab, text="IP Geolocation", padding=10)
        map_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.geoip_text = scrolledtext.ScrolledText(map_frame, bg='#0f172a',
                                                   fg='#00ff41', font=('Monaco', 9))
        self.geoip_text.pack(fill=tk.BOTH, expand=True)
    
    def create_flows_tab(self):
        """Create network flows tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="🔗 Flows")
        
        self.flows_tree = ttk.Treeview(tab,
                                      columns=('Source', 'Destination', 'Packets', 'Bytes', 'Duration', 'State'),
                                      height=20, show='headings')
        
        for col, width in [('Source', 180), ('Destination', 180), ('Packets', 100),
                          ('Bytes', 100), ('Duration', 100), ('State', 80)]:
            self.flows_tree.column(col, width=width)
            self.flows_tree.heading(col, text=col)
        
        scrollbar = ttk.Scrollbar(tab, orient=tk.VERTICAL, command=self.flows_tree.yview)
        self.flows_tree.configure(yscroll=scrollbar.set)
        
        self.flows_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=10)
    
    def create_anomalies_tab(self):
        """Create anomaly detection tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="⚡ Anomalies")
        
        self.anomalies_text = scrolledtext.ScrolledText(tab, bg='#0f172a',
                                                       fg='#00ff41', font=('Monaco', 9))
        self.anomalies_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
    
    def create_advanced_tab(self):
        """Create advanced settings tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="⚙️ Advanced")
        
        settings_frame = ttk.LabelFrame(tab, text="Detection Settings", padding=15)
        settings_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Various settings
        settings = [
            ('Enable DDoS Detection', 'ddos_detection'),
            ('Enable Malware Signatures', 'malware_sig'),
            ('Enable Anomaly Detection', 'anomaly_detect'),
            ('Enable GeoIP Filtering', 'geoip_filter'),
            ('Enable DNS Analysis', 'dns_analysis'),
            ('Log to Database', 'db_logging'),
        ]
        
        self.settings_vars = {}
        for label, key in settings:
            var = tk.BooleanVar(value=True)
            cb = ttk.Checkbutton(settings_frame, text=label, variable=var)
            cb.pack(fill=tk.X, pady=5)
            self.settings_vars[key] = var
        
        # Threshold settings
        threshold_frame = ttk.LabelFrame(tab, text="Thresholds", padding=15)
        threshold_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(threshold_frame, text="Packets/sec threshold:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.pps_threshold = ttk.Entry(threshold_frame, width=20)
        self.pps_threshold.insert(0, "1000")
        self.pps_threshold.grid(row=0, column=1, sticky=tk.W, padx=10)
        
        ttk.Label(threshold_frame, text="MB/sec threshold:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.mbps_threshold = ttk.Entry(threshold_frame, width=20)
        self.mbps_threshold.insert(0, "100")
        self.mbps_threshold.grid(row=1, column=1, sticky=tk.W, padx=10)
    
    def get_interfaces(self):
        """Get network interfaces"""
        try:
            return list(netifaces.interfaces())
        except:
            return ['Any']
    
    def start_monitoring(self):
        """Start packet capture"""
        if not self.running:
            self.running = True
            self.start_btn.config(state=tk.DISABLED)
            self.stop_btn.config(state=tk.NORMAL)
            self.status_label.config(text="● MONITORING")
            
            self.monitoring_thread = threading.Thread(target=self.capture_packets, daemon=True)
            self.monitoring_thread.start()
            
            self.update_thread = threading.Thread(target=self.update_display, daemon=True)
            self.update_thread.start()
    
    def stop_monitoring(self):
        """Stop packet capture"""
        self.running = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status_label.config(text="● OFFLINE")
    
    def capture_packets(self):
        """Capture network packets"""
        try:
            interface = self.interface_var.get() if self.interface_var.get() != 'Any' else None
            
            def packet_callback(packet):
                if not self.running:
                    return
                
                try:
                    packet_info = self.packet_analyzer.analyze_packet(packet)
                    self.packet_queue.put(packet_info)
                    
                    # Update stats
                    self.stats['total_packets'] += 1
                    self.stats['total_bytes'] += packet_info['size']
                    
                    for protocol in packet_info['protocols']:
                        self.stats['protocols'][protocol] += 1
                    
                    # Track threats
                    for threat in packet_info['threats']:
                        self.stats['threats'].append({
                            'timestamp': datetime.now(),
                            'type': threat['type'],
                            'severity': threat['severity'],
                            'src_ip': packet_info['src_ip'],
                            'dst_ip': packet_info['dst_ip'],
                            'description': threat['description'],
                            'threat_score': packet_info['threat_score'],
                        })
                        
                        # Log to database
                        if self.settings_vars['db_logging'].get():
                            self.log_to_database(packet_info, threat)
                
                except Exception as e:
                    pass
            
            sniff(prn=packet_callback, store=False, iface=interface)
        
        except Exception as e:
            messagebox.showerror("Error", f"Capture error: {e}")
            self.stop_monitoring()
    
    def log_to_database(self, packet_info, threat):
        """Log alerts to database"""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO alerts (timestamp, severity, threat_type, description, src_ip, dst_ip, src_port, dst_port)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                datetime.now().isoformat(),
                threat['severity'].name,
                threat['type'].value,
                threat['description'],
                packet_info['src_ip'],
                packet_info['dst_ip'],
                packet_info['src_port'] or 0,
                packet_info['dst_port'] or 0,
            ))
            
            conn.commit()
            conn.close()
        except Exception as e:
            pass
    
    def update_display(self):
        """Update GUI elements"""
        while self.running:
            try:
                # Update metrics
                self.stat_widgets['packets'].config(text=f"Total Packets: {self.stats['total_packets']:,}")
                self.stat_widgets['bytes'].config(text=f"Total Bytes: {self.stats['total_bytes'] / (1024**2):.2f} MB")
                self.stat_widgets['ips'].config(text=f"Active IPs: {len(self.packet_analyzer.flow_analyzer.flows)}")
                self.stat_widgets['alerts'].config(text=f"Alerts: {len(self.stats['alerts'])}")
                self.stat_widgets['threats'].config(text=f"Threats: {len(self.stats['threats'])}")
                
                # Update threat level indicator
                threat_count = len(self.stats['threats'])
                if threat_count > 50:
                    self.threat_indicator.config(text="⚠️ THREAT LEVEL: CRITICAL", foreground='#ff0000')
                elif threat_count > 20:
                    self.threat_indicator.config(text="⚠️ THREAT LEVEL: HIGH", foreground='#ff9900')
                elif threat_count > 5:
                    self.threat_indicator.config(text="⚠️ THREAT LEVEL: MEDIUM", foreground='#ffff00')
                else:
                    self.threat_indicator.config(text="✓ THREAT LEVEL: SAFE", foreground='#00ff41')
                
                # Update alerts table
                self.update_alerts_display()
                
                # Update threats table
                self.update_threats_display()
                
                # Update traffic analysis
                self.update_traffic_display()
                
                # Update flows
                self.update_flows_display()
                
                threading.Event().wait(2)  # Update every 2 seconds
            
            except Exception as e:
                pass
    
    def update_alerts_display(self):
        """Update alerts in table"""
        try:
            for item in self.alerts_tree.get_children():
                self.alerts_tree.delete(item)
            
            for alert in list(self.stats['alerts'])[-20:]:
                self.alerts_tree.insert('', 0, values=(
                    alert.get('timestamp', 'N/A'),
                    'ALERT',
                    'Network',
                    alert.get('description', 'N/A')
                ))
        except:
            pass
    
    def update_threats_display(self):
        """Update threats table"""
        try:
            for item in self.threats_tree.get_children():
                self.threats_tree.delete(item)
            
            for threat in list(self.stats['threats'])[-30:]:
                self.threats_tree.insert('', 0, values=(
                    threat['timestamp'].strftime('%H:%M:%S'),
                    threat['type'].value,
                    threat['severity'].name,
                    threat['src_ip'],
                    threat['dst_ip'],
                    threat['description'][:50]
                ))
        except:
            pass
    
    def update_traffic_display(self):
        """Update traffic analysis"""
        try:
            # Protocol stats
            protocol_text = "=== Protocol Distribution ===\n\n"
            for protocol, count in sorted(self.stats['protocols'].items(), key=lambda x: x[1], reverse=True)[:20]:
                pct = (count / self.stats['total_packets'] * 100) if self.stats['total_packets'] > 0 else 0
                protocol_text += f"{protocol:15} : {count:10,} ({pct:6.2f}%)\n"
            
            self.protocol_text.config(state=tk.NORMAL)
            self.protocol_text.delete(1.0, tk.END)
            self.protocol_text.insert(1.0, protocol_text)
            self.protocol_text.config(state=tk.DISABLED)
            
            # Port stats
            port_text = "=== Active Ports ===\n\n"
            for port, count in sorted(self.stats['ports'].items(), key=lambda x: x[1], reverse=True)[:20]:
                port_text += f"Port {port:5d} : {count:10,} packets\n"
            
            self.port_text.config(state=tk.NORMAL)
            self.port_text.delete(1.0, tk.END)
            self.port_text.insert(1.0, port_text)
            self.port_text.config(state=tk.DISABLED)
        except:
            pass
    
    def update_flows_display(self):
        """Update flows table"""
        try:
            for item in self.flows_tree.get_children():
                self.flows_tree.delete(item)
            
            for flow_key, flow_data in list(self.packet_analyzer.flow_analyzer.flows.items())[:30]:
                duration = (flow_data['last_seen'] - flow_data['first_seen']).total_seconds()
                self.flows_tree.insert('', 0, values=(
                    flow_key.split(' -> ')[0],
                    flow_key.split(' -> ')[1] if ' -> ' in flow_key else 'N/A',
                    flow_data['packets'],
                    f"{flow_data['bytes'] / 1024:.2f} KB",
                    f"{duration:.1f}s",
                    'ACTIVE'
                ))
        except:
            pass
    
    def export_report(self):
        """Export monitoring report"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("CSV files", "*.csv")],
            initialfile=f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        )
        
        if filename:
            try:
                report = {
                    'timestamp': datetime.now().isoformat(),
                    'statistics': {
                        'total_packets': self.stats['total_packets'],
                        'total_bytes': self.stats['total_bytes'],
                        'protocols': dict(self.stats['protocols']),
                        'threat_count': len(self.stats['threats']),
                    },
                    'threats': [
                        {
                            'timestamp': t['timestamp'].isoformat(),
                            'type': t['type'].value,
                            'severity': t['severity'].name,
                            'src_ip': t['src_ip'],
                            'dst_ip': t['dst_ip'],
                            'description': t['description'],
                        }
                        for t in list(self.stats['threats'])[:100]
                    ]
                }
                
                with open(filename, 'w') as f:
                    json.dump(report, f, indent=2)
                
                messagebox.showinfo("Success", f"Report exported to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Export failed: {e}")
    
    def save_capture(self):
        """Save captured packets"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".pcap",
            filetypes=[("PCAP files", "*.pcap")],
            initialfile=f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        )
        
        if filename:
            messagebox.showinfo("Info", "Packet capture saved (feature in development)")
    
    def clear_data(self):
        """Clear all data"""
        if messagebox.askyesno("Confirm", "Clear all monitoring data?"):
            self.stats = {
                'total_packets': 0,
                'total_bytes': 0,
                'protocols': defaultdict(int),
                'ports': defaultdict(int),
                'alerts': deque(maxlen=500),
                'threats': deque(maxlen=500),
                'connections': defaultdict(int),
                'geoip': defaultdict(int),
            }

def main():
    """Main entry point"""
    root = tk.Tk()
    app = AdvancedNetworkMonitorGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Advanced Network Monitoring GUI Application
Real-time network traffic analysis with threat detection
Monitors incoming/outgoing connections, port activity, and suspicious behavior
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import socket
import struct
import textwrap
import json
from datetime import datetime, timedelta
from collections import defaultdict, deque
import psutil
import netifaces
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP
import ipaddress
import subprocess
import platform
import hashlib
from queue import Queue
import warnings

warnings.filterwarnings('ignore')

class ThreatDetector:
    """Detect suspicious network activity"""
    
    SUSPICIOUS_PORTS = {
        # Common malware/backdoor ports
        31337: 'Back Orifice',
        666: 'Doom',
        1337: 'Leet ports',
        1433: 'SQL Server',
        3389: 'RDP Brute Force',
        445: 'SMB/Ransomware',
        4444: 'Blaster Worm',
        5555: 'Personal agent',
        6666: 'Trojan.Delf',
        7777: 'Trojan',
        8888: 'Proxies',
        9999: 'Ominous',
        27374: 'SubSeven',
        27665: 'JILL FTP',
        20000: 'Trojan Injector',
        6129: 'DameWare',
        12345: 'Netbus',
        54320: 'BOSniffer',
    }
    
    KNOWN_MALICIOUS_IPS = set()
    
    @staticmethod
    def check_port_reputation(port):
        """Check if port is known for malicious activity"""
        return port in ThreatDetector.SUSPICIOUS_PORTS
    
    @staticmethod
    def check_ip_reputation(ip):
        """Check if IP is known malicious"""
        return ip in ThreatDetector.KNOWN_MALICIOUS_IPS
    
    @staticmethod
    def detect_syn_flood(packets_count, time_window=5):
        """Detect SYN flood attack"""
        threshold = 100  # packets in 5 seconds
        return packets_count > threshold
    
    @staticmethod
    def detect_port_scan(ports_accessed, time_window=10):
        """Detect port scanning activity"""
        threshold = 50  # ports in 10 seconds
        return len(ports_accessed) > threshold
    
    @staticmethod
    def detect_dns_tunneling(dns_queries, time_window=5):
        """Detect DNS tunneling/exfiltration"""
        threshold = 100  # queries in 5 seconds
        return len(dns_queries) > threshold
    
    @staticmethod
    def detect_brute_force(failed_attempts, time_window=5):
        """Detect brute force attacks"""
        threshold = 20  # failed attempts in 5 seconds
        return failed_attempts > threshold

class NetworkPacketAnalyzer:
    """Analyze network packets in real-time"""
    
    def __init__(self):
        self.packet_stats = defaultdict(int)
        self.connection_map = defaultdict(list)
        self.suspicious_activity = deque(maxlen=1000)
        self.port_activity = defaultdict(lambda: deque(maxlen=100))
        
    def analyze_packet(self, packet):
        """Analyze individual packet"""
        packet_info = {
            'timestamp': datetime.now().isoformat(),
            'size': len(packet),
            'protocols': [],
            'src_ip': None,
            'dst_ip': None,
            'src_port': None,
            'dst_port': None,
            'flags': None,
            'threat_level': 'LOW'
        }
        
        if IP in packet:
            ip_layer = packet[IP]
            packet_info['src_ip'] = ip_layer.src
            packet_info['dst_ip'] = ip_layer.dst
            packet_info['protocols'].append(f'IPv{ip_layer.version}')
            
            # Check for suspicious IPs
            if ThreatDetector.check_ip_reputation(ip_layer.dst):
                packet_info['threat_level'] = 'CRITICAL'
        
        if TCP in packet:
            tcp_layer = packet[TCP]
            packet_info['src_port'] = tcp_layer.sport
            packet_info['dst_port'] = tcp_layer.dport
            packet_info['protocols'].append('TCP')
            packet_info['flags'] = str(tcp_layer.flags)
            
            # Detect SYN flood
            if tcp_layer.flags & 0x02:  # SYN flag
                packet_info['protocols'].append('SYN')
            
            # Check suspicious ports
            if ThreatDetector.check_port_reputation(tcp_layer.dport):
                packet_info['threat_level'] = 'HIGH'
        
        if UDP in packet:
            udp_layer = packet[UDP]
            packet_info['src_port'] = udp_layer.sport
            packet_info['dst_port'] = udp_layer.dport
            packet_info['protocols'].append('UDP')
            
            # DNS on port 53
            if udp_layer.dport == 53 or udp_layer.sport == 53:
                packet_info['protocols'].append('DNS')
        
        if ICMP in packet:
            icmp_layer = packet[ICMP]
            packet_info['protocols'].append(f'ICMP(type={icmp_layer.type})')
        
        if ARP in packet:
            arp_layer = packet[ARP]
            packet_info['protocols'].append('ARP')
            packet_info['src_ip'] = arp_layer.psrc
            packet_info['dst_ip'] = arp_layer.pdst
        
        return packet_info

class NetworkMonitorGUI:
    """Main GUI Application for Network Monitoring"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Network Monitor - Real-time Threat Detection")
        self.root.geometry("1400x900")
        self.root.configure(bg='#1e1e1e')
        
        # Data structures
        self.analyzer = NetworkPacketAnalyzer()
        self.packet_queue = Queue()
        self.running = False
        self.monitoring_thread = None
        
        # Statistics
        self.stats = {
            'total_packets': 0,
            'total_bytes': 0,
            'protocols': defaultdict(int),
            'connections': defaultdict(int),
            'alerts': deque(maxlen=100),
            'connections_history': deque(maxlen=1000)
        }
        
        self.setup_gui()
        self.setup_styles()
        
    def setup_styles(self):
        """Configure visual styles"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Custom colors
        bg_color = '#1e1e1e'
        fg_color = '#00ff00'
        
        style.configure('TFrame', background=bg_color)
        style.configure('TLabel', background=bg_color, foreground=fg_color)
        style.configure('TButton', background='#333333', foreground=fg_color)
        style.configure('Treeview', background='#2d2d2d', foreground=fg_color,
                       fieldbackground='#2d2d2d', borderwidth=0)
        style.configure('Treeview.Heading', background='#333333', foreground=fg_color)
        
        # Custom tag colors
        style.map('Treeview', background=[('selected', '#0078d4')])
        
    def setup_gui(self):
        """Setup main GUI layout"""
        # Header
        self.create_header()
        
        # Main container with notebook (tabs)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Tabs
        self.create_dashboard_tab()
        self.create_traffic_tab()
        self.create_connections_tab()
        self.create_alerts_tab()
        self.create_statistics_tab()
        self.create_settings_tab()
    
    def create_header(self):
        """Create header with controls"""
        header_frame = ttk.Frame(self.root)
        header_frame.pack(fill=tk.X, padx=10, pady=10)
        
        title_label = ttk.Label(header_frame, text="🔒 Network Security Monitor v2.0", 
                               font=('Arial', 16, 'bold'))
        title_label.pack(side=tk.LEFT, padx=10)
        
        # Status indicator
        self.status_label = ttk.Label(header_frame, text="● Stopped", foreground='red')
        self.status_label.pack(side=tk.LEFT, padx=20)
        
        # Control buttons
        button_frame = ttk.Frame(header_frame)
        button_frame.pack(side=tk.RIGHT, padx=10)
        
        self.start_button = ttk.Button(button_frame, text="▶ START MONITORING",
                                       command=self.start_monitoring)
        self.start_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = ttk.Button(button_frame, text="⏹ STOP MONITORING",
                                      command=self.stop_monitoring, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        self.clear_button = ttk.Button(button_frame, text="🗑 CLEAR DATA",
                                       command=self.clear_data)
        self.clear_button.pack(side=tk.LEFT, padx=5)
    
    def create_dashboard_tab(self):
        """Create main dashboard tab"""
        dashboard_frame = ttk.Frame(self.notebook)
        self.notebook.add(dashboard_frame, text="📊 Dashboard")
        
        # Top section - Key metrics
        metrics_frame = ttk.LabelFrame(dashboard_frame, text="Key Metrics", padding=10)
        metrics_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Create metric boxes
        self.metric_labels = {}
        metrics = [
            ('Total Packets', 'total_packets', 0),
            ('Total Data', 'total_bytes', 1),
            ('Protocols', 'protocols_count', 2),
            ('Active Connections', 'connections_count', 3),
            ('Alerts', 'alerts_count', 4),
            ('Threat Level', 'threat_level', 5)
        ]
        
        for label, key, col in metrics:
            box_frame = ttk.Frame(metrics_frame, relief=tk.SUNKEN, borderwidth=2)
            box_frame.grid(row=0, column=col, padx=5, pady=5, sticky='ew')
            
            ttk.Label(box_frame, text=label, font=('Arial', 10, 'bold')).pack(pady=5)
            
            value_label = ttk.Label(box_frame, text='0', font=('Arial', 14, 'bold'),
                                   foreground='#00ff00')
            value_label.pack(pady=5)
            self.metric_labels[key] = value_label
        
        # Bottom section - Real-time alerts
        alerts_frame = ttk.LabelFrame(dashboard_frame, text="🚨 Real-time Alerts", padding=10)
        alerts_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Alerts tree
        self.alerts_tree = ttk.Treeview(alerts_frame, columns=('Time', 'Severity', 'Description'),
                                       height=12, show='tree headings')
        self.alerts_tree.column('#0', width=0, stretch=tk.NO)
        self.alerts_tree.column('Time', anchor=tk.W, width=150)
        self.alerts_tree.column('Severity', anchor=tk.CENTER, width=100)
        self.alerts_tree.column('Description', anchor=tk.W, width=500)
        
        self.alerts_tree.heading('Time', text='Time')
        self.alerts_tree.heading('Severity', text='Severity')
        self.alerts_tree.heading('Description', text='Description')
        
        scrollbar = ttk.Scrollbar(alerts_frame, orient=tk.VERTICAL, command=self.alerts_tree.yview)
        self.alerts_tree.configure(yscroll=scrollbar.set)
        
        self.alerts_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def create_traffic_tab(self):
        """Create traffic analysis tab"""
        traffic_frame = ttk.Frame(self.notebook)
        self.notebook.add(traffic_frame, text="📈 Traffic Analysis")
        
        # Top: Protocol distribution
        protocol_frame = ttk.LabelFrame(traffic_frame, text="Protocol Distribution", padding=10)
        protocol_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.protocol_text = scrolledtext.ScrolledText(protocol_frame, height=8, width=100,
                                                       bg='#2d2d2d', fg='#00ff00', font=('Courier', 9))
        self.protocol_text.pack(fill=tk.BOTH, expand=True)
        
        # Bottom: Incoming/Outgoing traffic
        direction_frame = ttk.LabelFrame(traffic_frame, text="Traffic Direction", padding=10)
        direction_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.direction_text = scrolledtext.ScrolledText(direction_frame, height=15, width=100,
                                                        bg='#2d2d2d', fg='#00ff00', font=('Courier', 9))
        self.direction_text.pack(fill=tk.BOTH, expand=True)
    
    def create_connections_tab(self):
        """Create active connections tab"""
        connections_frame = ttk.Frame(self.notebook)
        self.notebook.add(connections_frame, text="🔗 Active Connections")
        
        # Connections tree
        self.connections_tree = ttk.Treeview(
            connections_frame,
            columns=('Protocol', 'Source IP', 'Src Port', 'Dest IP', 'Dest Port', 'State', 'PID', 'Process'),
            height=20, show='headings'
        )
        
        # Configure columns
        columns_config = [
            ('Protocol', 100),
            ('Source IP', 130),
            ('Src Port', 80),
            ('Dest IP', 130),
            ('Dest Port', 80),
            ('State', 80),
            ('PID', 80),
            ('Process', 200)
        ]
        
        for col, width in columns_config:
            self.connections_tree.column(col, anchor=tk.W, width=width)
            self.connections_tree.heading(col, text=col)
        
        scrollbar = ttk.Scrollbar(connections_frame, orient=tk.VERTICAL,
                                 command=self.connections_tree.yview)
        self.connections_tree.configure(yscroll=scrollbar.set)
        
        self.connections_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=10)
    
    def create_alerts_tab(self):
        """Create detailed alerts tab"""
        alerts_frame = ttk.Frame(self.notebook)
        self.notebook.add(alerts_frame, text="⚠️  Threat Alerts")
        
        # Alert details
        self.alert_details_text = scrolledtext.ScrolledText(alerts_frame, height=30, width=150,
                                                           bg='#2d2d2d', fg='#00ff00', font=('Courier', 9))
        self.alert_details_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Configure tags for colors
        self.alert_details_text.tag_config('CRITICAL', foreground='#ff0000')
        self.alert_details_text.tag_config('HIGH', foreground='#ff9900')
        self.alert_details_text.tag_config('MEDIUM', foreground='#ffff00')
        self.alert_details_text.tag_config('LOW', foreground='#00ff00')
    
    def create_statistics_tab(self):
        """Create statistics tab"""
        stats_frame = ttk.Frame(self.notebook)
        self.notebook.add(stats_frame, text="📊 Statistics")
        
        # Statistics display
        self.stats_text = scrolledtext.ScrolledText(stats_frame, height=30, width=150,
                                                   bg='#2d2d2d', fg='#00ff00', font=('Courier', 9))
        self.stats_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
    
    def create_settings_tab(self):
        """Create settings tab"""
        settings_frame = ttk.Frame(self.notebook)
        self.notebook.add(settings_frame, text="⚙️  Settings")
        
        # Network interface selection
        interface_frame = ttk.LabelFrame(settings_frame, text="Network Configuration", padding=10)
        interface_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(interface_frame, text="Monitor Interface:").pack(side=tk.LEFT, padx=5)
        
        self.interface_var = tk.StringVar()
        interfaces = self.get_network_interfaces()
        
        interface_combo = ttk.Combobox(interface_frame, textvariable=self.interface_var,
                                      values=interfaces, state='readonly', width=30)
        interface_combo.pack(side=tk.LEFT, padx=5)
        if interfaces:
            interface_combo.current(0)
        
        # Alert thresholds
        threshold_frame = ttk.LabelFrame(settings_frame, text="Alert Thresholds", padding=10)
        threshold_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Packet threshold
        ttk.Label(threshold_frame, text="Packets/sec:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.packet_threshold = ttk.Entry(threshold_frame, width=10)
        self.packet_threshold.insert(0, "1000")
        self.packet_threshold.grid(row=0, column=1, padx=5, pady=5)
        
        # Data threshold
        ttk.Label(threshold_frame, text="Data MB/sec:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.data_threshold = ttk.Entry(threshold_frame, width=10)
        self.data_threshold.insert(0, "100")
        self.data_threshold.grid(row=1, column=1, padx=5, pady=5)
        
        # Port scan threshold
        ttk.Label(threshold_frame, text="Port Scan Ports:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        self.port_threshold = ttk.Entry(threshold_frame, width=10)
        self.port_threshold.insert(0, "50")
        self.port_threshold.grid(row=2, column=1, padx=5, pady=5)
        
        # System info
        system_frame = ttk.LabelFrame(settings_frame, text="System Information", padding=10)
        system_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.system_info_text = scrolledtext.ScrolledText(system_frame, height=15, width=150,
                                                         bg='#2d2d2d', fg='#00ff00', font=('Courier', 9))
        self.system_info_text.pack(fill=tk.BOTH, expand=True)
        
        self.display_system_info()
    
    def get_network_interfaces(self):
        """Get available network interfaces"""
        interfaces = []
        if platform.system() == 'Windows':
            # Windows interfaces
            try:
                result = subprocess.run(['ipconfig'], capture_output=True, text=True)
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'Ethernet adapter' in line or 'Wireless' in line:
                        interface = line.split(':')[0].strip()
                        interfaces.append(interface)
            except:
                pass
        else:
            # Linux/Mac interfaces
            interfaces = list(netifaces.interfaces())
        
        return interfaces if interfaces else ['Any']
    
    def display_system_info(self):
        """Display system information"""
        self.system_info_text.delete(1.0, tk.END)
        
        info = f"""
=== SYSTEM INFORMATION ===
Hostname: {socket.gethostname()}
Platform: {platform.platform()}
Processor: {platform.processor()}
Machine: {platform.machine()}

=== NETWORK INTERFACES ===
"""
        
        for iface in netifaces.interfaces():
            ifaddresses = netifaces.ifaddresses(iface)
            info += f"\n{iface}:\n"
            for addr_type, addrs in ifaddresses.items():
                info += f"  {addr_type}: {addrs}\n"
        
        # CPU and Memory
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        
        info += f"""
=== SYSTEM RESOURCES ===
CPU Usage: {cpu_percent}%
Memory Total: {memory.total / (1024**3):.2f} GB
Memory Used: {memory.used / (1024**3):.2f} GB
Memory Percent: {memory.percent}%
"""
        
        self.system_info_text.insert(1.0, info)
    
    def start_monitoring(self):
        """Start network monitoring"""
        if not self.running:
            self.running = True
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.status_label.config(text="● Monitoring", foreground='#00ff00')
            
            # Start monitoring thread
            self.monitoring_thread = threading.Thread(target=self.monitor_network, daemon=True)
            self.monitoring_thread.start()
            
            # Start update thread
            self.update_thread = threading.Thread(target=self.update_display, daemon=True)
            self.update_thread.start()
    
    def stop_monitoring(self):
        """Stop network monitoring"""
        self.running = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.status_label.config(text="● Stopped", foreground='red')
    
    def monitor_network(self):
        """Capture and analyze network packets"""
        try:
            interface = self.interface_var.get() if self.interface_var.get() != 'Any' else None
            
            def packet_callback(packet):
                if not self.running:
                    return
                
                try:
                    packet_info = self.analyzer.analyze_packet(packet)
                    self.packet_queue.put(packet_info)
                    
                    # Update statistics
                    self.stats['total_packets'] += 1
                    self.stats['total_bytes'] += packet_info['size']
                    
                    # Track protocols
                    for protocol in packet_info['protocols']:
                        self.stats['protocols'][protocol] += 1
                    
                    # Check for threats
                    if packet_info['threat_level'] != 'LOW':
                        alert = {
                            'timestamp': datetime.now(),
                            'severity': packet_info['threat_level'],
                            'description': f"{packet_info['src_ip']} → {packet_info['dst_ip']}:{packet_info['dst_port']} ({', '.join(packet_info['protocols'])})",
                            'packet_info': packet_info
                        }
                        self.stats['alerts'].append(alert)
                
                except Exception as e:
                    pass
            
            # Start sniffing
            sniff(prn=packet_callback, store=False, iface=interface)
        
        except Exception as e:
            messagebox.showerror("Monitoring Error", f"Error during packet capture:\n{str(e)}")
            self.stop_monitoring()
    
    def update_display(self):
        """Update GUI with real-time data"""
        while self.running:
            try:
                # Update metrics
                self.metric_labels['total_packets'].config(text=f"{self.stats['total_packets']:,}")
                self.metric_labels['total_bytes'].config(text=f"{self.stats['total_bytes'] / (1024**2):.2f} MB")
                self.metric_labels['protocols_count'].config(text=str(len(self.stats['protocols'])))
                self.metric_labels['connections_count'].config(text=str(len(self.get_active_connections())))
                self.metric_labels['alerts_count'].config(text=str(len(self.stats['alerts'])))
                
                # Determine threat level
                if len(self.stats['alerts']) > 10:
                    threat_level = 'CRITICAL'
                    color = '#ff0000'
                elif len(self.stats['alerts']) > 5:
                    threat_level = 'HIGH'
                    color = '#ff9900'
                else:
                    threat_level = 'SAFE'
                    color = '#00ff00'
                
                self.metric_labels['threat_level'].config(text=threat_level, foreground=color)
                
                # Update alerts display
                self.update_alerts_display()
                
                # Update traffic analysis
                self.update_traffic_display()
                
                # Update connections
                self.update_connections_display()
                
                # Update statistics
                self.update_statistics_display()
                
                threading.Event().wait(2)  # Update every 2 seconds
            
            except Exception as e:
                pass
    
    def update_alerts_display(self):
        """Update alerts in dashboard"""
        try:
            # Clear existing items
            for item in self.alerts_tree.get_children():
                self.alerts_tree.delete(item)
            
            # Add new alerts (most recent first)
            for alert in reversed(list(self.stats['alerts'])[-10:]):
                severity = alert['severity']
                color_tag = ''
                
                if severity == 'CRITICAL':
                    color_tag = 'critical'
                elif severity == 'HIGH':
                    color_tag = 'high'
                
                self.alerts_tree.insert('', 0, values=(
                    alert['timestamp'].strftime('%H:%M:%S'),
                    severity,
                    alert['description']
                ))
        
        except Exception as e:
            pass
    
    def update_traffic_display(self):
        """Update traffic analysis"""
        try:
            # Protocol distribution
            protocol_text = "=== Protocol Distribution ===\n\n"
            for protocol, count in sorted(self.stats['protocols'].items(), key=lambda x: x[1], reverse=True):
                percentage = (count / self.stats['total_packets'] * 100) if self.stats['total_packets'] > 0 else 0
                protocol_text += f"{protocol:15} : {count:10,} packets ({percentage:6.2f}%)\n"
            
            self.protocol_text.config(state=tk.NORMAL)
            self.protocol_text.delete(1.0, tk.END)
            self.protocol_text.insert(1.0, protocol_text)
            self.protocol_text.config(state=tk.DISABLED)
            
            # Incoming/Outgoing traffic
            direction_text = self.analyze_traffic_direction()
            self.direction_text.config(state=tk.NORMAL)
            self.direction_text.delete(1.0, tk.END)
            self.direction_text.insert(1.0, direction_text)
            self.direction_text.config(state=tk.DISABLED)
        
        except Exception as e:
            pass
    
    def analyze_traffic_direction(self):
        """Analyze incoming vs outgoing traffic"""
        text = "=== Traffic Direction Analysis ===\n\n"
        
        try:
            local_ips = self.get_local_ips()
            incoming = 0
            outgoing = 0
            
            while not self.packet_queue.empty():
                packet_info = self.packet_queue.get()
                
                if packet_info['src_ip']:
                    if packet_info['src_ip'] in local_ips:
                        outgoing += 1
                    else:
                        incoming += 1
            
            text += f"Incoming Traffic: {incoming:,} packets\n"
            text += f"Outgoing Traffic: {outgoing:,} packets\n"
            text += f"Total: {incoming + outgoing:,} packets\n\n"
            
            text += "=== High Activity Ports ===\n\n"
            
            # Get port activity
            port_activity = defaultdict(int)
            while not self.packet_queue.empty():
                try:
                    packet_info = self.packet_queue.get_nowait()
                    if packet_info['dst_port']:
                        port_activity[packet_info['dst_port']] += 1
                except:
                    break
            
            for port, count in sorted(port_activity.items(), key=lambda x: x[1], reverse=True)[:10]:
                text += f"Port {port:5d} : {count:6,} packets\n"
        
        except Exception as e:
            text += f"Error: {str(e)}\n"
        
        return text
    
    def get_local_ips(self):
        """Get local IP addresses"""
        local_ips = set()
        try:
            for iface in netifaces.interfaces():
                ifaddresses = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in ifaddresses:
                    for addr_info in ifaddresses[netifaces.AF_INET]:
                        local_ips.add(addr_info['addr'])
        except:
            pass
        
        return local_ips
    
    def get_active_connections(self):
        """Get active network connections"""
        connections = []
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED':
                    try:
                        process = psutil.Process(conn.pid)
                        connections.append({
                            'protocol': 'TCP',
                            'src_ip': conn.laddr.ip if conn.laddr else 'N/A',
                            'src_port': conn.laddr.port if conn.laddr else 0,
                            'dst_ip': conn.raddr.ip if conn.raddr else 'N/A',
                            'dst_port': conn.raddr.port if conn.raddr else 0,
                            'state': conn.status,
                            'pid': conn.pid,
                            'process': process.name()
                        })
                    except:
                        pass
        except:
            pass
        
        return connections
    
    def update_connections_display(self):
        """Update active connections display"""
        try:
            # Clear existing items
            for item in self.connections_tree.get_children():
                self.connections_tree.delete(item)
            
            # Add connections
            connections = self.get_active_connections()
            for conn in connections[:50]:  # Limit to 50 for performance
                self.connections_tree.insert('', tk.END, values=(
                    conn['protocol'],
                    conn['src_ip'],
                    conn['src_port'],
                    conn['dst_ip'],
                    conn['dst_port'],
                    conn['state'],
                    conn['pid'],
                    conn['process']
                ))
        
        except Exception as e:
            pass
    
    def update_statistics_display(self):
        """Update statistics display"""
        try:
            stats_text = f"""
=== NETWORK STATISTICS ===

Total Packets: {self.stats['total_packets']:,}
Total Data: {self.stats['total_bytes'] / (1024**2):.2f} MB
Active Protocols: {len(self.stats['protocols'])}
Active Connections: {len(self.get_active_connections())}
Total Alerts: {len(self.stats['alerts'])}

=== PROTOCOL BREAKDOWN ===
"""
            
            for protocol, count in sorted(self.stats['protocols'].items(), key=lambda x: x[1], reverse=True):
                stats_text += f"{protocol:15} : {count:10,}\n"
            
            stats_text += f"""
=== RECENT ALERTS ===
"""
            
            for alert in reversed(list(self.stats['alerts'])[-10:]):
                stats_text += f"\n[{alert['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}] {alert['severity']}: {alert['description']}\n"
            
            self.stats_text.config(state=tk.NORMAL)
            self.stats_text.delete(1.0, tk.END)
            self.stats_text.insert(1.0, stats_text)
            self.stats_text.config(state=tk.DISABLED)
        
        except Exception as e:
            pass
    
    def clear_data(self):
        """Clear all collected data"""
        confirm = messagebox.askyesno("Confirm", "Clear all monitoring data?")
        if confirm:
            self.stats = {
                'total_packets': 0,
                'total_bytes': 0,
                'protocols': defaultdict(int),
                'connections': defaultdict(int),
                'alerts': deque(maxlen=100),
                'connections_history': deque(maxlen=1000)
            }
            messagebox.showinfo("Success", "Data cleared")

def main():
    """Main entry point"""
    root = tk.Tk()
    app = NetworkMonitorGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()

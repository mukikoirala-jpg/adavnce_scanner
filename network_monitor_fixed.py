#!/usr/bin/env python3
"""
ADVANCED NETWORK MONITORING & INTRUSION DETECTION SYSTEM v3.1 (FIXED)
Real-time threat detection with working features
Monitors: Protocols, Ports, Connections, Anomalies, DDoS
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import threading
import socket
import textwrap
import json
from datetime import datetime, timedelta
from collections import defaultdict, deque
import psutil
import netifaces
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, DNS
import ipaddress
import subprocess
import platform
import hashlib
from queue import Queue
import warnings
import sqlite3
from pathlib import Path
import re

warnings.filterwarnings('ignore')

class AlertSeverity:
    """Alert severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class MalwareSignatureDB:
    """Database of malware signatures and indicators"""
    
    SIGNATURES = {
        'ports': {
            # Botnets
            4444: {'name': 'Blaster Worm', 'family': 'Botnet', 'severity': 'CRITICAL'},
            5555: {'name': 'Personal Agent', 'family': 'Botnet', 'severity': 'CRITICAL'},
            6666: {'name': 'Trojan.Delf', 'family': 'Botnet', 'severity': 'CRITICAL'},
            6667: {'name': 'IRC Botnet', 'family': 'Botnet', 'severity': 'CRITICAL'},
            7777: {'name': 'Trojan', 'family': 'Trojan', 'severity': 'HIGH'},
            8888: {'name': 'Proxies', 'family': 'Proxy', 'severity': 'HIGH'},
            9999: {'name': 'Ominous', 'family': 'Botnet', 'severity': 'CRITICAL'},
            1337: {'name': 'Leet Backdoor', 'family': 'Backdoor', 'severity': 'CRITICAL'},
            12345: {'name': 'NetBus', 'family': 'Backdoor', 'severity': 'CRITICAL'},
            445: {'name': 'SMB Ransomware', 'family': 'Ransomware', 'severity': 'CRITICAL'},
            3389: {'name': 'RDP Brute Force', 'family': 'Ransomware', 'severity': 'HIGH'},
        }
    }

class NetworkAnomalyDetector:
    """Detect network anomalies using statistical analysis"""
    
    def __init__(self, window_size=60):
        self.window_size = window_size
        self.baseline = {
            'packets_per_sec': 0,
            'bytes_per_sec': 0,
        }
        self.history = deque(maxlen=window_size)
        self.anomalies = deque(maxlen=100)
        self.syn_count = 0
        self.port_scan_ports = defaultdict(list)
        
    def update_baseline(self, packets, bytes_total):
        """Update baseline statistics"""
        self.history.append({'packets': packets, 'bytes': bytes_total})
        
        if len(self.history) >= 10:
            avg_packets = sum(h['packets'] for h in self.history) / len(self.history)
            avg_bytes = sum(h['bytes'] for h in self.history) / len(self.history)
            self.baseline['packets_per_sec'] = avg_packets
            self.baseline['bytes_per_sec'] = avg_bytes
    
    def detect_anomaly(self, current_packets, current_bytes):
        """Detect anomalies"""
        anomalies = []
        
        if self.baseline['packets_per_sec'] > 0:
            pps_threshold = self.baseline['packets_per_sec'] * 3
            if current_packets > pps_threshold:
                anomalies.append({
                    'type': 'TRAFFIC_SPIKE',
                    'description': f'Packet rate spike: {current_packets} pps',
                    'severity': AlertSeverity.HIGH
                })
        
        return anomalies

class PacketAnalyzer:
    """Advanced packet analysis"""
    
    def __init__(self):
        self.flow_tracker = defaultdict(lambda: {'packets': 0, 'bytes': 0, 'flags': set()})
        self.dns_queries = deque(maxlen=1000)
        self.syn_packets = 0
        self.last_ports_scanned = deque(maxlen=100)
        
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
            'flags': None,
            'threats': [],
            'threat_score': 0,
        }
        
        try:
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
            
            # Layer 4 - TCP
            if TCP in packet:
                tcp = packet[TCP]
                packet_info['src_port'] = tcp.sport
                packet_info['dst_port'] = tcp.dport
                packet_info['protocols'].append('TCP')
                
                # Extract TCP flags
                flags = []
                if tcp.flags & 0x01: flags.append('FIN')
                if tcp.flags & 0x02: 
                    flags.append('SYN')
                    self.syn_packets += 1
                    if self.syn_packets > 100:  # SYN flood detection
                        packet_info['threats'].append({
                            'type': 'SYN_FLOOD',
                            'severity': AlertSeverity.CRITICAL,
                            'description': f'SYN flood detected: {self.syn_packets} SYN packets'
                        })
                        packet_info['threat_score'] += 100
                        self.syn_packets = 0
                
                if tcp.flags & 0x04: flags.append('RST')
                if tcp.flags & 0x08: flags.append('PSH')
                if tcp.flags & 0x10: flags.append('ACK')
                if tcp.flags & 0x20: flags.append('URG')
                
                packet_info['flags'] = ','.join(flags)
                
                # Check for suspicious ports
                if tcp.dport in MalwareSignatureDB.SIGNATURES['ports']:
                    threat_info = MalwareSignatureDB.SIGNATURES['ports'][tcp.dport]
                    packet_info['threats'].append({
                        'type': 'SUSPICIOUS_PORT',
                        'severity': threat_info['severity'],
                        'description': f'Connection to suspicious port: {tcp.dport} ({threat_info["name"]})'
                    })
                    packet_info['threat_score'] += 50
                
                # Track flow
                flow_key = f"{packet_info['src_ip']}:{tcp.sport} -> {packet_info['dst_ip']}:{tcp.dport}"
                self.flow_tracker[flow_key]['packets'] += 1
                self.flow_tracker[flow_key]['bytes'] += len(packet)
                self.flow_tracker[flow_key]['flags'].update(flags)
                
                # Port scan detection
                if len(flags) == 1 and 'SYN' in flags:
                    self.last_ports_scanned.append(tcp.dport)
                    if len(self.last_ports_scanned) > 50:
                        packet_info['threats'].append({
                            'type': 'PORT_SCAN',
                            'severity': AlertSeverity.HIGH,
                            'description': f'Port scanning detected: {len(self.last_ports_scanned)} ports in short time'
                        })
                        packet_info['threat_score'] += 70
            
            # Layer 4 - UDP
            if UDP in packet:
                udp = packet[UDP]
                packet_info['src_port'] = udp.sport
                packet_info['dst_port'] = udp.dport
                packet_info['protocols'].append('UDP')
                
                # Check for DNS (port 53)
                if udp.dport == 53 or udp.sport == 53:
                    self.dns_queries.append((packet_info['src_ip'], datetime.now()))
                    if len(self.dns_queries) > 100:
                        packet_info['threats'].append({
                            'type': 'DNS_TUNNEL',
                            'severity': AlertSeverity.HIGH,
                            'description': f'Possible DNS tunneling: {len(self.dns_queries)} queries'
                        })
                        packet_info['threat_score'] += 60
            
            # Layer 4 - ICMP
            if ICMP in packet:
                icmp = packet[ICMP]
                packet_info['protocols'].append(f'ICMP(type={icmp.type})')
        
        except Exception as e:
            pass
        
        return packet_info

class AdvancedNetworkMonitorGUI:
    """Advanced Network Monitoring GUI"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("🔒 Advanced Network Security Monitor v3.1")
        self.root.geometry("1600x1000")
        self.root.configure(bg='#0a0e27')
        
        # Setup theme
        self.setup_theme()
        
        # Data
        self.packet_analyzer = PacketAnalyzer()
        self.anomaly_detector = NetworkAnomalyDetector()
        self.packet_queue = Queue()
        self.running = False
        self.monitoring_thread = None
        self.last_packet_count = 0
        self.packet_count_per_sec = 0
        
        # Statistics
        self.stats = {
            'total_packets': 0,
            'total_bytes': 0,
            'protocols': defaultdict(int),
            'ports': defaultdict(int),
            'alerts': deque(maxlen=100),
            'threats': deque(maxlen=100),
            'connections': set(),
        }
        
        # Database
        self.init_database()
        
        # GUI
        self.setup_gui()
        
        # Start update loop
        self.update_display()
    
    def setup_theme(self):
        """Setup dark theme"""
        style = ttk.Style()
        style.theme_use('clam')
        
        style.configure('TFrame', background='#0a0e27')
        style.configure('TLabel', background='#0a0e27', foreground='#00ff41', font=('Courier', 9))
        style.configure('Header.TLabel', font=('Courier', 14, 'bold'), foreground='#00ff41')
        style.configure('TButton', background='#1e293b', foreground='#00ff41')
        style.configure('Treeview', background='#0f172a', foreground='#00ff41',
                       fieldbackground='#0f172a', borderwidth=1)
        style.configure('Treeview.Heading', background='#1e293b', foreground='#00ff41')
        style.map('Treeview', background=[('selected', '#1e3a8a')])
    
    def init_database(self):
        """Initialize SQLite database"""
        try:
            self.db_path = Path('network_monitor.db')
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
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
            print(f"DB Error: {e}")
    
    def setup_gui(self):
        """Setup GUI layout"""
        # Header
        header = ttk.Frame(self.root)
        header.pack(fill=tk.X, padx=10, pady=10)
        
        title = ttk.Label(header, text="🔒 ADVANCED NETWORK SECURITY MONITOR", style='Header.TLabel')
        title.pack(side=tk.LEFT)
        
        self.status_label = ttk.Label(header, text="● OFFLINE", foreground='red', font=('Courier', 10, 'bold'))
        self.status_label.pack(side=tk.RIGHT, padx=20)
        
        # Main container
        main = ttk.Frame(self.root)
        main.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Left panel
        left = ttk.LabelFrame(main, text="Control Panel", padding=10)
        left.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        
        self.start_btn = ttk.Button(left, text="▶ START", command=self.start_monitoring)
        self.start_btn.pack(fill=tk.X, pady=5)
        
        self.stop_btn = ttk.Button(left, text="⏹ STOP", command=self.stop_monitoring, state=tk.DISABLED)
        self.stop_btn.pack(fill=tk.X, pady=5)
        
        # Interface selection
        ttk.Label(left, text="Interface:").pack(pady=5)
        self.interface_var = tk.StringVar()
        interfaces = self.get_interfaces()
        combo = ttk.Combobox(left, textvariable=self.interface_var, values=interfaces, state='readonly')
        combo.pack(fill=tk.X, pady=5)
        if interfaces:
            combo.current(0)
        
        # Stats
        ttk.Label(left, text="Statistics:", font=('Courier', 10, 'bold')).pack(pady=(10, 5))
        
        self.stat_labels = {}
        for stat in ['Packets', 'Bytes', 'Threats', 'Alerts']:
            label = ttk.Label(left, text=f"{stat}: 0")
            label.pack(fill=tk.X, pady=2)
            self.stat_labels[stat] = label
        
        # Actions
        ttk.Label(left, text="Actions:", font=('Courier', 10, 'bold')).pack(pady=(10, 5))
        ttk.Button(left, text="📊 Export", command=self.export_report).pack(fill=tk.X, pady=3)
        ttk.Button(left, text="🗑 Clear", command=self.clear_data).pack(fill=tk.X, pady=3)
        
        # Right panel - Notebook
        right = ttk.Frame(main)
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        self.notebook = ttk.Notebook(right)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        self.create_tabs()
    
    def create_tabs(self):
        """Create tabs"""
        # Dashboard
        tab1 = ttk.Frame(self.notebook)
        self.notebook.add(tab1, text="📊 Dashboard")
        
        # Metrics
        metrics_frame = ttk.LabelFrame(tab1, text="Real-time Metrics", padding=10)
        metrics_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.metric_widgets = {}
        for i, label in enumerate(['Total Packets', 'Total Bytes', 'Unique IPs', 'Threats Detected']):
            box = ttk.LabelFrame(metrics_frame, text=label, padding=10)
            box.grid(row=0, column=i, padx=5, pady=5, sticky='ew')
            
            val = ttk.Label(box, text='0', font=('Courier', 16, 'bold'), foreground='#00ff41')
            val.pack()
            self.metric_widgets[label] = val
        
        # Alerts
        alerts_frame = ttk.LabelFrame(tab1, text="🚨 Real-time Alerts", padding=10)
        alerts_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.alerts_tree = ttk.Treeview(alerts_frame, columns=('Time', 'Severity', 'Description'), height=15)
        self.alerts_tree.column('#0', width=0)
        self.alerts_tree.column('Time', anchor=tk.W, width=100)
        self.alerts_tree.column('Severity', anchor=tk.CENTER, width=80)
        self.alerts_tree.column('Description', anchor=tk.W, width=500)
        
        self.alerts_tree.heading('Time', text='Time')
        self.alerts_tree.heading('Severity', text='Severity')
        self.alerts_tree.heading('Description', text='Description')
        
        scroll = ttk.Scrollbar(alerts_frame, orient=tk.VERTICAL, command=self.alerts_tree.yview)
        self.alerts_tree.configure(yscroll=scroll.set)
        
        self.alerts_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Threats
        tab2 = ttk.Frame(self.notebook)
        self.notebook.add(tab2, text="🚨 Threats")
        
        self.threats_text = scrolledtext.ScrolledText(tab2, bg='#0f172a', fg='#00ff41', font=('Courier', 9), height=30)
        self.threats_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Traffic
        tab3 = ttk.Frame(self.notebook)
        self.notebook.add(tab3, text="📈 Traffic")
        
        proto_frame = ttk.LabelFrame(tab3, text="Protocols", padding=10)
        proto_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.protocol_text = scrolledtext.ScrolledText(proto_frame, bg='#0f172a', fg='#00ff41', font=('Courier', 9), height=8)
        self.protocol_text.pack(fill=tk.BOTH, expand=True)
        
        port_frame = ttk.LabelFrame(tab3, text="Ports", padding=10)
        port_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.port_text = scrolledtext.ScrolledText(port_frame, bg='#0f172a', fg='#00ff41', font=('Courier', 9), height=15)
        self.port_text.pack(fill=tk.BOTH, expand=True)
        
        # Flows
        tab4 = ttk.Frame(self.notebook)
        self.notebook.add(tab4, text="🔗 Flows")
        
        self.flows_tree = ttk.Treeview(tab4, columns=('Source', 'Destination', 'Packets', 'Bytes'), height=20)
        self.flows_tree.column('#0', width=0)
        self.flows_tree.column('Source', anchor=tk.W, width=200)
        self.flows_tree.column('Destination', anchor=tk.W, width=200)
        self.flows_tree.column('Packets', anchor=tk.CENTER, width=100)
        self.flows_tree.column('Bytes', anchor=tk.CENTER, width=100)
        
        self.flows_tree.heading('Source', text='Source')
        self.flows_tree.heading('Destination', text='Destination')
        self.flows_tree.heading('Packets', text='Packets')
        self.flows_tree.heading('Bytes', text='Bytes')
        
        scroll = ttk.Scrollbar(tab4, orient=tk.VERTICAL, command=self.flows_tree.yview)
        self.flows_tree.configure(yscroll=scroll.set)
        
        self.flows_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        scroll.pack(side=tk.RIGHT, fill=tk.Y, pady=10)
        
        # Statistics
        tab5 = ttk.Frame(self.notebook)
        self.notebook.add(tab5, text="📊 Statistics")
        
        self.stats_text = scrolledtext.ScrolledText(tab5, bg='#0f172a', fg='#00ff41', font=('Courier', 9))
        self.stats_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
    
    def get_interfaces(self):
        """Get network interfaces"""
        try:
            return list(netifaces.interfaces())
        except:
            return ['Any']
    
    def start_monitoring(self):
        """Start monitoring"""
        if not self.running:
            self.running = True
            self.start_btn.config(state=tk.DISABLED)
            self.stop_btn.config(state=tk.NORMAL)
            self.status_label.config(text="● MONITORING", foreground='#00ff41')
            
            self.monitoring_thread = threading.Thread(target=self.capture_packets, daemon=True)
            self.monitoring_thread.start()
    
    def stop_monitoring(self):
        """Stop monitoring"""
        self.running = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status_label.config(text="● OFFLINE", foreground='red')
    
    def capture_packets(self):
        """Capture packets"""
        try:
            interface = self.interface_var.get() if self.interface_var.get() != 'Any' else None
            
            def packet_callback(packet):
                if not self.running:
                    return
                
                try:
                    packet_info = self.packet_analyzer.analyze_packet(packet)
                    self.packet_queue.put(packet_info)
                    
                    self.stats['total_packets'] += 1
                    self.stats['total_bytes'] += packet_info['size']
                    
                    for protocol in packet_info['protocols']:
                        self.stats['protocols'][protocol] += 1
                    
                    if packet_info['src_port']:
                        self.stats['ports'][packet_info['src_port']] += 1
                    if packet_info['dst_port']:
                        self.stats['ports'][packet_info['dst_port']] += 1
                    
                    for threat in packet_info['threats']:
                        self.stats['threats'].append({
                            'timestamp': datetime.now(),
                            'type': threat['type'],
                            'severity': threat['severity'],
                            'description': threat['description'],
                            'src_ip': packet_info['src_ip'],
                            'dst_ip': packet_info['dst_ip'],
                        })
                        self.log_to_db(packet_info, threat)
                
                except:
                    pass
            
            sniff(prn=packet_callback, store=False, iface=interface)
        
        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.stop_monitoring()
    
    def log_to_db(self, packet_info, threat):
        """Log to database"""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO alerts VALUES (NULL, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                datetime.now().isoformat(),
                threat['severity'],
                threat['type'],
                threat['description'],
                packet_info['src_ip'],
                packet_info['dst_ip'],
                packet_info['src_port'] or 0,
                packet_info['dst_port'] or 0,
            ))
            conn.commit()
            conn.close()
        except:
            pass
    
    def update_display(self):
        """Update display"""
        try:
            # Update metrics
            self.metric_widgets['Total Packets'].config(text=f"{self.stats['total_packets']:,}")
            self.metric_widgets['Total Bytes'].config(text=f"{self.stats['total_bytes'] / (1024**2):.2f} MB")
            self.metric_widgets['Unique IPs'].config(text=str(len(self.packet_analyzer.flow_tracker)))
            self.metric_widgets['Threats Detected'].config(text=str(len(self.stats['threats'])))
            
            # Update stat labels
            self.stat_labels['Packets'].config(text=f"Packets: {self.stats['total_packets']:,}")
            self.stat_labels['Bytes'].config(text=f"Bytes: {self.stats['total_bytes'] / (1024**2):.2f} MB")
            self.stat_labels['Threats'].config(text=f"Threats: {len(self.stats['threats'])}")
            self.stat_labels['Alerts'].config(text=f"Alerts: {len(self.stats['alerts'])}")
            
            # Update alerts table
            for item in self.alerts_tree.get_children():
                self.alerts_tree.delete(item)
            
            for alert in list(self.stats['threats'])[-20:]:
                self.alerts_tree.insert('', 0, values=(
                    alert['timestamp'].strftime('%H:%M:%S'),
                    alert['severity'],
                    alert['description'][:60]
                ))
            
            # Update threats text
            threats_display = "=== DETECTED THREATS ===\n\n"
            for i, threat in enumerate(list(self.stats['threats'])[-10:], 1):
                threats_display += f"{i}. [{threat['severity']}] {threat['type']}\n"
                threats_display += f"   {threat['src_ip']} → {threat['dst_ip']}\n"
                threats_display += f"   {threat['description']}\n\n"
            
            self.threats_text.config(state=tk.NORMAL)
            self.threats_text.delete(1.0, tk.END)
            self.threats_text.insert(1.0, threats_display)
            self.threats_text.config(state=tk.DISABLED)
            
            # Update protocol stats
            proto_text = "=== PROTOCOL DISTRIBUTION ===\n\n"
            for protocol, count in sorted(self.stats['protocols'].items(), key=lambda x: x[1], reverse=True)[:15]:
                pct = (count / self.stats['total_packets'] * 100) if self.stats['total_packets'] > 0 else 0
                proto_text += f"{protocol:15} : {count:10,} ({pct:6.2f}%)\n"
            
            self.protocol_text.config(state=tk.NORMAL)
            self.protocol_text.delete(1.0, tk.END)
            self.protocol_text.insert(1.0, proto_text)
            self.protocol_text.config(state=tk.DISABLED)
            
            # Update port stats
            port_text = "=== ACTIVE PORTS ===\n\n"
            for port, count in sorted(self.stats['ports'].items(), key=lambda x: x[1], reverse=True)[:20]:
                port_text += f"Port {port:5d} : {count:10,} packets\n"
            
            self.port_text.config(state=tk.NORMAL)
            self.port_text.delete(1.0, tk.END)
            self.port_text.insert(1.0, port_text)
            self.port_text.config(state=tk.DISABLED)
            
            # Update flows
            for item in self.flows_tree.get_children():
                self.flows_tree.delete(item)
            
            for flow_key, flow_data in list(self.packet_analyzer.flow_tracker.items())[:30]:
                parts = flow_key.split(' -> ')
                if len(parts) == 2:
                    self.flows_tree.insert('', 0, values=(
                        parts[0],
                        parts[1],
                        flow_data['packets'],
                        f"{flow_data['bytes'] / 1024:.2f} KB"
                    ))
            
            # Update statistics
            stats_text = f"""
=== NETWORK STATISTICS ===
Total Packets: {self.stats['total_packets']:,}
Total Bytes: {self.stats['total_bytes'] / (1024**2):.2f} MB
Threats Detected: {len(self.stats['threats'])}
Active Flows: {len(self.packet_analyzer.flow_tracker)}
Unique Protocols: {len(self.stats['protocols'])}

=== TOP THREATS ===
"""
            for threat in list(self.stats['threats'])[-5:]:
                stats_text += f"\n{threat['severity']}: {threat['type']}\n  {threat['description']}\n"
            
            self.stats_text.config(state=tk.NORMAL)
            self.stats_text.delete(1.0, tk.END)
            self.stats_text.insert(1.0, stats_text)
            self.stats_text.config(state=tk.DISABLED)
        
        except Exception as e:
            pass
        
        # Schedule next update
        self.root.after(2000, self.update_display)
    
    def export_report(self):
        """Export report"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json")],
            initialfile=f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        )
        
        if filename:
            try:
                report = {
                    'timestamp': datetime.now().isoformat(),
                    'statistics': {
                        'total_packets': self.stats['total_packets'],
                        'total_bytes': self.stats['total_bytes'],
                        'threats_detected': len(self.stats['threats']),
                    },
                    'threats': [
                        {
                            'timestamp': t['timestamp'].isoformat(),
                            'type': t['type'],
                            'severity': t['severity'],
                            'description': t['description'],
                        }
                        for t in list(self.stats['threats'])[:50]
                    ]
                }
                
                with open(filename, 'w') as f:
                    json.dump(report, f, indent=2)
                
                messagebox.showinfo("Success", f"Report saved to {filename}")
            except Exception as e:
                messagebox.showerror("Error", str(e))
    
    def clear_data(self):
        """Clear data"""
        if messagebox.askyesno("Confirm", "Clear all data?"):
            self.stats = {
                'total_packets': 0,
                'total_bytes': 0,
                'protocols': defaultdict(int),
                'ports': defaultdict(int),
                'alerts': deque(maxlen=100),
                'threats': deque(maxlen=100),
                'connections': set(),
            }

def main():
    root = tk.Tk()
    app = AdvancedNetworkMonitorGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()

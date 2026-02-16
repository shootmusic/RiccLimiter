#!/usr/bin/env python3
import sys
import os
import threading
import json
import socket
from datetime import datetime

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QPushButton, QLabel, QLineEdit, QTextEdit, QTableWidget,
    QTableWidgetItem, QTabWidget, QGroupBox, QCheckBox,
    QSpinBox, QComboBox, QMessageBox, QFileDialog, QListWidget,
    QProgressBar, QStatusBar, QHeaderView
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QFont, QPalette, QColor

from core.network_scanner import NetworkScanner
from core.arp_spoofer import ARPSpoofer
from core.dns_spoofer import DNSSpoofer
from core.session_hijacker import SessionHijacker
from core.ai_analytics import MrXAnalytics

# ==================== DARK THEME (WITH GRID) ====================
DARK_STYLE = """
QMainWindow {
    background-color: #0d1117;
    color: #e6edf3;
    font-family: 'Segoe UI', 'Arial', sans-serif;
}
QGroupBox {
    color: #58a6ff;
    border: 1px solid #30363d;
    border-radius: 6px;
    margin-top: 12px;
    font-weight: 500;
    font-size: 13px;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 12px;
    padding: 0 6px 0 6px;
    color: #58a6ff;
    background-color: #0d1117;
}
QPushButton {
    background-color: #21262d;
    color: #e6edf3;
    border: 1px solid #30363d;
    padding: 8px 16px;
    border-radius: 6px;
    font-weight: 500;
    min-width: 80px;
}
QPushButton:hover {
    background-color: #30363d;
    border: 1px solid #58a6ff;
    color: #58a6ff;
}
QPushButton:pressed {
    background-color: #3d444d;
    border: 1px solid #58a6ff;
    color: #ffffff;
}
QPushButton#attack_btn {
    background-color: #bd2c00;
    border: none;
    color: #ffffff;
    font-weight: bold;
}
QPushButton#attack_btn:hover {
    background-color: #da3a0b;
}
QPushButton#attack_btn:pressed {
    background-color: #9e2400;
}
QPushButton#stop_btn {
    background-color: #238636;
    border: none;
    color: #ffffff;
    font-weight: bold;
}
QPushButton#stop_btn:hover {
    background-color: #2ea043;
}
QPushButton#stop_btn:pressed {
    background-color: #1a6129;
}
QTableWidget {
    background-color: #0d1117;
    color: #e6edf3;
    gridline-color: #30363d;
    border: 1px solid #30363d;
    border-radius: 6px;
    alternate-background-color: #161b22;
    selection-background-color: #1f6feb;
    selection-color: #ffffff;
    outline: none;
}
QTableWidget::item {
    padding: 8px;
    border-bottom: 1px solid #30363d;
    border-right: 1px solid #30363d;
    text-align: center;
}
QTableWidget::item:selected {
    background-color: #1f6feb;
    color: #ffffff;
    border: none;
}
QTableWidget::item:hover {
    background-color: #2d333b;
}
QTableWidget:focus {
    outline: none;
}
QTableWidget::item:focus {
    outline: none;
    border: none;
}
QHeaderView::section {
    background-color: #161b22;
    color: #58a6ff;
    padding: 8px;
    border: 1px solid #30363d;
    font-weight: 600;
    text-align: center;
}
QHeaderView::section:horizontal {
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
}
QTextEdit {
    background-color: #0d1117;
    color: #e6edf3;
    border: 1px solid #30363d;
    border-radius: 6px;
    font-family: 'Consolas', 'Monospace', monospace;
}
QLineEdit {
    background-color: #0d1117;
    color: #e6edf3;
    border: 1px solid #30363d;
    padding: 8px;
    border-radius: 6px;
}
QLineEdit:focus {
    border: 1px solid #58a6ff;
}
QComboBox {
    background-color: #0d1117;
    color: #e6edf3;
    border: 1px solid #30363d;
    padding: 8px;
    border-radius: 6px;
}
QComboBox::drop-down {
    border: none;
}
QComboBox QAbstractItemView {
    background-color: #0d1117;
    color: #e6edf3;
    border: 1px solid #30363d;
    selection-background-color: #1f6feb;
}
QSpinBox {
    background-color: #0d1117;
    color: #e6edf3;
    border: 1px solid #30363d;
    padding: 6px;
    border-radius: 6px;
}
QCheckBox {
    color: #e6edf3;
    spacing: 8px;
}
QCheckBox::indicator {
    width: 18px;
    height: 18px;
    background-color: #0d1117;
    border: 1px solid #30363d;
    border-radius: 4px;
}
QCheckBox::indicator:checked {
    background-color: #1f6feb;
    border: 1px solid #1f6feb;
}
QCheckBox::indicator:hover {
    border: 1px solid #58a6ff;
}
QTabWidget::pane {
    background-color: #0d1117;
    border: 1px solid #30363d;
    border-radius: 6px;
}
QTabBar::tab {
    background-color: #161b22;
    color: #8b949e;
    padding: 8px 16px;
    margin-right: 2px;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    font-weight: 500;
}
QTabBar::tab:selected {
    background-color: #0d1117;
    color: #58a6ff;
    border-bottom: 2px solid #1f6feb;
}
QTabBar::tab:hover {
    color: #e6edf3;
}
QStatusBar {
    background-color: #161b22;
    color: #8b949e;
}
QLabel {
    color: #e6edf3;
}
QMessageBox {
    background-color: #0d1117;
    color: #e6edf3;
}
QMessageBox QPushButton {
    min-width: 80px;
    min-height: 30px;
}
"""

class ScanThread(QThread):
    finished = pyqtSignal(list)
    log = pyqtSignal(str)
    
    def __init__(self, scanner):
        super().__init__()
        self.scanner = scanner
        
    def run(self):
        self.log.emit("[*] Scanning network...")
        devices = self.scanner.scan()
        self.finished.emit(devices)

class AttackThread(QThread):
    log = pyqtSignal(str)
    
    def __init__(self, arp, dns, session, victims, attacks):
        super().__init__()
        self.arp = arp
        self.dns = dns
        self.session = session
        self.victims = victims
        self.attacks = attacks
        
    def run(self):
        if 'arp' in self.attacks:
            self.log.emit("[+] ARP spoofing started")
            self.arp.start_spoofing(self.victims)
        if 'dns' in self.attacks:
            self.log.emit("[+] DNS spoofing started")
            self.dns.start()
        if 'session' in self.attacks:
            self.log.emit("[+] Session hijacking started")
            self.session.start()

class RiccLimiterGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.interface = None
        self.arp_spoofer = None
        self.dns_spoofer = None
        self.session_hijacker = None
        self.scanner = None
        self.devices = []
        self.attack_running = False
        self.ai = MrXAnalytics()
        
        self.init_ui()
        self.load_interfaces()
        
    def init_ui(self):
        self.setWindowTitle("RiccLimiter v5.0")
        self.setGeometry(100, 100, 1300, 850)
        self.setStyleSheet(DARK_STYLE)
        
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setSpacing(12)
        main_layout.setContentsMargins(15, 15, 15, 15)
        
        # Header
        header = QLabel("RiccLimiter")
        header.setAlignment(Qt.AlignCenter)
        header.setStyleSheet("""
            font-size: 28px;
            font-weight: bold;
            color: #58a6ff;
            padding: 15px;
            background-color: #161b22;
            border-radius: 8px;
            letter-spacing: 1px;
        """)
        main_layout.addWidget(header)
        
        self.status = QStatusBar()
        self.setStatusBar(self.status)
        self.status.showMessage("Ready")
        
        tabs = QTabWidget()
        tabs.setDocumentMode(True)
        main_layout.addWidget(tabs)
        
        # Network Tab
        net_tab = QWidget()
        net_layout = QVBoxLayout(net_tab)
        net_layout.setSpacing(15)
        
        # Interface Group
        iface_group = QGroupBox("Interface")
        iface_layout = QHBoxLayout()
        iface_layout.addWidget(QLabel("Select:"))
        self.interface_combo = QComboBox()
        self.interface_combo.setMinimumWidth(250)
        iface_layout.addWidget(self.interface_combo)
        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self.load_interfaces)
        iface_layout.addWidget(self.refresh_btn)
        iface_layout.addStretch()
        iface_group.setLayout(iface_layout)
        net_layout.addWidget(iface_group)
        
        # Scan Group
        scan_group = QGroupBox("Scan")
        scan_layout = QHBoxLayout()
        self.scan_btn = QPushButton("Start Scan")
        self.scan_btn.setMinimumHeight(40)
        self.scan_btn.setMinimumWidth(200)
        self.scan_btn.clicked.connect(self.start_scan)
        scan_layout.addWidget(self.scan_btn)
        scan_layout.addStretch()
        scan_group.setLayout(scan_layout)
        net_layout.addWidget(scan_group)
        
        # Targets Table
        table_group = QGroupBox("Targets")
        table_layout = QVBoxLayout(table_group)
        table_layout.setSpacing(8)
        table_layout.setContentsMargins(10, 15, 10, 10)
        
        self.device_table = QTableWidget()
        self.device_table.setColumnCount(5)
        self.device_table.setHorizontalHeaderLabels(["Select", "IP Address", "MAC Address", "Hostname", "Analysis"])
        self.device_table.setShowGrid(True)
        self.device_table.setGridStyle(Qt.SolidLine)
        self.device_table.verticalHeader().setVisible(False)
        self.device_table.setAlternatingRowColors(True)
        self.device_table.horizontalHeader().setStretchLastSection(True)
        self.device_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.device_table.setSelectionBehavior(QTableWidget.SelectRows)
        
        # Set alignment untuk header
        for col in range(1, 5):
            item = self.device_table.horizontalHeaderItem(col)
            if item:
                item.setTextAlignment(Qt.AlignCenter)
        
        table_layout.addWidget(self.device_table)
        
        # Table Controls
        ctrl_widget = QWidget()
        ctrl_layout = QHBoxLayout(ctrl_widget)
        ctrl_layout.setContentsMargins(0, 5, 0, 0)
        ctrl_layout.setSpacing(10)
        
        self.select_all_btn = QPushButton("Select All")
        self.select_all_btn.setFixedWidth(100)
        self.select_all_btn.clicked.connect(self.select_all)
        ctrl_layout.addWidget(self.select_all_btn)
        
        self.clear_btn = QPushButton("Clear")
        self.clear_btn.setFixedWidth(80)
        self.clear_btn.clicked.connect(self.clear_selection)
        ctrl_layout.addWidget(self.clear_btn)
        
        ctrl_layout.addStretch()
        table_layout.addWidget(ctrl_widget)
        
        net_layout.addWidget(table_group)
        tabs.addTab(net_tab, "Network")
        
        # Attack Tab
        attack_tab = QWidget()
        attack_layout = QVBoxLayout(attack_tab)
        attack_layout.setSpacing(15)
        
        type_group = QGroupBox("Attack Methods")
        type_layout = QVBoxLayout()
        self.arp_check = QCheckBox("ARP Spoofing - Connection Interruption")
        self.arp_check.setChecked(True)
        type_layout.addWidget(self.arp_check)
        self.dns_check = QCheckBox("DNS Spoofing - Traffic Redirection")
        type_layout.addWidget(self.dns_check)
        self.session_check = QCheckBox("Session Hijacking - Data Capture")
        type_layout.addWidget(self.session_check)
        type_group.setLayout(type_layout)
        attack_layout.addWidget(type_group)
        
        ctrl_layout = QHBoxLayout()
        self.start_btn = QPushButton("Execute Attack")
        self.start_btn.setObjectName("attack_btn")
        self.start_btn.setMinimumHeight(45)
        self.start_btn.clicked.connect(self.start_attack)
        ctrl_layout.addWidget(self.start_btn)
        
        self.stop_btn = QPushButton("Stop")
        self.stop_btn.setObjectName("stop_btn")
        self.stop_btn.setMinimumHeight(45)
        self.stop_btn.clicked.connect(self.stop_attack)
        self.stop_btn.setEnabled(False)
        ctrl_layout.addWidget(self.stop_btn)
        attack_layout.addLayout(ctrl_layout)
        
        self.attack_status = QLabel("● Inactive")
        self.attack_status.setStyleSheet("color: #9da5b4; font-weight: 500;")
        attack_layout.addWidget(self.attack_status)
        attack_layout.addStretch()
        tabs.addTab(attack_tab, "Attack")
        
        # DNS Tab
        dns_tab = QWidget()
        dns_layout = QVBoxLayout(dns_tab)
        
        dns_group = QGroupBox("DNS Rules")
        dns_form = QVBoxLayout()
        
        add_layout = QHBoxLayout()
        add_layout.addWidget(QLabel("Domain:"))
        self.dns_domain = QLineEdit()
        self.dns_domain.setPlaceholderText("example.com")
        add_layout.addWidget(self.dns_domain)
        add_layout.addWidget(QLabel("→"))
        self.dns_redirect = QLineEdit()
        self.dns_redirect.setPlaceholderText("127.0.0.1")
        add_layout.addWidget(self.dns_redirect)
        self.add_dns_btn = QPushButton("Add")
        self.add_dns_btn.clicked.connect(self.add_dns)
        add_layout.addWidget(self.add_dns_btn)
        dns_form.addLayout(add_layout)
        
        self.dns_list = QTextEdit()
        self.dns_list.setReadOnly(True)
        self.dns_list.setMaximumHeight(150)
        dns_form.addWidget(self.dns_list)
        
        dns_group.setLayout(dns_form)
        dns_layout.addWidget(dns_group)
        dns_layout.addStretch()
        tabs.addTab(dns_tab, "DNS")
        
        # AI Tab
        ai_tab = QWidget()
        ai_layout = QVBoxLayout(ai_tab)
        
        ai_group = QGroupBox("AI Analytics")
        ai_form = QVBoxLayout()
        
        self.analyze_btn = QPushButton("Analyze Network")
        self.analyze_btn.clicked.connect(self.analyze_devices)
        ai_form.addWidget(self.analyze_btn)
        
        self.ai_report = QTextEdit()
        self.ai_report.setReadOnly(True)
        self.ai_report.setFont(QFont("Consolas", 9))
        ai_form.addWidget(self.ai_report)
        
        ai_group.setLayout(ai_form)
        ai_layout.addWidget(ai_group)
        ai_layout.addStretch()
        tabs.addTab(ai_tab, "Analysis")
        
        # Console
        console_group = QGroupBox("Console")
        console_layout = QVBoxLayout()
        self.log_console = QTextEdit()
        self.log_console.setReadOnly(True)
        self.log_console.setMaximumHeight(150)
        self.log_console.setFont(QFont("Consolas", 9))
        console_layout.addWidget(self.log_console)
        console_group.setLayout(console_layout)
        main_layout.addWidget(console_group)
        
    def load_interfaces(self):
        self.interface_combo.clear()
        try:
            import netifaces as ni
            for iface in ni.interfaces():
                try:
                    addrs = ni.ifaddresses(iface)
                    if ni.AF_INET in addrs:
                        self.interface_combo.addItem(f"{iface}", iface)
                except:
                    pass
        except:
            pass
            
    def start_scan(self):
        if not self.interface_combo.currentData():
            QMessageBox.warning(self, "Error", "Select interface first!")
            return
        self.interface = self.interface_combo.currentData()
        scanner = NetworkScanner(self.interface)
        self.scan_thread = ScanThread(scanner)
        self.scan_thread.finished.connect(self.on_scan)
        self.scan_thread.log.connect(self.log)
        self.scan_thread.start()
        self.scan_btn.setEnabled(False)
        self.scan_btn.setText("Scanning...")
        
    def on_scan(self, devices):
        self.devices = devices
        self.scan_btn.setEnabled(True)
        self.scan_btn.setText("Start Scan")
        
        self.device_table.setRowCount(len(devices))
        for i, d in enumerate(devices):
            cb = QTableWidgetItem()
            cb.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled)
            cb.setCheckState(Qt.Unchecked)
            cb.setTextAlignment(Qt.AlignCenter)
            self.device_table.setItem(i, 0, cb)
            
            ip_item = QTableWidgetItem(d['ip'])
            ip_item.setTextAlignment(Qt.AlignCenter)
            self.device_table.setItem(i, 1, ip_item)
            
            mac_item = QTableWidgetItem(d['mac'])
            mac_item.setTextAlignment(Qt.AlignCenter)
            self.device_table.setItem(i, 2, mac_item)
            
            host_item = QTableWidgetItem(d['hostname'])
            host_item.setTextAlignment(Qt.AlignCenter)
            self.device_table.setItem(i, 3, host_item)
            
            info = self.ai.analyze_mac(d['mac'])
            analysis_item = QTableWidgetItem(info['vendor'])
            analysis_item.setTextAlignment(Qt.AlignCenter)
            self.device_table.setItem(i, 4, analysis_item)
            
        self.log(f"[+] Found {len(devices)} devices")
        
    def analyze_devices(self):
        if not self.devices:
            QMessageBox.warning(self, "Error", "Scan first!")
            return
            
        self.log("[*] Analyzing devices...")
        report = self.ai.generate_report(self.devices)
        
        text = "="*60 + "\n"
        text += "AI ANALYSIS REPORT\n"
        text += "="*60 + "\n\n"
        text += f"Total Devices: {report['summary']['total']}\n"
        text += f"Cameras Detected: {report['summary']['cameras']}\n\n"
        
        if report.get('warnings'):
            text += "Warnings:\n"
            for w in report['warnings']:
                text += f"  - {w}\n"
            text += "\n"
            
        text += "Device Details:\n"
        for d in report['devices']:
            text += f"  {d['ip']} - {d['vendor']}\n"
            
        self.ai_report.setText(text)
        self.log("[+] Analysis complete")
        
    def select_all(self):
        for i in range(self.device_table.rowCount()):
            self.device_table.item(i, 0).setCheckState(Qt.Checked)
            
    def clear_selection(self):
        for i in range(self.device_table.rowCount()):
            self.device_table.item(i, 0).setCheckState(Qt.Unchecked)
            
    def get_selected(self):
        victims = []
        for i in range(self.device_table.rowCount()):
            if self.device_table.item(i, 0).checkState() == Qt.Checked:
                victims.append({
                    'ip': self.device_table.item(i, 1).text(),
                    'mac': self.device_table.item(i, 2).text(),
                    'hostname': self.device_table.item(i, 3).text()
                })
        return victims
        
    def start_attack(self):
        victims = self.get_selected()
        if not victims:
            QMessageBox.warning(self, "Error", "Select targets first!")
            return
            
        self.arp_spoofer = ARPSpoofer(self.interface)
        self.arp_spoofer.get_network_info()
        self.dns_spoofer = DNSSpoofer(self.interface)
        self.session_hijacker = SessionHijacker(self.interface)
        
        attacks = []
        if self.arp_check.isChecked():
            attacks.append('arp')
        if self.dns_check.isChecked():
            attacks.append('dns')
        if self.session_check.isChecked():
            attacks.append('session')
            
        self.attack_thread = AttackThread(
            self.arp_spoofer, self.dns_spoofer,
            self.session_hijacker, victims, attacks
        )
        self.attack_thread.log.connect(self.log)
        self.attack_thread.start()
        
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.attack_status.setText("● Active")
        self.attack_status.setStyleSheet("color: #bd2c00; font-weight: bold;")
        self.log(f"[!] Attacking {len(victims)} targets")
        
    def stop_attack(self):
        if self.arp_spoofer:
            self.arp_spoofer.stop_spoofing()
        if self.dns_spoofer:
            self.dns_spoofer.stop()
        if self.session_hijacker:
            self.session_hijacker.stop()
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.attack_status.setText("● Inactive")
        self.attack_status.setStyleSheet("color: #9da5b4; font-weight: 500;")
        self.log("[+] Attack stopped")
        
    def add_dns(self):
        domain = self.dns_domain.text().strip()
        ip = self.dns_redirect.text().strip()
        if domain and ip:
            current = self.dns_list.toPlainText()
            if current:
                current += f"\n{domain} → {ip}"
            else:
                current = f"{domain} → {ip}"
            self.dns_list.setText(current)
            self.log(f"[+] DNS: {domain} → {ip}")
            self.dns_domain.clear()
            self.dns_redirect.clear()
        
    def log(self, msg):
        ts = datetime.now().strftime("%H:%M:%S")
        self.log_console.append(f"[{ts}] {msg}")

def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    
    font = QFont("Segoe UI", 9)
    app.setFont(font)
    
    window = RiccLimiterGUI()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()

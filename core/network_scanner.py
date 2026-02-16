#!/usr/bin/env python3
"""
Network Scanner untuk RiccLimiter
Dioptimalkan untuk jaringan rumahan (5-50 device)
"""

from scapy.all import ARP, Ether, srp, conf
import socket
import netifaces as ni

class NetworkScanner:
    def __init__(self, interface):
        self.interface = interface
        conf.iface = interface
        conf.verb = 0
        
    def get_network_range(self):
        """
        Deteksi jaringan - PAKSA /24 untuk kecepatan maksimal
        Cocok untuk wifi rumahan
        """
        try:
            # Ambil IP dari interface
            addrs = ni.ifaddresses(self.interface)
            ip = addrs[ni.AF_INET][0]['addr']
            
            # Paksa pake /24 (256 IP) - cukup untuk rumah
            ip_parts = ip.split('.')
            network = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
            
            print(f"[*] Network: {network} ( /24 mode for speed )")
            return network
            
        except Exception as e:
            print(f"[!] Error: {e}, using fallback")
            return "192.168.1.0/24"
    
    def get_own_ip(self):
        """IP sendiri"""
        try:
            addrs = ni.ifaddresses(self.interface)
            return addrs[ni.AF_INET][0]['addr']
        except:
            return "0.0.0.0"
    
    def get_hostname(self, ip):
        """Hostname dari IP"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return "Unknown"
        
    def scan(self):
        """
        Scan cepat untuk jaringan rumahan
        Timeout 2 detik, 1x retry -> selesai < 5 detik
        """
        devices = []
        try:
            # Dapatkan range (pasti /24)
            network = self.get_network_range()
            print(f"[*] Scanning {network}...")
            
            # Buat ARP request
            arp = ARP(pdst=network)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp
            
            # KONFIGURASI CEPET UNTUK RUMAH
            result = srp(packet, 
                        timeout=2,        # Tunggu 2 detik
                        retry=1,          # 1x ulang
                        verbose=0, 
                        inter=0.02)[0]    # Jeda 20ms
            
            own_ip = self.get_own_ip()
            
            # Proses hasil
            for sent, received in result:
                if received.psrc != own_ip:
                    device = {
                        'ip': received.psrc,
                        'mac': received.hwsrc.upper(),
                        'hostname': self.get_hostname(received.psrc)
                    }
                    devices.append(device)
                    print(f"[+] {received.psrc} - {received.hwsrc[:8]}...")
            
            print(f"[+] Found {len(devices)} devices in {network}")
                    
        except Exception as e:
            print(f"[!] Scan error: {e}")
            
        return devices


# Testing
if __name__ == "__main__":
    import sys
    iface = sys.argv[1] if len(sys.argv) > 1 else "wlan0"
    scanner = NetworkScanner(iface)
    devices = scanner.scan()
    for d in devices:
        print(f"{d['ip']}\t{d['mac']}\t{d['hostname']}")

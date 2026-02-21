# ⚡ RICC LIMITER ⚡

Advanced Network Analysis & Attack Suite  
Created by RICC

---

## ⚠️ DISCLAIMER PENTING

**Tools ini dibuat untuk tujuan edukasi dan pengujian keamanan pada jaringan sendiri.**

Penulis **tidak bertanggung jawab** atas:
- Penyalahgunaan tools untuk aktivitas ilegal
- Kerusakan atau kerugian yang ditimbulkan
- Pelanggaran hukum yang dilakukan pengguna

Pengguna bertanggung jawab penuh atas kepatuhan terhadap hukum yang berlaku di wilayahnya.

**Gunakan dengan bijak dan etis!** 🔒

---

## FITUR UTAMA
| Fitur | Deskripsi |
|-------|-----------|
| Network Scanner | Auto-detect semua device di jaringan |
| ARP Spoofing | Putus koneksi target, MITM attack |
| DNS Spoofing | Redirect website ke IP manapun |
| Session Hijacking | Capture cookie & data HTTP |
| AI Analytics | Deteksi vendor, kamera, skor keamanan |

---

## INSTALLASI

### Linux (Kali/Ubuntu/Debian)
```bash
git clone https://github.com/shootmusic/RiccLimiter.git
cd RiccLimiter
pip install -r requirements.txt
sudo python3 ricclimiter_gui.py
```

Windows (Auto Install)

```batch
git clone https://github.com/shootmusic/RiccLimiter.git
cd RiccLimiter
setup.bat
```

Windows (Manual)

1. Download ZIP dari https://github.com/shootmusic/RiccLimiter
2. Extract ke folder
3. Buka CMD sebagai Administrator
4. cd ke folder
5. pip install -r requirements.txt
6. python ricclimiter_gui.py

---

Fedora (RPM-based)

```bash
# Install dependencies via DNF
sudo dnf install python3-pyqt5 python3-scapy python3-netifaces git

# Clone repository
git clone https://github.com/shootmusic/RiccLimiter.git
cd RiccLimiter

# Jalankan
python3 ricclimiter_gui.py
```

Catatan Penting untuk Fedora/RHEL/CentOS:
Tools ini dikembangkan di Kali Linux (Debian based), tapi sudah diuji dan berjalan lancar di Fedora.
Jika遇到 error, pastikan:

· Semua dependencies terinstall via dnf (sesuai instruksi di atas)
· Gunakan python3 bukan python
· Jalankan sebagai user biasa (tidak perlu sudo untuk GUI, kecuali untuk raw socket)

Troubleshooting Fedora

Jika muncul error No module named 'PyQt5':

```bash
# Install ulang via dnf
sudo dnf reinstall python3-pyqt5
```

Jika error externally-managed-environment:

```bash
# Pakai virtual environment
python3 -m venv ricc-env
source ricc-env/bin/activate
pip install -r requirements.txt
python3 ricclimiter_gui.py
```

---

PERSYARATAN

Linux

· Python 3.8+
· pip
· scapy, netifaces, PyQt5

Windows

· Python 3.8+ (tambahkan ke PATH) - https://python.org
· Npcap (https://npcap.com) - pilih "Install in WinPcap API-compatible Mode"
· Git (opsional) - https://git-scm.com

---

CARA PENGGUNAAN

1. Pilih interface (wlan0/eth0 di Linux, WiFi adapter di Windows)
2. Klik START SCAN - otomatis deteksi jaringan
3. Centang target yang akan diserang
4. Pilih metode serangan di tab Attack
5. Klik EXECUTE

DNS Spoofing

· Buka tab DNS
· Tambah rule: domain.com → IP tujuan
· Centang DNS Spoofing saat attack

AI Analytics

· Klik ANALYZE NETWORK di tab Analysis
· Lihat laporan lengkap device + deteksi kamera

---

DISCLAIMER

Untuk edukasi dan pengujian jaringan sendiri!
Penulis tidak bertanggung jawab atas penyalahgunaan tools ini.

---

CREDITS

· Developer: RICC
· UI Theme: GitHub Dark
· Powered by: PyQt5, Scapy, Netifaces

---

KONTAK

· GitHub: @shootmusic
· Report bug: Issues

---

⭐ Jangan lupa kasih star ya ⭐

# 🛡️ WiFi Security Auditor

> **⚠️ Support / Errors?**
> If you encounter any issues, bugs, or compilation errors, please contact:
> **📧 contact@morariuandreiraul.com**
> I'll do my best to help you as quickly as possible.

<div align="center">
  <img src="https://media1.tenor.com/m/XKNjuLjL7W8AAAAd/naruto-thumbs-up.gif" alt="Naruto thumbs up" width="200"/>
</div>

---

**Instrument educațional pentru auditarea securității rețelelor WiFi proprii**

> ⚠️ **AVERTISMENT LEGAL**: Acest instrument este destinat exclusiv testării rețelelor WiFi pe care le dețineți sau aveți permisiunea explicită de testare. Utilizarea pe rețele fără autorizare este ilegală.

---

## 📋 Funcționalități

| Modul | Descriere |
|-------|-----------|
| 📡 **Scanner** | Scanează rețelele WiFi din jur: SSID, BSSID, canal, semnal, tip securitate |
| 🔍 **Analyzer** | Evaluează nivelul de securitate și atribuie scoruri (OPEN → WPA3) |
| 🔒 **Checker** | Verifică vulnerabilități locale: WPS, DNS, porturi deschise, dispozitive în rețea |
| 📊 **Reporter** | Generează rapoarte în terminal, HTML și JSON |

---

## 🚀 Instalare (Kali Linux / WSL Kali)

```bash
# Clonează repository-ul
git clone https://github.com/morariuraulandrei-commits/wifi-security-auditor.git
cd wifi-security-auditor

# Rulează scriptul de instalare
chmod +x install.sh
sudo ./install.sh
```

### Instalare manuală
```bash
sudo apt-get update
sudo apt-get install -y wireless-tools iw network-manager net-tools nmap
chmod +x wifi_auditor.py
```

---

## 🖥️ Utilizare

```bash
sudo python3 wifi_auditor.py
sudo python3 wifi_auditor.py --quick
sudo python3 wifi_auditor.py --report
sudo python3 wifi_auditor.py --json
sudo python3 wifi_auditor.py --iface wlan0
sudo python3 wifi_auditor.py --help
```

---

## 📊 Scala de Securitate

| Nivel | Protocol | Scor |
|-------|----------|------|
| 🔴 CRITICAL | OPEN | 0/5 |
| 🟠 HIGH | WEP | 1/5 |
| 🟡 MEDIUM | WPA | 2/5 |
| 🟢 GOOD | WPA2 | 3/5 |
| 🔵 VERY GOOD | WPA2/WPA3 | 4/5 |
| 🟣 EXCELLENT | WPA3 | 5/5 |

---

## 🛠️ Structura

```
wifi-security-auditor/
├── wifi_auditor.py
├── install.sh
├── requirements.txt
├── README.md
└── modules/
    ├── scanner.py
    ├── analyzer.py
    ├── checker.py
    └── reporter.py
```

---

MIT License - utilizare educatională pe rețele proprii.

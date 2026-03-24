"""
Vulnerability Checker Module
Checks the local network/router for common misconfigurations and vulnerabilities.
"""

import subprocess, re, socket, os


def _run(cmd, timeout=10):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip()
    except Exception as e:
        return "", str(e)


def check_default_gateway():
    out, _ = _run("ip route show default 2>/dev/null")
    m = re.search(r"default via ([d.]+)", out)
    if m:
        return m.group(1)
    out, _ = _run("route -n 2>/dev/null")
    for line in out.splitlines():
        if line.startswith("0.0.0.0"):
            parts = line.split()
            if len(parts) >= 2:
                return parts[1]
    return None


def check_router_admin_panel(gateway_ip):
    if not gateway_ip:
        return []
    findings = []
    open_ports = []
    for port in [80, 443, 8080, 8443]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            if s.connect_ex((gateway_ip, port)) == 0:
                open_ports.append(port)
            s.close()
        except Exception:
            pass
    if open_ports:
        findings.append({
            "check": "ROUTER_ADMIN_PANEL", "status": "INFO",
            "title": f"Panou administrare router detectat",
            "detail": f"Panoul ({gateway_ip}) este accesibil pe porturile: {open_ports}.",
            "recommendation": "Asigura-te ca parola de admin NU este cea implicita."
        })
    return findings


def check_dns_leak():
    findings = []
    out, _ = _run("cat /etc/resolv.conf 2>/dev/null")
    dns_servers = re.findall(r"nameservers+([d.]+)", out)
    public_dns = {"8.8.8.8":"Google DNS","8.8.4.4":"Google DNS","1.1.1.1":"Cloudflare DNS",
                  "1.0.0.1":"Cloudflare DNS","9.9.9.9":"Quad9 DNS"}
    for dns in dns_servers:
        if dns in public_dns:
            findings.append({"check":"PUBLIC_DNS","status":"INFO",
                "title":f"DNS public: {public_dns[dns]} ({dns})",
                "detail":"Interogatiile DNS sunt vizibile pentru furnizor.",
                "recommendation":"Considera DNS over HTTPS (DoH) pentru mai multa intimitate."})
        else:
            findings.append({"check":"PRIVATE_DNS","status":"GOOD",
                "title":f"DNS privat/ISP: {dns}",
                "detail":"Folosesti serverul DNS al routerului sau ISP-ului.",
                "recommendation":"Verifica ca routerul nu redirectioneaza DNS fara stirea ta."})
    return findings


def check_ipv6():
    findings = []
    out, _ = _run("ip -6 addr 2>/dev/null")
    if out and "inet6" in out:
        if any("global" in l.lower() for l in out.splitlines()):
            findings.append({"check":"IPV6_ENABLED","status":"INFO",
                "title":"IPv6 activat cu adresa globala",
                "detail":"Interfetele au adrese IPv6 globale.",
                "recommendation":"Verifica ca routerul are firewall IPv6 activat."})
    return findings


def check_open_ports_local():
    findings = []
    out, _ = _run("ss -tuln 2>/dev/null || netstat -tuln 2>/dev/null")
    risky_ports = {22:("SSH","MEDIUM"),23:("Telnet","CRITICAL"),21:("FTP","HIGH"),
                   3389:("RDP","HIGH"),5900:("VNC","HIGH"),3306:("MySQL","HIGH"),
                   5432:("PostgreSQL","HIGH"),27017:("MongoDB","HIGH"),6379:("Redis","HIGH"),
                   445:("SMB","HIGH"),139:("NetBIOS","MEDIUM")}
    listening = set()
    for line in out.splitlines():
        m = re.search(r"[:s]([d.]*):(d+)s", line)
        if m:
            try:
                listening.add(int(m.group(2)))
            except ValueError:
                pass
    for port in listening:
        if port in risky_ports:
            svc, severity = risky_ports[port]
            if severity in ("CRITICAL","HIGH"):
                findings.append({"check":f"OPEN_PORT_{port}","status":severity,
                    "title":f"Port {port} deschis ({svc})",
                    "detail":f"Serviciul {svc} asculta pe portul {port}.",
                    "recommendation":f"Daca nu folosesti {svc}, opreste serviciul."})
    return findings


def check_network_neighbors():
    devices = []
    out, _ = _run("arp -n 2>/dev/null || ip neigh 2>/dev/null")
    for line in out.splitlines():
        m = re.search(r"([d.]+)s+.*?([0-9a-fA-F:]{17})", line)
        if m:
            ip, mac = m.group(1), m.group(2).upper()
            if not ip.endswith(".255") and ip != "0.0.0.0":
                devices.append({"ip": ip, "mac": mac})
    return devices


def check_wps_vulnerability(networks):
    return [n for n in networks if n.get("wps")]


def run_all_checks(networks=None):
    results = {"gateway":None,"admin_panel":[],"dns":[],"ipv6":[],"open_ports":[],"neighbors":[],"wps_networks":[]}
    gateway = check_default_gateway()
    results["gateway"] = gateway
    if gateway:
        results["admin_panel"] = check_router_admin_panel(gateway)
    results["dns"] = check_dns_leak()
    results["ipv6"] = check_ipv6()
    results["open_ports"] = check_open_ports_local()
    results["neighbors"] = check_network_neighbors()
    if networks:
        results["wps_networks"] = check_wps_vulnerability(networks)
    return results

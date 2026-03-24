"""
WiFi Network Scanner Module
Scans for nearby wireless networks using available system tools.
"""

import subprocess, re, os


def _run_cmd(cmd, timeout=15):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip()
    except subprocess.TimeoutExpired:
        return "", "Command timed out"
    except Exception as e:
        return "", str(e)


def get_interfaces():
    interfaces = []
    out, _ = _run_cmd("iw dev 2>/dev/null")
    if out:
        for line in out.splitlines():
            m = re.search(r"Interfaces+(S+)", line)
            if m:
                interfaces.append(m.group(1))
    if not interfaces:
        out, _ = _run_cmd("iwconfig 2>/dev/null")
        for line in out.splitlines():
            if "IEEE 802.11" in line or "ESSID" in line:
                iface = line.split()[0]
                if iface and iface != "lo":
                    interfaces.append(iface)
    if not interfaces:
        out, _ = _run_cmd("ip link show 2>/dev/null")
        for line in out.splitlines():
            m = re.search(r"^d+:s+(wlS+):", line)
            if m:
                interfaces.append(m.group(1))
    return list(set(interfaces))


def _dbm_to_quality(dbm):
    if dbm <= -100: return 0
    if dbm >= -50: return 100
    return 2 * (dbm + 100)


def _quality_to_dbm(quality):
    return (quality // 2) - 100


def _parse_iwlist(output):
    networks = []
    current = {}
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("Cell"):
            if current:
                networks.append(current)
            current = {}
            m = re.search(r"Address:s+([0-9A-Fa-f:]{17})", line)
            if m:
                current["bssid"] = m.group(1).upper()
        elif "ESSID:" in line:
            m = re.search(r'ESSID:"(.*)"', line)
            current["ssid"] = m.group(1) if m else "<hidden>"
        elif "Frequency:" in line:
            m = re.search(r"Frequency:([d.]+)", line)
            if m:
                freq = float(m.group(1))
                current["frequency"] = freq
                current["band"] = "5 GHz" if freq > 3 else "2.4 GHz"
            mc = re.search(r"Channel:(d+)", line)
            if mc:
                current["channel"] = int(mc.group(1))
        elif "Signal level=" in line:
            m = re.search(r"Signal level=(-?d+)s*dBm", line)
            if m:
                dbm = int(m.group(1))
                current["signal_dbm"] = dbm
                current["signal_quality"] = _dbm_to_quality(dbm)
        elif "Encryption key:" in line:
            current["encryption_enabled"] = "on" in line.lower()
        elif "IE: IEEE 802.11i/WPA2" in line or "WPA2" in line:
            current.setdefault("security", set()).add("WPA2")
        elif "IE: WPA Version 1" in line:
            current.setdefault("security", set()).add("WPA")
        elif "WPA3" in line or "SAE" in line:
            current.setdefault("security", set()).add("WPA3")
        elif "WPS" in line:
            current["wps"] = True
    if current:
        networks.append(current)
    for n in networks:
        sec = n.get("security", set())
        enc = n.get("encryption_enabled", False)
        if not sec and not enc:
            n["security_label"] = "OPEN"
        elif not sec and enc:
            n["security_label"] = "WEP"
        elif "WPA3" in sec and "WPA2" in sec:
            n["security_label"] = "WPA2/WPA3"
        elif "WPA3" in sec:
            n["security_label"] = "WPA3"
        elif "WPA2" in sec:
            n["security_label"] = "WPA2"
        elif "WPA" in sec:
            n["security_label"] = "WPA"
        else:
            n["security_label"] = "WEP" if enc else "OPEN"
        n.pop("security", None)
        n.pop("encryption_enabled", None)
    return networks


def _parse_nmcli(output):
    networks = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("IN-USE"):
            continue
        parts = re.split(r"s{2,}", line)
        if len(parts) >= 6:
            try:
                ch = int(parts[3]) if parts[3].isdigit() else 0
                sig = int(parts[5]) if parts[5].isdigit() else 0
                net = {
                    "ssid": parts[0].replace("*","").strip() or "<hidden>",
                    "bssid": parts[1].upper() if len(parts[1])==17 else "??:??:??:??:??:??",
                    "channel": ch, "signal_quality": sig,
                    "signal_dbm": _quality_to_dbm(sig),
                    "security_label": _nmcli_security(parts[7] if len(parts)>7 else ""),
                    "band": "5 GHz" if ch > 14 else "2.4 GHz",
                }
                networks.append(net)
            except (ValueError, IndexError):
                continue
    return networks


def _nmcli_security(sec_str):
    sec = sec_str.upper()
    if "WPA3" in sec and "WPA2" in sec: return "WPA2/WPA3"
    if "WPA3" in sec: return "WPA3"
    if "WPA2" in sec: return "WPA2"
    if "WPA1" in sec or (sec.startswith("WPA") and "WPA2" not in sec): return "WPA"
    if "WEP" in sec: return "WEP"
    if "--" in sec or sec == "": return "OPEN"
    return sec_str.strip() or "UNKNOWN"


def scan_networks(interface=None):
    interfaces = get_interfaces() if not interface else [interface]
    networks = []
    used_iface = None

    for iface in interfaces:
        out, _ = _run_cmd(f"sudo iwlist {iface} scan 2>/dev/null")
        if out and "Cell" in out:
            networks = _parse_iwlist(out)
            used_iface = iface
            break

    if not networks:
        out, _ = _run_cmd("nmcli -t -f IN-USE,SSID,BSSID,MODE,CHAN,FREQ,RATE,SIGNAL,BARS,SECURITY dev wifi list 2>/dev/null")
        if out:
            networks = _parse_nmcli(out)
            used_iface = "nmcli"

    seen, unique = set(), []
    for n in networks:
        key = n.get("bssid", n.get("ssid", ""))
        if key not in seen:
            seen.add(key)
            unique.append(n)

    return unique, used_iface


def get_connected_network():
    info = {}
    import re as _re
    out, _ = _run_cmd("iwgetid -r 2>/dev/null")
    if out:
        info["ssid"] = out.strip()
    out, _ = _run_cmd("iwgetid -a 2>/dev/null")
    m = _re.search(r"([0-9A-Fa-f:]{17})", out)
    if m:
        info["bssid"] = m.group(1).upper()
    out, _ = _run_cmd("ip route show default 2>/dev/null")
    m = _re.search(r"via ([d.]+)", out)
    if m:
        info["gateway"] = m.group(1)
    out, _ = _run_cmd("hostname -I 2>/dev/null")
    if out:
        info["local_ip"] = out.split()[0]
    return info

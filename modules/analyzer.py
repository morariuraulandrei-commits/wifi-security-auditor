"""
Security Analyzer Module
Evaluates security level of detected WiFi networks and assigns risk scores.
"""

SECURITY_RATINGS = {
    "OPEN":       {"score": 0, "level": "CRITICAL", "color": "red",    "emoji": "🔴"},
    "WEP":        {"score": 1, "level": "HIGH",     "color": "orange", "emoji": "🟠"},
    "WPA":        {"score": 2, "level": "MEDIUM",   "color": "yellow", "emoji": "🟡"},
    "WPA2":       {"score": 3, "level": "GOOD",     "color": "green",  "emoji": "🟢"},
    "WPA2/WPA3":  {"score": 4, "level": "VERY GOOD","color": "blue",   "emoji": "🔵"},
    "WPA3":       {"score": 5, "level": "EXCELLENT","color": "purple", "emoji": "🟣"},
    "UNKNOWN":    {"score": -1,"level": "UNKNOWN",  "color": "grey",   "emoji": "⚪"},
}

SECURITY_DESCRIPTIONS = {
    "OPEN": "Reteaua este complet deschisa - traficul este transmis necriptat.",
    "WEP":  "WEP este DEPRECAT si COMPROMIS. Poate fi spart in cateva minute.",
    "WPA":  "WPA (TKIP) are vulnerabilitati cunoscute. Actualizare necesara.",
    "WPA2": "WPA2 cu AES/CCMP este standardul actual. Parola complexa recomandata.",
    "WPA2/WPA3": "Mod tranzitie WPA2/WPA3 - compatibilitate si securitate moderna.",
    "WPA3": "WPA3 este cel mai recent standard. Foloseste SAE pentru protectie maxima.",
    "UNKNOWN": "Tipul de securitate nu a putut fi determinat.",
}

RECOMMENDATIONS = {
    "OPEN":  ["Activeaza imediat criptarea pe router (WPA2 sau WPA3)","NU transmite informatii sensibile pe aceasta retea","Foloseste un VPN daca trebuie sa te conectezi"],
    "WEP":   ["Schimba imediat la WPA2 sau WPA3","WEP poate fi spart in sub 60 de secunde","Verifica daca routerul suporta firmware mai nou"],
    "WPA":   ["Actualizeaza la WPA2 sau WPA3","TKIP are vulnerabilitati cunoscute","Asigura-te ca parola are cel putin 12 caractere"],
    "WPA2":  ["Parola minima 12 caractere cu litere, cifre si simboluri","Dezactiveaza WPS daca nu il folosesti","Verifica daca routerul suporta WPA3"],
    "WPA2/WPA3": ["Considera migrarea completa la WPA3","Parola complexa recomandata","Dezactiveaza WPS daca nu este necesar"],
    "WPA3":  ["Excelent! Esti protejat cu cel mai modern standard","Actualizeaza firmware-ul routerului periodic","Verifica setarile retelei de oaspeti"],
    "UNKNOWN": ["Verifica manual setarile de securitate ale routerului"],
}


def analyze_network(network):
    result = dict(network)
    sec_label = network.get("security_label", "UNKNOWN")
    rating = SECURITY_RATINGS.get(sec_label, SECURITY_RATINGS["UNKNOWN"])

    result["security_score"] = rating["score"]
    result["security_level"] = rating["level"]
    result["security_color"] = rating["color"]
    result["security_emoji"] = rating["emoji"]
    result["security_description"] = SECURITY_DESCRIPTIONS.get(sec_label, "")
    result["recommendations"] = RECOMMENDATIONS.get(sec_label, [])
    result["issues"] = []
    result["positives"] = []

    if network.get("wps"):
        result["issues"].append({"type":"WPS_ENABLED","severity":"HIGH",
            "title":"WPS Activat","detail":"WPS este vulnerabil la Pixie Dust si PIN brute-force.",
            "fix":"Dezactiveaza WPS din setarile routerului."})

    dbm = network.get("signal_dbm", -100)
    if dbm > -50:
        result["positives"].append("Semnal excelent (> -50 dBm)")
    elif dbm > -70:
        result["positives"].append("Semnal bun (-70 pana la -50 dBm)")
    else:
        result["issues"].append({"type":"WEAK_SIGNAL","severity":"LOW",
            "title":"Semnal slab","detail":f"Puterea semnalului este {dbm} dBm.",
            "fix":"Repozitioneaza routerul sau foloseste un repetor WiFi."})

    if sec_label == "OPEN":
        result["issues"].append({"type":"NO_ENCRYPTION","severity":"CRITICAL",
            "title":"Fara criptare","detail":"Orice persoana din raza poate vedea tot traficul.",
            "fix":"Activeaza WPA2 sau WPA3 imediat."})
    elif sec_label == "WEP":
        result["issues"].append({"type":"DEPRECATED_WEP","severity":"CRITICAL",
            "title":"WEP Deprecat","detail":"WEP a fost compromis. Poate fi spart in cateva minute.",
            "fix":"Schimba la WPA2/WPA3 din panoul routerului."})
    elif sec_label == "WPA":
        result["issues"].append({"type":"WEAK_WPA","severity":"MEDIUM",
            "title":"WPA (TKIP) - Protocol vechi","detail":"WPA cu TKIP are vulnerabilitati cunoscute.",
            "fix":"Actualizeaza la WPA2 sau WPA3."})

    if sec_label in ("WPA2","WPA2/WPA3","WPA3"):
        result["positives"].append(f"Folosesti {sec_label} - protocol modern")
    if sec_label == "WPA3":
        result["positives"].append("WPA3 SAE protejeaza impotriva atacurilor offline")
    if not network.get("wps") and sec_label not in ("OPEN","WEP","WPA"):
        result["positives"].append("WPS nu a fost detectat ca activ")

    return result


def analyze_all(networks):
    analyzed = [analyze_network(n) for n in networks]
    analyzed.sort(key=lambda x: x.get("security_score", -1))
    return analyzed


def get_summary_stats(analyzed_networks):
    total = len(analyzed_networks)
    if total == 0:
        return {}
    by_security = {}
    total_issues = 0
    critical_count = 0
    for n in analyzed_networks:
        sec = n.get("security_label", "UNKNOWN")
        by_security[sec] = by_security.get(sec, 0) + 1
        total_issues += len(n.get("issues", []))
        if n.get("security_level") == "CRITICAL":
            critical_count += 1
    return {
        "total_networks": total,
        "by_security": by_security,
        "total_issues": total_issues,
        "critical_count": critical_count,
        "secure_count": sum(1 for n in analyzed_networks if n.get("security_score", 0) >= 3),
    }

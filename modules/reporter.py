"""
Reporter Module
Generates terminal and HTML reports from analysis results.
"""

import os
import json
import datetime


# ── ANSI Colors ──────────────────────────────────────────────────────────────
class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[91m"
    ORANGE  = "\033[33m"
    YELLOW  = "\033[93m"
    GREEN   = "\033[92m"
    BLUE    = "\033[94m"
    CYAN    = "\033[96m"
    PURPLE  = "\033[95m"
    WHITE   = "\033[97m"
    GREY    = "\033[90m"
    BG_RED  = "\033[41m"
    BG_GREEN= "\033[42m"


LEVEL_COLORS = {
    "CRITICAL":  C.RED,
    "HIGH":      C.ORANGE,
    "MEDIUM":    C.YELLOW,
    "GOOD":      C.GREEN,
    "VERY GOOD": C.BLUE,
    "EXCELLENT": C.PURPLE,
    "UNKNOWN":   C.GREY,
    "INFO":      C.CYAN,
    "LOW":       C.YELLOW,
}

SEP = C.GREY + "─" * 70 + C.RESET


def _color_level(level):
    col = LEVEL_COLORS.get(level, C.WHITE)
    return f"{col}{C.BOLD}{level}{C.RESET}"


def _bar(score, max_score=5, width=20):
    filled = int((score / max_score) * width)
    bar = "█" * filled + "░" * (width - filled)
    if score <= 1:
        color = C.RED
    elif score == 2:
        color = C.YELLOW
    elif score == 3:
        color = C.GREEN
    else:
        color = C.PURPLE
    return f"{color}{bar}{C.RESET} {score}/{max_score}"


def print_banner():
    banner = f"""
{C.CYAN}{C.BOLD}
╔═════════════════════════════════════════════════════════════════════╗
║          🛡️  WiFi Security Auditor  |  Cybersecurity Tool  🛡️        ║
║              Scanare · Analiză · Raportare Securitate WiFi           ║
╚══════════════════════════════════════════════════════════════════════╝
{C.RESET}"""
    print(banner)


def print_networks_table(analyzed_networks):
    print(f"\n{C.BOLD}{C.WHITE}{'SSID':<28} {'BSSID':<19} {'CH':>3} {'BAND':<8} {'SIG':>5} {'SECURITATE':<16} {'SCOR'}{C.RESET}")
    print(SEP)
    for n in sorted(analyzed_networks, key=lambda x: -x.get("signal_quality", 0)):
        ssid    = (n.get("ssid") or "<hidden>")[:27]
        bssid   = n.get("bssid", "??:??:??:??:??:??")
        ch      = str(n.get("channel", "?"))
        band    = n.get("band", "?")
        sig     = f"{n.get('signal_dbm', '?')} dBm"
        sec     = n.get("security_label", "UNKNOWN")
        score   = n.get("security_score", -1)
        emoji   = n.get("security_emoji", "⚪")
        col     = LEVEL_COLORS.get(n.get("security_level", "UNKNOWN"), C.WHITE)

        print(
            f"{C.WHITE}{ssid:<28}{C.RESET} "
            f"{C.GREY}{bssid:<19}{C.RESET} "
            f"{ch:>3} "
               f"{band:<8} "
            f"{sig:>8} "
            f"{col}{emoji} {sec:<14}{C.RESET} "
            f"{_bar(max(score, 0))}"
        )
    print(SEP)


def print_detailed_network(n):
    print(f"\n{SEP}")
    ssid = n.get("ssid", "<hidden>")
    emoji = n.get("security_emoji", "⚪")
    level = n.get("security_level", "UNKNOWN")
    print(f"  {emoji} {C.BOLD}{C.WHITE}{ssid}{C.RESET}  →  {_color_level(level)}")
    print(f"  BSSID    : {C.GREY}{n.get('bssid','?')}{C.RESET}")
    print(f"  Canal    : {n.get('channel','?')}  |  Band: {n.get('band','?')}")
    print(f"  Semnal   : {n.get('signal_dbm','?')} dBm  ({n.get('signal_quality','?')}%)")
    print(f"  Securitate: {C.BOLD}{n.get('security_label','?')}{C.RESET}")
    print(f"  Scor     : {_bar(max(n.get('security_score',0), 0))}")
    print(f"\n  {C.CYAN}Descriere:{C.RESET} {n.get('security_description','')}")

    issues = n.get("issues", [])
    if issues:
        print(f"\n  {C.RED}{C.BOLD}⚠  Probleme detectate ({len(issues)}):{C.RESET}")
        for issue in issues:
            sev_col = LEVEL_COLORS.get(issue.get("severity",""), C.WHITE)
            print(f"     • [{sev_col}{issue['severity']}{C.RESET}] {C.BOLD}{issue['title']}{C.RESET}")
            print(f"       {C.GREY}{issue['detail']}{C.RESET}")
            print(f"       {C.GREEN}Fix: {issue['fix']}{C.RESET}")

    positives = n.get("positives", [])
    if positives:
        print(f"\n  {C.GREEN}{C.BOLD}✓  Puncte pozitive:{C.RESET}")
        for p in positives:
            print(f"     • {C.GREEN}{p}{C.RESET}")

    recs = n.get("recommendations", [])
    if recs:
        print(f"\n  {C.YELLOW}{C.BOLD}💡 Recomandări:{C.RESET}")
        for r in recs:
            print(f"     → {r}")


def print_check_results(checks):
    print(f"\n{C.BOLD}{C.CYAN}═══ VERIFICĂRI LOCALE ════════════════════════════════════════════════{C.RESET}")

    gw = checks.get("gateway")
    if gw:
        print(f"\n  🌐 Gateway/Router detectat: {C.GREEN}{gw}{C.RESET}")
    else:
        print(f"\n  🌐 {C.GREY}Gateway nu a putut fi detectat (poate nu ești conectat la WiFi){C.RESET}")

    # Neighbors
    neighbors = checks.get("neighbors", [])
    if neighbors:
        print(f"\n  {C.YELLOW}📡 Dispozitive detectate în rețea ({len(neighbors)}):{C.RESET}")
        for d in neighbors[:15]:
            print(f"     • {d['ip']:<18} {C.GREY}{d['mac']}{C.RESET}")
        if len(neighbors) > 15:
            print(f"     ... și {len(neighbors)-15} altele")

    all_findings = (
        checks.get("admin_panel", []) +
        checks.get("dns", []) +
        checks.get("ipv6", []) +
        checks.get("open_ports", [])
    )

    if all_findings:
        print(f"\n  {C.BOLD}Constatări locale:{C.RESET}")
        for f in all_findings:
            status = f.get("status", "INFO")
            col = LEVEL_COLORS.get(status, C.CYAN)
            print(f"\n  [{col}{status}{C.RESET}] {C.BOLD}{f['title']}{C.RESET}")
            print(f"    {C.GREY}{f['detail']}{C.RESET}")
            print(f"    {C.GREEN}→ {f['recommendation']}{C.RESET}")

    wps_nets = checks.get("wps_networks", [])
    if wps_nets:
        print(f"\n  {C.RED}{C.BOLD}⚠ Rețele cu WPS activat ({len(wps_nets)}):{C.RESET}")
        for n in wps_nets:
            print(f"     • {n.get('ssid','?')} [{n.get('bssid','?')}]")


def print_summary(stats, scan_time):
    print(f"\n{C.BOLD}{C.CYAN}═══ SUMAR ════════════════════════════════════════════════════════════{C.RESET}")
    print(f"\n  Rețele scanate total  : {C.BOLD}{stats.get('total_networks',0)}{C.RESET}")
    print(f"  Rețele cu probleme    : {C.RED}{C.BOLD}{stats.get('critical_count',0)}{C.RESET} critice")
    print(f"  Rețele securizate     : {C.GREEN}{C.BOLD}{stats.get('secure_count',0)}{C.RESET} (WPA2 sau mai bun)")
    print(f"  Probleme totale       : {C.YELLOW}{stats.get('total_issues',0)}{C.RESET}")

    by_sec = stats.get("by_security", {})
    if by_sec:
        print(f"\n  Distribuție securitate:")
        order = ["OPEN","WEP","WPA","WPA2","WPA2/WPA3","WPA3","UNKNOWN"]
        for sec in order:
            cnt = by_sec.get(sec, 0)
            if cnt:
                from modules.analyzer import SECURITY_RATINGS
                info = SECURITY_RATINGS.get(sec, {})
                col = LEVEL_COLORS.get(info.get("level",""), C.WHITE)
                emoji = info.get("emoji","⚪")
                print(f"    {emoji} {col}{sec:<16}{C.RESET} : {cnt}")

    print(f"\n  Timp scanare: {scan_time:.2f}s")
    print(f"  Raport generat: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")


def generate_html_report(analyzed_networks, checks, stats, output_path):
    """Generate a full HTML report."""
    from modules.analyzer import SECURITY_RATINGS

    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    gw = checks.get("gateway", "N/A")
    neighbors = checks.get("neighbors", [])

    # Build network rows
    net_rows = ""
    for n in sorted(analyzed_networks, key=lambda x: x.get("security_score", 5)):
        sec = n.get("security_label", "UNKNOWN")
        level = n.get("security_level", "UNKNOWN")
        emoji = n.get("security_emoji", "⚪")
        score = max(n.get("security_score", 0), 0)
        issues_count = len(n.get("issues", []))
        wps = "⚠ WPS" if n.get("wps") else ""

        css_class = {
            "CRITICAL": "danger", "HIGH": "warning",
            "MEDIUM": "warning", "GOOD": "success",
            "VERY GOOD": "info", "EXCELLENT": "info",
        }.get(level, "secondary")

        net_rows += f"""
        <tr>
          <td><strong>{n.get('ssid','?')}</strong></td>
          <td><code>{n.get('bssid','?')}</code></td>
          <td>{n.get('channel','?')}</td>
          <td>{n.get('band','?')}</td>
          <td>{n.get('signal_dbm','?')} dBm</td>
          <td><span class="badge bg-{css_class}">{emoji} {sec}</span></td>
          <td>{"⚠" * issues_count if issues_count else "✓"} {issues_count or ""}</td>
          <td class="text-danger">{wps}</td>
        </tr>"""

    # Build issues detail cards
    detail_cards = ""
    for n in analyzed_networks:
        issues = n.get("issues", [])
        recs = n.get("recommendations", [])
        pos = n.get("positives", [])
        if not issues and not recs:
            continue
        ssid = n.get("ssid", "?")
        sec = n.get("security_label", "?")
        level = n.get("security_level", "?")
        css_class = {
            "CRITICAL": "danger", "HIGH": "warning",
            "MEDIUM": "warning", "GOOD": "success",
            "VERY GOOD": "info", "EXCELLENT": "primary",
        }.get(level, "secondary")

        issues_html = ""
        for iss in issues:
            sev = iss.get("severity","INFO")
            sev_class = {"CRITICAL":"danger","HIGH":"warning","MEDIUM":"warning","LOW":"info"}.get(sev,"info")
            issues_html += f"""
            <div class="alert alert-{sev_class} py-2 mb-2">
              <strong>[{sev}] {iss['title']}</strong><br>
              <small>{iss['detail']}</small><br>
              <span class="text-success"><em>Fix: {iss['fix']}</em></span>
            </div>"""

        pos_html = "".join(f'<li class="text-success">✓ {p}</li>' for p in pos)
        rec_html = "".join(f'<li>→ {r}</li>' for r in recs)

        detail_cards += f"""
        <div class="card mb-3 border-{css_class}">
          <div class="card-header bg-{css_class} text-white">
            <strong>{ssid}</strong> — <span class="badge bg-dark">{sec}</span>
            <span class="float-end">{n.get('bssid','?')}</span>
          </div>
          <div class="card-body">
            <p class="card-text">{n.get('security_description','')}</p>
            {issues_html}
            {'<ul>' + pos_html + '</ul>' if pos_html else ''}
            {'<hr><strong>Recomandări:</strong><ul>' + rec_html + '</ul>' if rec_html else ''}
          </div>
        </div>"""

    # Neighbor rows
    neighbor_rows = "".join(
        f"<tr><td>{d['ip']}</td><td><code>{d['mac']}</code></td></tr>"
        for d in neighbors
    )

    # Local check findings
    local_findings_html = ""
    all_local = (
        checks.get("admin_panel", []) +
        checks.get("dns", []) +
        checks.get("ipv6", []) +
        checks.get("open_ports", [])
    )
    for f in all_local:
        status = f.get("status","INFO")
        css = {"CRITICAL":"danger","HIGH":"warning","MEDIUM":"warning",
               "LOW":"info","INFO":"info","GOOD":"success"}.get(status,"secondary")
        local_findings_html += f"""
        <div class="alert alert-{css} py-2 mb-2">
          <strong>[{status}] {f['title']}</strong><br>
          <small>{f['detail']}</small><br>
          <em class="text-success">→ {f['recommendation']}</em>
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="ro">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WiFi Security Audit Report</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
<style>
  body {{ background:#1a1a2e; color:#e0e0e0; }}
  .card {{ background:#16213e; border-color:#0f3460; }}
  .card-header {{ background:#0f3460!important; }}
  table {{ color:#e0e0e0; }}
  th {{ background:#0f3460; color:#fff; }}
  td {{ border-color:#1a1a2e!important; }}
  .navbar {{ background:#0f3460!important; }}
  h2, h4 {{ color:#00d4ff; }}
  code {{ color:#ff6b9d; }}
  .stat-card {{ background:#0f3460; border-radius:12px; padding:20px; text-align:center; }}
  .stat-number {{ font-size:2.5rem; font-weight:bold; }}
</style>
</head>
<body>
<nav class="navbar navbar-dark mb-4">
  <div class="container-fluid">
    <span class="navbar-brand h1">🛡️ WiFi Security Auditor — Raport</span>
    <span class="text-muted">{now}</span>
  </div>
</nav>

<div class="container-fluid">

  <!-- Summary cards -->
  <div class="row mb-4">
    <div class="col-md-3">
      <div class="stat-card">
        <div class="stat-number text-info">{stats.get('total_networks',0)}</div>
        <div>Rețele detectate</div>
      </div>
    </div>
    <div class="col-md-3">
      <div class="stat-card">
        <div class="stat-number text-danger">{stats.get('critical_count',0)}</div>
        <div>Rețele critice</div>
      </div>
    </div>
    <div class="col-md-3">
      <div class="stat-card">
        <div class="stat-number text-success">{stats.get('secure_count',0)}</div>
        <div>Rețele securizate</div>
      </div>
    </div>
    <div class="col-md-3">
      <div class="stat-card">
        <div class="stat-number text-warning">{stats.get('total_issues',0)}</div>
        <div>Probleme găsite</div>
      </div>
    </div>
  </div>

  <!-- Networks table -->
  <div class="card mb-4">
    <div class="card-header"><h4 class="mb-0">📡 Rețele WiFi Detectate</h4></div>
    <div class="card-body p-0">
      <table class="table table-dark table-hover mb-0">
        <thead>
          <tr><th>SSID</th><th>BSSID</th><th>Canal</th><th>Band</th>
              <th>Semnal</th><th>Securitate</th><th>Probleme</th><th>WPS</th></tr>
        </thead>
        <tbody>{net_rows}</tbody>
      </table>
    </div>
  </div>

  <!-- Detail cards -->
  <div class="card mb-4">
    <div class="card-header"><h4 class="mb-0">🔍 Analiză Detaliată</h4></div>
    <div class="card-body">{detail_cards or '<p class="text-success">✓ Nu au fost găsite probleme majore.</p>'}</div>
  </div>

  <!-- Local checks -->
  <div class="row mb-4">
    <div class="col-md-8">
      <div class="card">
        <div class="card-header"><h4 class="mb-0">🖥️ Verificări Locale (Gateway: {gw})</h4></div>
        <div class="card-body">
          {local_findings_html or '<p class="text-success">✓ Nu au fost detectate probleme locale.</p>'}
        </div>
      </div>
    </div>
    <div class="col-md-4">
      <div class="card">
        <div class="card-header"><h4 class="mb-0">🏠 Dispozitive în rețea ({len(neighbors)})</h4></div>
        <div class="card-body p-0">
          {'<table class="table table-dark table-sm mb-0"><thead><tr><th>IP</th><th>MAC</th></tr></thead><tbody>' + neighbor_rows + '</tbody></table>' if neighbor_rows else '<p class="text-muted m-3">Niciun dispozitiv detectat în ARP cache.</p>'}
        </div>
      </div>
    </div>
  </div>

  <footer class="text-center text-muted mb-4">
    <small>WiFi Security Auditor — scop educational, utilizare exclusiv pe rețele proprii</small>
  </footer>
</div>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    return output_path


def export_json(analyzed_networks, checks, stats, output_path):
    """Export results as JSON."""
    data = {
        "generated_at": datetime.datetime.now().isoformat(),
        "summary": stats,
        "networks": [
            {k: v for k, v in n.items() if not isinstance(v, set)}
            for n in analyzed_networks
        ],
        "local_checks": {
            "gateway": checks.get("gateway"),
            "findings": (
                checks.get("admin_panel", []) +
                checks.get("dns", []) +
                checks.get("ipv6", []) +
                checks.get("open_ports", [])
            ),
            "neighbor_count": len(checks.get("neighbors", [])),
        },
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    return output_path

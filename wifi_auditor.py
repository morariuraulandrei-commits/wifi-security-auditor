#!/usr/bin/env python3
"""
WiFi Security Auditor - instrument educational pentru auditarea securitatii retelelor WiFi proprii.
NOTA: Folositi EXCLUSIV pe retelele WiFi pe care le detineti sau aveti permisiune explicita.
"""

import argparse, sys, os, time, datetime
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.scanner import scan_networks, get_interfaces, get_connected_network
from modules.analyzer import analyze_all, get_summary_stats
from modules.checker import run_all_checks
from modules.reporter import (
    print_banner, print_networks_table, print_detailed_network,
    print_check_results, print_summary, generate_html_report, export_json, C
)


def check_root():
    if os.geteuid() != 0:
        print(f"{C.YELLOW}⚠  Rulezi fara privilegii root. Unele functii necesita sudo.{C.RESET}\n")


def check_dependencies():
    import shutil
    tools = {"iwlist":"wireless-tools","nmcli":"network-manager","iw":"iw","nmap":"nmap","iwgetid":"wireless-tools"}
    missing, available = [], []
    for tool, pkg in tools.items():
        (available if shutil.which(tool) else missing).append((tool, pkg))
    if available:
        print(f"{C.GREEN}✓ Unelte disponibile:{C.RESET} {', '.join(t for t,_ in available)}")
    if missing:
        pkgs = " ".join(set(p for _,p in missing))
        print(f"{C.YELLOW}⚠ Unelte lipsa:{C.RESET} {', '.join(t for t,_ in missing)}")
        print(f"  Instalare: {C.CYAN}sudo apt-get install {pkgs}{C.RESET}\n")
    return bool(available)


def parse_args():
    parser = argparse.ArgumentParser(description="WiFi Security Auditor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Exemple:\n  sudo python3 wifi_auditor.py\n  sudo python3 wifi_auditor.py --report\n  sudo python3 wifi_auditor.py --quick")
    parser.add_argument("--quick",     action="store_true", help="Doar tabelul retelelor")
    parser.add_argument("--report",    action="store_true", help="Genereaza raport HTML")
    parser.add_argument("--json",      action="store_true", help="Exporta JSON")
    parser.add_argument("--no-checks", action="store_true", help="Sari verificarile locale")
    parser.add_argument("--iface",     type=str, default=None, help="Interfata WiFi (ex: wlan0)")
    parser.add_argument("--output",    type=str, default=None, help="Fisier output")
    parser.add_argument("--all",       action="store_true", help="Detalii pentru toate retelele")
    return parser.parse_args()


def main():
    args = parse_args()
    print_banner()
    check_root()

    print(f"{C.BOLD}[1/4] Verificare unelte disponibile...{C.RESET}")
    check_dependencies()

    print(f"{C.BOLD}[2/4] Detectare interfete WiFi...{C.RESET}")
    interfaces = get_interfaces()
    if interfaces:
        print(f"  Interfete detectate: {C.GREEN}{', '.join(interfaces)}{C.RESET}")
    else:
        print(f"  {C.YELLOW}Nicio interfata WiFi detectata.{C.RESET}")
        print(f"  {C.GREY}(pe WSL: utilizeaza nmcli sau adaptorul WiFi nativ){C.RESET}")

    connected = get_connected_network()
    if connected.get("ssid"):
        print(f"  Conectat la: {C.GREEN}{C.BOLD}{connected['ssid']}{C.RESET}  IP: {connected.get('local_ip','?')}  GW: {connected.get('gateway','?')}")

    print(f"\n{C.BOLD}[3/4] Scanare retele WiFi...{C.RESET}")
    print(f"  {C.GREY}(poate dura 10-30 secunde){C.RESET}")

    t_start = time.time()
    networks, used_iface = scan_networks(interface=args.iface)
    t_scan = time.time() - t_start

    if not networks:
        print(f"\n  {C.YELLOW}⚠ Nu au fost gasite retele WiFi.{C.RESET}")
        print(f"  Pe WSL: adaptorul WiFi nu este expus direct la Linux.")
        print(f"  Solutie: sudo nmcli dev wifi list")
        print(f"\n  {C.GREY}Generand raport demo cu date simulate...{C.RESET}\n")
        networks = _demo_networks()

    analyzed = analyze_all(networks)
    stats = get_summary_stats(analyzed)
    if used_iface:
        print(f"  Interfata folosita: {C.CYAN}{used_iface}{C.RESET}")
    print(f"  Retele gasite: {C.BOLD}{len(analyzed)}{C.RESET}  (scanat in {t_scan:.1f}s)")

    print(f"\n{C.BOLD}{C.CYAN}=== REZULTATE SCANARE ==={C.RESET}")
    print_networks_table(analyzed)

    if not args.quick:
        critical_nets = [n for n in analyzed if n.get("security_score",5)<3 or n.get("issues")]
        if critical_nets or args.all:
            nets_to_show = analyzed if args.all else critical_nets[:5]
            print(f"\n{C.BOLD}{C.RED}=== RETELE CU PROBLEME ==={C.RESET}")
            for n in nets_to_show:
                print_detailed_network(n)

    checks = {}
    if not args.no_checks:
        print(f"\n{C.BOLD}[4/4] Verificari de securitate locale...{C.RESET}")
        checks = run_all_checks(networks=analyzed)
        print_check_results(checks)
    else:
        print(f"\n{C.GREY}[4/4] Verificari locale sarite.{C.RESET}")

    print_summary(stats, t_scan)

    if args.report or args.json:
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        if args.report:
            out = args.output or f"wifi_audit_{ts}.html"
            generate_html_report(analyzed, checks, stats, out)
            print(f"\n  {C.GREEN}✓ Raport HTML: {out}{C.RESET}")
        if args.json:
            out = args.output or f"wifi_audit_{ts}.json"
            export_json(analyzed, checks, stats, out)
            print(f"  {C.GREEN}✓ JSON: {out}{C.RESET}")

    print(f"\n{C.CYAN}{'='*70}{C.RESET}")
    print(f"{C.GREY}WiFi Security Auditor - utilizare exclusiv pe retele proprii{C.RESET}\n")


def _demo_networks():
    return [
        {"ssid":"HomeNetwork_DEMO", "bssid":"AA:BB:CC:DD:EE:01","channel":6, "band":"2.4 GHz","signal_dbm":-55,"signal_quality":90,"security_label":"WPA2"},
        {"ssid":"OldRouter",        "bssid":"AA:BB:CC:DD:EE:02","channel":11,"band":"2.4 GHz","signal_dbm":-72,"signal_quality":56,"security_label":"WEP","wps":True},
        {"ssid":"FreeWifi_OPEN",    "bssid":"AA:BB:CC:DD:EE:03","channel":1, "band":"2.4 GHz","signal_dbm":-80,"signal_quality":40,"security_label":"OPEN"},
        {"ssid":"Neighbor_WPA",     "bssid":"AA:BB:CC:DD:EE:04","channel":36,"band":"5 GHz",  "signal_dbm":-65,"signal_quality":70,"security_label":"WPA"},
        {"ssid":"ModernRouter_5G",  "bssid":"AA:BB:CC:DD:EE:05","channel":44,"band":"5 GHz",  "signal_dbm":-48,"signal_quality":100,"security_label":"WPA3"},
        {"ssid":"TP-Link_Default",  "bssid":"AA:BB:CC:DD:EE:06","channel":6, "band":"2.4 GHz","signal_dbm":-70,"signal_quality":60,"security_label":"WPA2","wps":True},
        {"ssid":"ASUS_Transition",  "bssid":"AA:BB:CC:DD:EE:07","channel":100,"band":"5 GHz", "signal_dbm":-58,"signal_quality":84,"security_label":"WPA2/WPA3"},
    ]

if __name__ == "__main__":
    main()

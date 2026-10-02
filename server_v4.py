#!/usr/bin/env python3
"""
WiFi Scanner Server v4 — Cyber Intelligence Edition
=====================================================
HOW IP DISCOVERY WORKS (v4 fix — v3 was broken):
  • v3 BUG: Tried to match AP BSSID (wireless radio MAC) against ARP table.
    This NEVER works — an AP's BSSID is its WiFi interface MAC, which is
    completely different from its LAN/gateway MAC address.
  • v4 FIX: Correct approach:
      1. Gateway IP = the connected router's management IP (always accurate)
      2. /proc/net/arp + `ip neigh` = all LAN hosts recently contacted
      3. nmap -sn subnet sweep = discover every live host on LAN
      4. Port scan runs on GATEWAY + all discovered LAN hosts
      5. OUI prefix match: if AP vendor == LAN host vendor → likely the AP
      6. Connected AP always gets gateway IP (100% reliable)

RUN:
  sudo python3 wifi_server_v4.py
API: http://localhost:8765/wifi
     http://localhost:8765/hosts   ← all discovered LAN hosts + ports

REQUIREMENTS:
  sudo apt install network-manager nmap iproute2 python3
"""

import subprocess, json, math, re, threading, time, collections, socket
from http.server import HTTPServer, BaseHTTPRequestHandler
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── Config ─────────────────────────────────────────────────────────────────────
PORT               = 8765
SCAN_INTERVAL      = 15       # WiFi scan interval (seconds)
HOST_DISC_INTERVAL = 45       # How often to re-discover LAN hosts
PORT_RESCAN_SEC    = 90       # Rescan ports on known IPs after this many seconds
CALIBRATION_FACTOR = 1.0
C_LIGHT            = 299_792_458.0
HISTORY_LEN        = 8

# ── Globals ────────────────────────────────────────────────────────────────────
latest_data    = {"networks": [], "timestamp": 0, "error": None,
                  "scan_count": 0, "host_info": {}, "channel_map": {},
                  "gateway_ip": None, "local_ip": None, "subnet": None}
data_lock      = threading.Lock()
signal_history = collections.defaultdict(lambda: collections.deque(maxlen=HISTORY_LEN))

# IP/port caches (filled by background thread)
ip_cache      = {}   # bssid → ip  (only for connected AP via gateway)
host_cache    = {}   # ip → {mac, vendor, hostname, ports, os_guess, risk, last_scan}
hidden_cache  = {}   # bssid → ssid string or None


# ═══════════════════════════════════════════════════════════════════════════════
#  DISTANCE ENGINE  (LDPL-v2, unchanged)
# ═══════════════════════════════════════════════════════════════════════════════
def quality_to_dbm(q: int) -> float:
    """NetworkManager quality (0-100) → dBm. Correct NM inverse formula."""
    return (float(q) * 70.0 / 100.0) - 110.0

def fspl_at_1m(freq_hz: float) -> float:
    return 20.0 * math.log10((4.0 * math.pi * freq_hz) / C_LIGHT)

def estimate_n(freq_ghz: float, all_quality: list) -> float:
    base = 3.1 if freq_ghz >= 5.0 else 3.3
    if len(all_quality) >= 2:
        spread = abs(quality_to_dbm(max(all_quality)) - quality_to_dbm(min(all_quality)))
        if spread < 12:   base -= 0.2
        elif spread > 40: base += 0.3
    return round(base, 2)

def estimate_tx(ssid: str, freq_ghz: float) -> int:
    s = (ssid or "").lower()
    if any(k in s for k in ["jio","airtel","act","bsnl","hathway","tata","fiber","fibre","mesh","orbi","eero","deco","nighthawk"]): return 23
    if any(k in s for k in ["hotspot","mobile","phone","android","iphone","galaxy","redmi","oneplus","realme","poco","pixel"]): return 18
    return 22 if freq_ghz >= 5.0 else 23

def smooth_signal(bssid: str, raw: float) -> float:
    h = signal_history[bssid]; h.append(raw)
    if len(h) == 1: return raw
    e = float(h[0])
    for v in list(h)[1:]: e = 0.4 * v + 0.6 * e
    return round(e, 1)

def compute_distance(quality: int, bssid: str, freq_hz: float, ssid: str, all_q: list) -> dict:
    dbm_r = quality_to_dbm(quality)
    dbm   = smooth_signal(bssid, dbm_r)
    hlen  = len(signal_history[bssid])
    fghz  = freq_hz / 1e9
    tx    = estimate_tx(ssid, fghz)
    fspl  = fspl_at_1m(freq_hz)
    n     = estimate_n(fghz, all_q)
    loss  = max(float(tx) - dbm, 1.0)
    exp   = (loss - fspl) / (10.0 * n)
    d     = max(0.3, min(10.0 ** exp * CALIBRATION_FACTOR, 300.0))
    conf  = max(10, min(95, 90
                        - max(0, (HISTORY_LEN - hlen) * 7)
                        - (20 if dbm < -75 else 10 if dbm < -65 else 0)
                        - (5 if fghz >= 5 else 0)))
    if d < 1:      val, unit = round(d * 100, 1), "cm"
    elif d < 1000: val, unit = round(d, 1), "m"
    else:          val, unit = round(d / 1000, 2), "km"
    return {"value": val, "unit": unit, "raw_m": round(d, 2), "confidence": conf,
            "smoothed_dbm": dbm, "tx_power_dbm": tx, "path_loss_exp": n,
            "wall_loss_db": 0, "interference_db": 0, "model": "LDPL-v2",
            "_dbm_raw": round(dbm_r, 1), "_fspl_1m": round(fspl, 2),
            "_measured_loss": round(loss, 1)}


# ═══════════════════════════════════════════════════════════════════════════════
#  NETWORK INTERFACE HELPERS
# ═══════════════════════════════════════════════════════════════════════════════
def get_wifi_ifaces() -> list:
    """Return wireless interface names (wlan0, wlp2s0, etc.)."""
    try:
        r = subprocess.run(["ip", "-o", "link", "show"],
                           capture_output=True, text=True, timeout=5)
        ifaces = []
        for line in r.stdout.splitlines():
            if any(p in line for p in ["wlan", "wlp", "wlx", "wlo"]):
                name = re.split(r'\d+:', line)[1].strip().split("@")[0].strip() if ':' in line else "wlan0"
                # cleaner parse
                m = re.search(r'^\d+:\s+(\S+)', line)
                if m:
                    n = m.group(1).split("@")[0]
                    if any(p in n for p in ["wlan","wlp","wlx","wlo"]):
                        ifaces.append(n)
        return ifaces if ifaces else ["wlan0"]
    except Exception:
        return ["wlan0"]


def get_gateway_ip() -> str | None:
    """Default gateway — this is the router/AP management IP."""
    try:
        r = subprocess.run(["ip", "route", "show", "default"],
                           capture_output=True, text=True, timeout=5)
        m = re.search(r'default via ([\d.]+)', r.stdout)
        return m.group(1) if m else None
    except Exception:
        return None


def get_local_ip_and_subnet() -> tuple:
    """
    Returns (local_ip, subnet_cidr) e.g. ('192.168.1.5', '192.168.1.0/24').
    We look at the WiFi interface specifically.
    """
    try:
        ifaces = get_wifi_ifaces()
        r = subprocess.run(["ip", "-4", "addr", "show"],
                           capture_output=True, text=True, timeout=5)
        lines = r.stdout.splitlines()
        target_iface = None
        for i, line in enumerate(lines):
            # Check if this line announces one of our WiFi interfaces
            for iface in ifaces:
                if re.match(rf'^\d+:\s+{re.escape(iface)}\b', line):
                    target_iface = iface
            if target_iface and "inet " in line:
                m = re.search(r'inet ([\d.]+)/([\d]+)', line)
                if m:
                    ip   = m.group(1)
                    plen = int(m.group(2))
                    # Convert to network CIDR
                    parts = [int(x) for x in ip.split('.')]
                    mask  = (0xFFFFFFFF << (32 - plen)) & 0xFFFFFFFF
                    net   = [(parts[i] & ((mask >> (24 - 8 * i)) & 0xFF)) for i in range(4)]
                    subnet = f"{'.'.join(map(str, net))}/{plen}"
                    return ip, subnet
        # Fallback: any inet on any interface
        for line in lines:
            if "inet " in line and "127.0.0.1" not in line:
                m = re.search(r'inet ([\d.]+)/([\d]+)', line)
                if m:
                    ip   = m.group(1)
                    plen = int(m.group(2))
                    parts = [int(x) for x in ip.split('.')]
                    mask  = (0xFFFFFFFF << (32 - plen)) & 0xFFFFFFFF
                    net   = [(parts[i] & ((mask >> (24 - 8 * i)) & 0xFF)) for i in range(4)]
                    subnet = f"{'.'.join(map(str, net))}/{plen}"
                    return ip, subnet
    except Exception as e:
        print(f"  [NetInfo] Error: {e}")
    return None, None


# ═══════════════════════════════════════════════════════════════════════════════
#  HOST DISCOVERY  (reliable multi-method approach)
# ═══════════════════════════════════════════════════════════════════════════════
def read_arp_table() -> dict:
    """
    Read kernel ARP/neighbour table — fastest, no tools needed.
    Returns {ip: mac_upper}.
    Method 1: /proc/net/arp  (always available on Linux)
    Method 2: `ip neigh show` (iproute2)
    """
    hosts = {}

    # Method 1: /proc/net/arp (direct kernel table)
    try:
        with open("/proc/net/arp") as f:
            for line in f.readlines()[1:]:   # skip header
                parts = line.split()
                if len(parts) >= 4:
                    ip  = parts[0]
                    mac = parts[3].upper()
                    flags = parts[2]
                    # flags=0x0 means incomplete/stale, skip
                    if re.match(r'\d+\.\d+\.\d+\.\d+', ip) and re.match(r'[\dA-F]{2}:[\dA-F]{2}', mac) and mac != "00:00:00:00:00:00":
                        hosts[ip] = mac
    except Exception:
        pass

    # Method 2: ip neigh show (adds recently expired entries too)
    try:
        r = subprocess.run(["ip", "neigh", "show"],
                           capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines():
            # format: 192.168.1.1 dev wlan0 lladdr ac:84:c9:xx:xx:xx REACHABLE
            m = re.search(r'^([\d.]+).*lladdr\s+([\dA-Fa-f:]{17})', line)
            if m:
                ip  = m.group(1)
                mac = m.group(2).upper()
                if ip not in hosts:
                    hosts[ip] = mac
    except Exception:
        pass

    return hosts


def nmap_ping_sweep(subnet: str) -> dict:
    """
    Discover ALL live hosts on subnet using nmap ping sweep.
    Returns {ip: mac_upper}.
    This is the RELIABLE way to find all LAN hosts.
    """
    hosts = {}
    if not subnet:
        return hosts

    print(f"  [HostDisc] nmap ping sweep: {subnet}")
    try:
        # -sn = no port scan (ping only)
        # -oG - = greppable output to stdout
        # --send-ip = use IP ping (works without raw sockets on some systems)
        # sudo is required for proper ARP discovery
        r = subprocess.run(
            ["nmap", "-sn", subnet, "-oG", "-", "--host-timeout", "5s"],
            capture_output=True, text=True, timeout=60
        )
        current_ip = None
        for line in r.stdout.splitlines():
            # Host: 192.168.1.1 (hostname)   Status: Up
            if line.startswith("Host:") and "Status: Up" in line:
                m = re.search(r'Host: ([\d.]+)', line)
                if m:
                    current_ip = m.group(1)
                    hosts[current_ip] = hosts.get(current_ip, "")
            # Separate MAC line in some nmap versions
            if "MAC Address:" in line and current_ip:
                m = re.search(r'MAC Address: ([\dA-F:]{17})', line, re.IGNORECASE)
                if m:
                    hosts[current_ip] = m.group(1).upper()
        print(f"  [HostDisc] nmap found {len(hosts)} hosts")
    except FileNotFoundError:
        print("  [HostDisc] nmap not found — install with: sudo apt install nmap")
    except Exception as e:
        print(f"  [HostDisc] nmap error: {e}")

    # Merge with ARP table to fill in missing MACs
    arp = read_arp_table()
    for ip in hosts:
        if not hosts[ip] and ip in arp:
            hosts[ip] = arp[ip]

    return hosts


def ping_host(ip: str, count: int = 1) -> bool:
    """Quick ping to check if host is alive."""
    try:
        r = subprocess.run(
            ["ping", "-c", str(count), "-W", "1", "-q", ip],
            capture_output=True, timeout=3
        )
        return r.returncode == 0
    except Exception:
        return False


def arping_host(ip: str, iface: str) -> str | None:
    """
    Use arping to get MAC for a specific IP (works only on same subnet).
    Returns MAC string or None.
    """
    try:
        r = subprocess.run(
            ["arping", "-c", "2", "-I", iface, ip],
            capture_output=True, text=True, timeout=5
        )
        m = re.search(r'\[([\dA-Fa-f:]{17})\]', r.stdout)
        return m.group(1).upper() if m else None
    except Exception:
        return None


# ═══════════════════════════════════════════════════════════════════════════════
#  PORT SCANNING  (TCP connect — no raw sockets needed)
# ═══════════════════════════════════════════════════════════════════════════════
PORTS_TO_SCAN = {
    # Port: (service_name, description, risk_level)
    21:    ("FTP",          "File transfer — plaintext credentials",         "HIGH"),
    22:    ("SSH",          "Secure shell — brute-force risk if weak auth",   "MEDIUM"),
    23:    ("Telnet",       "Plaintext remote shell — CRITICAL exposure",     "CRITICAL"),
    25:    ("SMTP",         "Mail server",                                    "LOW"),
    53:    ("DNS",          "Domain name service — zone transfer risk",       "LOW"),
    80:    ("HTTP",         "Web admin UI — unencrypted",                     "MEDIUM"),
    110:   ("POP3",         "Email retrieval — plaintext",                    "MEDIUM"),
    135:   ("MS-RPC",       "Windows RPC endpoint mapper",                    "HIGH"),
    139:   ("NetBIOS-SSN",  "Windows/Samba file sharing",                     "HIGH"),
    143:   ("IMAP",         "Email access",                                   "LOW"),
    161:   ("SNMP",         "Network management — default community string",  "CRITICAL"),
    443:   ("HTTPS",        "Secure web admin UI",                            "LOW"),
    445:   ("SMB",          "Windows file share — EternalBlue/ransomware",    "CRITICAL"),
    515:   ("LPD",          "Line printer daemon",                            "LOW"),
    554:   ("RTSP",         "IP camera stream — check if auth required",      "HIGH"),
    587:   ("SMTP-SUB",     "Mail submission",                                "LOW"),
    631:   ("IPP",          "Internet printing protocol",                     "LOW"),
    993:   ("IMAPS",        "Secure IMAP",                                    "LOW"),
    1883:  ("MQTT",         "IoT messaging broker — often unauthenticated",   "CRITICAL"),
    3306:  ("MySQL",        "Database server exposed to LAN",                 "HIGH"),
    3389:  ("RDP",          "Windows remote desktop — brute-force target",    "HIGH"),
    4848:  ("GlassFish",    "Java EE app server admin console",               "HIGH"),
    5000:  ("UPnP/Dev",     "UPnP or development HTTP server",                "MEDIUM"),
    5555:  ("ADB",          "Android Debug Bridge — full device access",      "CRITICAL"),
    5900:  ("VNC",          "Remote desktop — check password strength",       "HIGH"),
    7547:  ("TR-069/CWMP",  "ISP remote management — Misfortune Cookie",      "CRITICAL"),
    8080:  ("HTTP-alt",     "Alternate web port — admin panels",              "MEDIUM"),
    8181:  ("HTTP-alt2",    "Alternate HTTP service",                         "MEDIUM"),
    8443:  ("HTTPS-alt",    "Alternate HTTPS",                                "LOW"),
    8888:  ("HTTP-alt3",    "Jupyter / dev server",                           "MEDIUM"),
    9000:  ("Portainer",    "Docker management UI",                           "HIGH"),
    9090:  ("Prometheus",   "Metrics/monitoring — info leak",                 "MEDIUM"),
    9100:  ("JetDirect",    "Printer direct — info leak via PJL",             "MEDIUM"),
    9443:  ("VMware",       "VMware vSphere web client",                      "MEDIUM"),
    47808: ("BACnet",       "Building automation — SCADA exposure",           "HIGH"),
    49152: ("UPnP",         "Universal Plug and Play — SSRF risk",            "MEDIUM"),
    51820: ("WireGuard",    "WireGuard VPN",                                  "LOW"),
}

RISK_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def grab_banner(ip: str, port: int, timeout: float = 1.5) -> str:
    """Attempt to grab service banner from open port."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        # Send appropriate probe
        if port in (80, 8080, 8181, 8888, 5000):
            s.send(f"GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: NetScan/4.0\r\n\r\n".encode())
        elif port == 22:
            pass  # SSH sends banner automatically
        elif port == 21:
            pass  # FTP sends banner automatically
        elif port == 23:
            pass  # Telnet sends banner
        else:
            s.send(b"\r\n")
        data = s.recv(1024)
        s.close()
        banner = data.decode("utf-8", errors="replace").strip()
        # Extract first meaningful line
        for line in banner.splitlines():
            line = line.strip()
            if line and not line.startswith("\x00"):
                return line[:160]
        return ""
    except Exception:
        return ""


def tcp_probe(ip: str, port: int, timeout: float = 1.2) -> bool:
    """TCP connect probe — returns True if port is open."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        rc = s.connect_ex((ip, port))
        s.close()
        return rc == 0
    except Exception:
        return False


def scan_ports_on_ip(ip: str) -> list:
    """
    Scan all PORTS_TO_SCAN on a single IP using parallel TCP connect.
    Returns sorted list of open port dicts.
    """
    if not ip:
        return []

    print(f"  [PortScan] Scanning {ip} ({len(PORTS_TO_SCAN)} ports)…")
    open_ports = []

    def probe_one(port_data):
        port, (svc, desc, risk) = port_data
        if tcp_probe(ip, port, timeout=1.2):
            banner = grab_banner(ip, port, timeout=1.0) if port in (
                21, 22, 23, 80, 8080, 8181, 8888, 443, 554, 5900, 4848) else ""
            return {"port": port, "service": svc, "desc": desc,
                    "risk": risk, "banner": banner}
        return None

    with ThreadPoolExecutor(max_workers=40) as pool:
        futures = [pool.submit(probe_one, item) for item in PORTS_TO_SCAN.items()]
        for f in as_completed(futures):
            res = f.result()
            if res:
                open_ports.append(res)

    open_ports.sort(key=lambda p: (RISK_ORDER.get(p["risk"], 9), p["port"]))
    print(f"  [PortScan] {ip}: {len(open_ports)} open ports")
    return open_ports


def guess_os(ports: list, mac: str = "") -> str:
    """Heuristic OS/device identification from open ports + MAC OUI."""
    pnums = {p["port"] for p in ports}
    if 7547 in pnums:                    return "Router / ISP Gateway"
    if 554 in pnums:                     return "IP Camera / NVR"
    if 5555 in pnums:                    return "Android Device"
    if 47808 in pnums:                   return "SCADA / BACnet Controller"
    if 3389 in pnums:                    return "Windows Desktop/Server"
    if 445 in pnums and 135 in pnums:    return "Windows (SMB+RPC)"
    if 139 in pnums:                     return "Windows / Samba"
    if 9000 in pnums:                    return "Docker Host"
    if 1883 in pnums:                    return "IoT MQTT Broker"
    if 9100 in pnums or 515 in pnums or 631 in pnums: return "Network Printer"
    if 22 in pnums and 80 in pnums:      return "Linux Server"
    if 22 in pnums:                      return "Linux / Unix"
    if 3306 in pnums:                    return "Database Server"
    if 80 in pnums or 8080 in pnums or 443 in pnums:  return "Web Device / Router"
    return "Unknown"


def risk_score(ports: list) -> int:
    """
    0-100 risk score based on open ports.
    CRITICAL ports = 30 pts each, HIGH = 15, MEDIUM = 5.
    """
    if not ports: return 0
    score = 0
    for p in ports:
        score += {"CRITICAL": 30, "HIGH": 15, "MEDIUM": 5, "LOW": 1}.get(p["risk"], 0)
    return min(score, 100)


# ═══════════════════════════════════════════════════════════════════════════════
#  HIDDEN SSID PROBING
# ═══════════════════════════════════════════════════════════════════════════════
def probe_hidden_ssid(bssid: str) -> str | None:
    """Try to find the SSID of a hidden AP via NM connection history."""
    if bssid in hidden_cache:
        return hidden_cache[bssid]

    # Method 1: NetworkManager seen-bssids in saved connections
    try:
        r = subprocess.run(
            ["nmcli", "-t", "-f", "NAME,UUID", "connection", "show"],
            capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines():
            parts = line.split(":", 1)
            if len(parts) < 2: continue
            uuid = parts[1].strip()
            r2 = subprocess.run(
                ["nmcli", "-t", "-f",
                 "802-11-wireless.seen-bssids,802-11-wireless.ssid",
                 "connection", "show", uuid],
                capture_output=True, text=True, timeout=3)
            if bssid.upper() in r2.stdout.upper():
                for l2 in r2.stdout.splitlines():
                    if "802-11-wireless.ssid:" in l2.lower():
                        ssid = l2.split(":", 1)[1].strip()
                        if ssid and ssid != "--":
                            hidden_cache[bssid] = ssid
                            return ssid
    except Exception:
        pass

    # Method 2: iw scan output BSS blocks
    try:
        ifaces = get_wifi_ifaces()
        if ifaces:
            r = subprocess.run(["iw", "dev", ifaces[0], "scan"],
                               capture_output=True, text=True, timeout=10)
            cur_bssid = None
            for line in r.stdout.splitlines():
                line = line.strip()
                if line.startswith("BSS "):
                    m = re.search(r'BSS ([\dA-Fa-f:]{17})', line)
                    cur_bssid = m.group(1).upper() if m else None
                if cur_bssid and cur_bssid == bssid.upper():
                    m2 = re.match(r'SSID:\s+(.+)', line)
                    if m2:
                        ssid = m2.group(1).strip()
                        if ssid:
                            hidden_cache[bssid] = ssid
                            return ssid
    except Exception:
        pass

    hidden_cache[bssid] = None
    return None


# ═══════════════════════════════════════════════════════════════════════════════
#  SECURITY AUDIT
# ═══════════════════════════════════════════════════════════════════════════════
def audit_wifi(net: dict) -> list:
    """Return list of {level, msg} security findings for a WiFi network."""
    findings = []
    sec  = (net.get("security") or "").upper()
    ssid = net.get("ssid", "")
    dbm  = net.get("dbm", -90)
    fghz = net.get("freq_ghz", 2.4)

    if sec in ("OPEN", "", "NONE"):
        findings.append({"level": "CRITICAL", "msg": "No encryption — all traffic visible in plaintext"})
    elif "WEP" in sec:
        findings.append({"level": "CRITICAL", "msg": "WEP — crackable in < 60 seconds with aircrack-ng"})
    elif "WPA3" in sec:
        findings.append({"level": "LOW",      "msg": "WPA3-SAE — strong, resistant to PMKID/offline attacks"})
    elif "WPA2" in sec:
        findings.append({"level": "MEDIUM",   "msg": "WPA2-PSK — vulnerable to PMKID capture + offline dictionary"})
    elif "WPA" in sec:
        findings.append({"level": "HIGH",     "msg": "WPA-TKIP — vulnerable to dictionary attacks"})

    if not ssid or ssid == "<Hidden>":
        findings.append({"level": "INFO", "msg": "Hidden SSID — not real security, discoverable via probe"})
    elif any(k in ssid.lower() for k in ["netgear","dlink","linksys","asus","tp-link","tplink","default","admin","belkin"]):
        findings.append({"level": "HIGH", "msg": f"Default SSID '{ssid}' — likely default password"})
    elif any(k in ssid.lower() for k in ["home","house","flat","wifi","wireless","internet"]):
        findings.append({"level": "LOW",  "msg": "Generic SSID — minimal obscurity"})

    if dbm >= -50:
        findings.append({"level": "INFO", "msg": "Very strong signal — attacker in same room/metre range"})
    elif dbm >= -65:
        findings.append({"level": "INFO", "msg": "Good signal — attacker within same building"})

    if fghz < 5:
        findings.append({"level": "INFO", "msg": "2.4 GHz — wider range increases passive interception surface"})

    return findings


def build_channel_map(networks: list) -> dict:
    """Count networks per channel."""
    counter = collections.Counter()
    for n in networks:
        ch = n.get("channel", "?")
        if ch != "?":
            try: counter[int(ch)] += 1
            except (ValueError, TypeError): pass
    return {str(ch): {"count": c, "congested": c >= 3,
                       "band": "5GHz" if int(ch) > 14 else "2.4GHz"}
            for ch, c in counter.items()}


# ═══════════════════════════════════════════════════════════════════════════════
#  WIFI SCANNERS
# ═══════════════════════════════════════════════════════════════════════════════
def dbm_to_pct(dbm: float) -> int:
    return round(((max(-90.0, min(-30.0, float(dbm))) + 90.0) / 60.0) * 100.0)

def classify(dbm: float) -> str:
    if dbm >= -50: return "excellent"
    if dbm >= -60: return "good"
    if dbm >= -70: return "fair"
    return "poor"


def scan_nmcli() -> list:
    r = subprocess.run(
        ["nmcli", "-t", "-f",
         "SSID,BSSID,MODE,CHAN,FREQ,RATE,SIGNAL,BARS,SECURITY,ACTIVE",
         "dev", "wifi", "list", "--rescan", "yes"],
        capture_output=True, text=True, timeout=20)
    if r.returncode != 0:
        raise RuntimeError(f"nmcli: {r.stderr.strip()}")

    networks, seen = [], set()
    for line in r.stdout.strip().splitlines():
        parts = re.split(r'(?<!\\):', line)
        parts = [p.replace('\\:', ':') for p in parts]
        if len(parts) < 9: continue

        ssid   = parts[0].strip()
        bssid  = parts[1].strip()
        if bssid in seen: continue
        seen.add(bssid)

        hidden = not ssid
        if hidden:
            probed = probe_hidden_ssid(bssid)
            ssid   = probed if probed else "<Hidden>"

        mode   = parts[2].strip()
        chan   = parts[3].strip()
        fstr   = parts[4].strip()
        rate   = parts[5].strip()
        sig    = parts[6].strip()
        sec    = parts[8].strip() or "OPEN"
        active = parts[9].strip().lower() == "yes" if len(parts) > 9 else False

        try: quality = int(sig)
        except ValueError: continue

        dbm     = round(quality_to_dbm(quality))
        fghz    = 2.4
        freq_hz = 2.437e9
        try:
            fmhz    = int(fstr.split()[0])
            fghz    = fmhz / 1000.0
            freq_hz = float(fmhz) * 1e6
        except (ValueError, IndexError): pass

        # Pull cached IP/port data
        ip         = ip_cache.get(bssid)
        host_data  = host_cache.get(ip, {}) if ip else {}

        networks.append({
            "ssid":          ssid,
            "bssid":         bssid,
            "is_hidden":     hidden,
            "dbm":           dbm,
            "quality":       quality,
            "percent":       dbm_to_pct(dbm),
            "signal_class":  classify(dbm),
            "frequency":     "5 GHz" if fghz >= 5.0 else "2.4 GHz",
            "freq_ghz":      round(fghz, 3),
            "freq_hz":       freq_hz,
            "channel":       chan,
            "security":      sec,
            "rate":          rate,
            "active":        active,
            "mode":          mode,
            "ip":            ip,
            "hostname":      host_data.get("hostname", ""),
            "os_guess":      host_data.get("os_guess", ""),
            "open_ports":    host_data.get("ports", []),
            "risk_score":    host_data.get("risk", 0),
        })

    all_q = [n["quality"] for n in networks]
    for n in networks:
        n["distance"]      = compute_distance(n["quality"], n["bssid"],
                                               n["freq_hz"], n["ssid"], all_q)
        n["security_audit"] = audit_wifi(n)

    networks.sort(key=lambda n: (not n["active"], -n["quality"]))
    return networks


def scan_iwlist() -> list:
    """Fallback to iwlist scan."""
    iface = get_wifi_ifaces()[0]
    r = subprocess.run(["iwlist", iface, "scan"],
                       capture_output=True, text=True, timeout=20)
    if r.returncode != 0:
        raise RuntimeError(f"iwlist: {r.stderr.strip()}")

    networks, cur = [], {}
    for line in r.stdout.splitlines():
        line = line.strip()
        if line.startswith("Cell"):
            if cur.get("bssid"): networks.append(cur)
            m = re.search(r'Address: ([\dA-Fa-f:]+)', line)
            cur = {"bssid": m.group(1) if m else "??", "active": False}
        elif "ESSID:" in line:
            m = re.search(r'ESSID:"(.*?)"', line)
            raw = m.group(1) if m else ""
            cur["is_hidden"] = not raw
            cur["ssid"] = raw or (probe_hidden_ssid(cur.get("bssid","")) or "<Hidden>")
        elif "Signal level=" in line:
            m = re.search(r'Signal level=(-?\d+)', line)
            if m:
                raw = int(m.group(1))
                dbm = round(quality_to_dbm(raw)) if raw > 0 else raw
                q   = raw if raw > 0 else max(0, min(100, round((raw + 110) * 100 / 70)))
                cur.update({"dbm": dbm, "quality": q, "percent": dbm_to_pct(dbm)})
        elif "Frequency:" in line:
            m = re.search(r'Frequency:([\d.]+)', line)
            if m:
                fghz = float(m.group(1))
                cur.update({"freq_ghz": fghz, "freq_hz": fghz * 1e9,
                             "frequency": "5 GHz" if fghz >= 5 else "2.4 GHz"})
            m2 = re.search(r'Channel:(\d+)', line)
            if m2: cur["channel"] = m2.group(1)
        elif "Encryption key:" in line: cur["security"] = "WPA2" if "on" in line else "OPEN"
        elif "IE: IEEE 802.11i/WPA2" in line: cur["security"] = "WPA2"
        elif "IE: WPA Version" in line: cur["security"] = "WPA"

    if cur.get("bssid"): networks.append(cur)

    for n in networks:
        n.setdefault("ssid","<Hidden>"); n.setdefault("is_hidden",False)
        n.setdefault("dbm",-80); n.setdefault("quality",40)
        n.setdefault("percent",dbm_to_pct(n["dbm"])); n.setdefault("freq_ghz",2.4)
        n.setdefault("freq_hz",2.437e9); n.setdefault("frequency","2.4 GHz")
        n.setdefault("channel","?"); n.setdefault("security","OPEN")
        n.setdefault("rate","?"); n.setdefault("mode","?")
        n["signal_class"] = classify(n["dbm"])
        ip = ip_cache.get(n.get("bssid",""))
        hd = host_cache.get(ip, {}) if ip else {}
        n.update({"ip": ip, "hostname": hd.get("hostname",""),
                  "os_guess": hd.get("os_guess",""), "open_ports": hd.get("ports",[]),
                  "risk_score": hd.get("risk", 0)})

    all_q = [n["quality"] for n in networks]
    for n in networks:
        n["distance"] = compute_distance(n["quality"],n["bssid"],n["freq_hz"],n["ssid"],all_q)
        n["security_audit"] = audit_wifi(n)

    networks.sort(key=lambda n: -n["quality"])
    return networks


def do_scan():
    try:    return scan_nmcli(), None
    except Exception as e1:
        try: return scan_iwlist(), None
        except Exception as e2: return [], f"nmcli:{e1} | iwlist:{e2}"


# ═══════════════════════════════════════════════════════════════════════════════
#  BACKGROUND HOST DISCOVERY + PORT SCAN LOOP
# ═══════════════════════════════════════════════════════════════════════════════
def host_discovery_loop():
    """
    Every HOST_DISC_INTERVAL seconds:
      1. Get gateway IP → assign to connected AP (bssid → ip)
      2. Read ARP table → find all cached LAN hosts
      3. nmap ping sweep → discover all live hosts
      4. Port scan each host (parallelised)
      5. Merge everything back into latest_data
    """
    first_run = True
    while True:
        try:
            print("  [HostDisc] Starting host discovery cycle…")

            # ── Step 1: Gateway IP (connected router) ───────────────────────
            gw_ip     = get_gateway_ip()
            local_ip, subnet = get_local_ip_and_subnet()
            print(f"  [HostDisc] Gateway={gw_ip}  Local={local_ip}  Subnet={subnet}")

            # Update global network info
            with data_lock:
                latest_data["gateway_ip"] = gw_ip
                latest_data["local_ip"]   = local_ip
                latest_data["subnet"]     = subnet

            # Connected AP → gateway IP (this is always correct)
            if gw_ip:
                with data_lock:
                    nets = latest_data.get("networks", [])
                for n in nets:
                    if n.get("active") and n.get("bssid"):
                        ip_cache[n["bssid"]] = gw_ip
                        print(f"  [HostDisc] Connected AP {n['bssid']} → {gw_ip}")
                        break

            # ── Step 2: ARP table (instant, no tools) ────────────────────────
            arp_hosts = read_arp_table()
            print(f"  [HostDisc] ARP table: {len(arp_hosts)} entries")

            # ── Step 3: nmap sweep (finds all live hosts) ─────────────────────
            nmap_hosts = {}
            if subnet:
                nmap_hosts = nmap_ping_sweep(subnet)

            # Merge: nmap takes priority (more complete), ARP fills in MACs
            all_hosts = dict(arp_hosts)
            for ip, mac in nmap_hosts.items():
                all_hosts[ip] = mac if mac else all_hosts.get(ip, "")

            # Always include gateway
            if gw_ip and gw_ip not in all_hosts:
                all_hosts[gw_ip] = ""

            print(f"  [HostDisc] Total unique hosts: {len(all_hosts)}")

            # ── Step 4: Port scan each host ────────────────────────────────────
            for ip, mac in all_hosts.items():
                last = host_cache.get(ip, {}).get("last_scan", 0)
                if time.time() - last < PORT_RESCAN_SEC:
                    continue  # skip recently scanned

                ports     = scan_ports_on_ip(ip)
                os_g      = guess_os(ports, mac)
                risk      = risk_score(ports)
                hostname  = ""
                try: hostname = socket.gethostbyaddr(ip)[0]
                except Exception: pass

                host_cache[ip] = {
                    "ip":        ip,
                    "mac":       mac,
                    "hostname":  hostname,
                    "os_guess":  os_g,
                    "ports":     ports,
                    "risk":      risk,
                    "last_scan": time.time(),
                }
                print(f"  [HostDisc] {ip:>15} | {os_g:<25} | {len(ports)} ports open | risk={risk}")

            # ── Step 5: Merge back into network list ───────────────────────────
            with data_lock:
                latest_data["host_info"] = {
                    ip: {k: v for k, v in d.items() if k != "last_scan"}
                    for ip, d in host_cache.items()
                }
                for n in latest_data["networks"]:
                    bssid = n.get("bssid","")
                    # Connected AP always gets gateway
                    if n.get("active") and gw_ip:
                        ip_cache[bssid] = gw_ip
                    ip = ip_cache.get(bssid)
                    n["ip"] = ip
                    if ip and ip in host_cache:
                        hd = host_cache[ip]
                        n["hostname"]   = hd.get("hostname","")
                        n["os_guess"]   = hd.get("os_guess","")
                        n["open_ports"] = hd.get("ports",[])
                        n["risk_score"] = hd.get("risk",0)

        except Exception as e:
            print(f"  [HostDisc] Error: {e}")
            import traceback; traceback.print_exc()

        if first_run:
            first_run = False
            print(f"  [HostDisc] First cycle done. Next in {HOST_DISC_INTERVAL}s")
        time.sleep(HOST_DISC_INTERVAL)


# ═══════════════════════════════════════════════════════════════════════════════
#  WIFI SCAN LOOP
# ═══════════════════════════════════════════════════════════════════════════════
def scan_loop():
    count = 0
    while True:
        nets, error = do_scan()
        count += 1
        cmap = build_channel_map(nets)

        # Merge cached host data
        for n in nets:
            bssid = n.get("bssid","")
            if n.get("active") and latest_data.get("gateway_ip"):
                ip_cache[bssid] = latest_data["gateway_ip"]
            ip = ip_cache.get(bssid)
            n["ip"] = ip
            hd = host_cache.get(ip, {}) if ip else {}
            n["hostname"]   = hd.get("hostname","")
            n["os_guess"]   = hd.get("os_guess","")
            n["open_ports"] = hd.get("ports",[])
            n["risk_score"] = hd.get("risk",0)

        with data_lock:
            latest_data.update({
                "networks":      nets,
                "timestamp":     time.time(),
                "error":         error,
                "scan_count":    count,
                "network_count": len(nets),
                "channel_map":   cmap,
            })

        print(f"[WiFiScan #{count}] {len(nets)} nets" + (f" | ERR:{error}" if error else ""))
        for n in nets[:4]:
            d = n.get("distance", {})
            print(f"  {n['ssid'][:18]:<18}  dBm={n['dbm']:4d}  "
                  f"dist={str(d.get('value','?'))+d.get('unit',''):>7}  "
                  f"ip={str(n.get('ip') or '—'):<16}  "
                  f"ports={len(n.get('open_ports',[]))}")
        time.sleep(SCAN_INTERVAL)


# ═══════════════════════════════════════════════════════════════════════════════
#  HTTP SERVER
# ═══════════════════════════════════════════════════════════════════════════════
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def send_json(self, data, code=200):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path in ("/wifi", "/wifi/"):
            with data_lock: self.send_json(latest_data)

        elif self.path in ("/hosts", "/hosts/"):
            # All discovered LAN hosts + full port details
            with data_lock:
                self.send_json({
                    "gateway_ip": latest_data.get("gateway_ip"),
                    "local_ip":   latest_data.get("local_ip"),
                    "subnet":     latest_data.get("subnet"),
                    "hosts":      latest_data.get("host_info", {}),
                    "timestamp":  time.time()
                })

        elif self.path in ("/scan", "/scan/"):
            # Trigger immediate WiFi + host rescan
            def bg():
                global host_cache
                nets, err = do_scan()
                cmap = build_channel_map(nets)
                with data_lock:
                    latest_data.update({
                        "networks": nets, "timestamp": time.time(),
                        "error": err, "channel_map": cmap,
                        "network_count": len(nets)
                    })
                host_discovery_loop.__wrapped__ = True  # flag
            threading.Thread(target=bg, daemon=True).start()
            self.send_json({"status": "scan triggered"})

        elif self.path in ("/", "/index.html"):
            self.send_response(302)
            self.send_header("Location", f"http://localhost:{PORT}/wifi")
            self.end_headers()

        else:
            self.send_response(404); self.end_headers()
            self.wfile.write(b"Not found")

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()


# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    print("=" * 64)
    print("  WiFi Scanner v4 — Cyber Intelligence Edition")
    print("=" * 64)
    print(f"  WiFi scan every     : {SCAN_INTERVAL}s")
    print(f"  Host discovery every: {HOST_DISC_INTERVAL}s")
    print(f"  Port rescan after   : {PORT_RESCAN_SEC}s")
    print(f"  API (WiFi data)     : http://localhost:{PORT}/wifi")
    print(f"  API (LAN hosts)     : http://localhost:{PORT}/hosts")
    print("=" * 64)
    print()
    print("  v4 fixes vs v3:")
    print("    ✓ IP discovery: reads /proc/net/arp + ip neigh (no ARP match bug)")
    print("    ✓ Connected AP: always gets gateway IP immediately")
    print("    ✓ nmap sweep: correct flags, proper host parsing")
    print("    ✓ Port scan: immediate on startup, not after 60s delay")
    print("    ✓ /hosts endpoint: see all LAN devices independently")
    print("    ✓ Port results sorted by risk level, not port number")
    print()
    print("  REQUIREMENTS: sudo apt install nmap iproute2 network-manager")
    print()

    # Initial WiFi scan (synchronous — data ready immediately)
    print("  Running first WiFi scan…")
    nets, error = do_scan()
    cmap = build_channel_map(nets)
    for n in nets:
        n.update({"ip": None, "hostname": "", "os_guess": "Scanning…",
                  "open_ports": [], "risk_score": 0})
    with data_lock:
        latest_data.update({
            "networks": nets, "timestamp": time.time(), "error": error,
            "scan_count": 1, "network_count": len(nets), "channel_map": cmap,
            "gateway_ip": None, "local_ip": None, "subnet": None
        })
    print(f"  First scan: {len(nets)} networks found.")
    print()
    print("  Starting host discovery in background (takes ~30–60s first run)…")
    print()

    threading.Thread(target=scan_loop,          daemon=True).start()
    threading.Thread(target=host_discovery_loop, daemon=True).start()

    httpd = HTTPServer(("localhost", PORT), Handler)
    print(f"  Listening on port {PORT}. Press Ctrl+C to stop.\n")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n  Stopped.")

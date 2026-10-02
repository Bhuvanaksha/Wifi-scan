# 📡 NetScan v4 — WiFi Cyber Intelligence

A real-time WiFi scanner with a live browser dashboard. It discovers nearby
access points, estimates physical distance using an LDPL-v2 signal propagation
model, resolves the connected router's IP, sweeps the LAN for live hosts, and
port-scans each device with risk classification.

![Status](https://img.shields.io/badge/status-active-brightgreen)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey)

---

## ✨ Features

- **Live radar sweep** — animated canvas radar plotting detected APs by signal class
- **Distance estimation** — LDPL-v2 propagation model with exponential smoothing and confidence scoring
- **Signal history** — per-network sparkline chart tracking dBm over time
- **Hidden SSID probing** — attempts SSID recovery via NetworkManager history and `iw scan`
- **LAN host discovery** — `nmap -sn` ping sweep combined with `/proc/net/arp` and `ip neigh`
- **Port scanning** — 40 common ports with banner grabbing, sorted by risk tier
- **Risk scoring** — per-host 0–100 score based on open port severity
- **Security audit** — per-network findings (WEP, open networks, default SSIDs, WPA2-PMKID exposure)
- **Channel congestion map** — visualises how many networks share each channel
- **Zero-dependency frontend** — a single HTML file, no build step, no npm
- **Auto-refresh** — WiFi every 15s, host discovery every 45s, port rescan every 90s

---

## 🧠 How IP Discovery Works (the v4 fix)

Earlier versions tried to match an AP's **BSSID** (its wireless radio MAC)
against the **ARP table**. This never works — an AP's WiFi interface MAC is
completely different from its LAN/gateway MAC address.

v4 uses the correct approach:

1. **Gateway IP** — read the connected router's management IP from `ip route show default`
2. **ARP + neighbours** — parse `/proc/net/arp` and `ip neigh show` for recently contacted LAN hosts
3. **nmap sweep** — `nmap -sn <subnet>` discovers every live host on the subnet
4. **Port scan** — runs against the gateway and all discovered hosts
5. **Connected AP** — always assigned the gateway IP, which is 100% reliable

---

## 📦 Requirements

**Python:** 3.10 or newer (the code uses `str | None` union syntax)

**System packages (Debian / Ubuntu):**

```bash
sudo apt install network-manager nmap iproute2 python3
```

**Python packages:** none — everything used is in the standard library.

---

## 🚀 Usage

### 1. Start the backend

Root is required for nmap's ARP-based host discovery:

```bash
sudo python3 server_v4.py
```

You'll see a startup banner, an initial WiFi scan, and the first host-discovery
cycle (which takes roughly 30–60 seconds).

### 2. Open the dashboard

Open `index.html` directly in your browser:

```bash
xdg-open index.html
```

The dashboard polls the local API and updates live.

### 3. Stop the server

Press `Ctrl + C` in the terminal running the Python script.

---

## 🌐 API Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/wifi` | Full WiFi scan data — networks, distances, security audits, channel map |
| `GET` | `/hosts` | All discovered LAN hosts with ports, OS guesses, and risk scores |
| `GET` | `/scan` | Trigger an immediate WiFi rescan in the background |

Example:

```bash
curl http://localhost:8765/wifi | python3 -m json.tool
```

---

## ⚙️ Configuration

Edit the constants at the top of `server_v4.py`:

| Constant | Default | Meaning |
| :--- | :--- | :--- |
| `PORT` | `8765` | HTTP API port |
| `SCAN_INTERVAL` | `15` | Seconds between WiFi scans |
| `HOST_DISC_INTERVAL` | `45` | Seconds between LAN host discovery cycles |
| `PORT_RESCAN_SEC` | `90` | Cooldown before re-scanning a host's ports |
| `CALIBRATION_FACTOR` | `1.0` | Multiplier applied to distance estimates |
| `HISTORY_LEN` | `8` | Signal samples kept per network for smoothing |

**Tuning distance accuracy:** if estimates feel consistently too high or too
low, adjust `CALIBRATION_FACTOR`. Values below `1.0` shorten distances, above
`1.0` lengthen them.

---

## 🗂️ Project Structure

```
netscan-wifi/
├── server_v4.py           # Backend: scanning, analysis, HTTP API
├── index.html    # Frontend: live dashboard (single file)
├── requirements.txt            # Python deps (none)
├── LICENSE                     # MIT
├── README.md                   # This file
└── .gitignore
```

---

## 🔍 Port Risk Tiers

Ports are classified by the severity of exposure if left open:

| Tier | Examples | Meaning |
| :--- | :--- | :--- |
| **CRITICAL** | `23` Telnet, `161` SNMP, `445` SMB, `5555` ADB, `7547` TR-069 | Immediate compromise risk |
| **HIGH** | `21` FTP, `139` NetBIOS, `3306` MySQL, `3389` RDP, `5900` VNC | Serious exposure, brute-force target |
| **MEDIUM** | `22` SSH, `80` HTTP, `1883` MQTT-adjacent services | Needs hardening |
| **LOW** | `443` HTTPS, `993` IMAPS, `51820` WireGuard | Generally expected |

The per-host **risk score** (0–100) adds 30 points per CRITICAL port, 15 per
HIGH, 5 per MEDIUM, and 1 per LOW, capped at 100.

---

## 🛠️ Troubleshooting

| Problem | Fix |
| :--- | :--- |
| Dashboard shows **"WAITING FOR SERVER"** | Backend isn't running, or not on port 8765 |
| **`nmcli: command not found`** | `sudo apt install network-manager` |
| **nmap finds 0 hosts** | Make sure you're running as root — ARP discovery needs it |
| **No IP shown for networks** | Normal for APs you aren't connected to; only your own router's IP is discoverable |
| **Distance estimates look wrong** | Adjust `CALIBRATION_FACTOR` (see Configuration) |
| **Port scan is slow on first run** | It scans every discovered host; subsequent cycles use the 90s cooldown |

---

## ⚠️ Ethical Use

This tool is intended for **auditing networks you own or have explicit written
permission to test**. Port scanning and host discovery against networks you do
not control is illegal in many jurisdictions, including under India's IT Act
and the UK's Computer Misuse Act.

Use it on your own home network, in a lab you control, or in a sanctioned
penetration test with a signed scope document. Nothing else.

The author takes no responsibility for misuse.

---

## 🗺️ Roadmap

- [ ] Export scan results to JSON / CSV
- [ ] Historical signal logging to SQLite
- [ ] Dark theme for the dashboard
- [ ] Optional auth token on the API
- [ ] Support for 6 GHz channel reporting

---

## 📄 License

MIT — see [LICENSE](LICENSE) for the full text.

---

## 🙏 Acknowledgements

- Distance model inspired by the Log-Distance Path Loss (LDPL) model
- Port risk tiers informed by common SANS / CIS benchmarks
- Built with the Python standard library, `nmap`, and `iproute2`

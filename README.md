# 🎯 c2-hunter: Cross-Platform C2 Beaconing Detection Tool

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](https://github.com/)

```text
 ██████╗██████╗     ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
██╔════╝╚════██╗    ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
██║      █████╔╝    ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
██║     ██╔═══╝     ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
╚██████╗███████╗    ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
 ╚═════╝╚══════╝    ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
           Cross-Platform C2 Beaconing Detection Engine v1.0
```

---

## 📋 Overview

**`c2-hunter`** is a high-performance, cross-platform Command-Line cybersecurity tool engineered to detect **Command & Control (C2) beaconing activity** in network traffic. 

Malware and C2 agents (such as Cobalt Strike, Sliver, or custom RATs) regularly contact their external C2 servers using periodic heartbeat requests. **`c2-hunter`** extracts packet timestamps, groups network traffic into unique session flows, and performs statistical interval variance analysis to uncover hidden C2 communication channels.

---

## 🏗️ Architecture

```
                    ┌─────────────────────────┐
                    │ PCAP File / Live Sniff  │
                    └────────────┬────────────┘
                                 │
                                 ▼
                     ┌──────────────────────┐
                     │ Scapy Packet Parser  │ (Extract IP, Port, Timestamp, DNS/HTTP/TLS)
                     └───────────┬──────────┘
                                 │
                                 ▼
                     ┌──────────────────────┐
                     │ Session Flow Grouper │ (Group by tuple: src_ip, dst_ip, dst_port)
                     └───────────┬──────────┘
                                 │
                                 ▼
                    ┌────────────────────────┐
                    │ Beacon Detection Engine│ (Delta t, Mean, StdDev, Variance, MAD, Jitter %)
                    └────────────┬───────────┘
                                 │
                                 ▼
              ┌──────────────────┴──────────────────┐
              │                                     │
              ▼                                     ▼
   ┌──────────────────────┐              ┌──────────────────────┐
   │ Rich TUI CLI Table   │              │ Exporters (JSON/CSV) │
   └──────────────────────┘              └──────────────────────┘
```

---

## 🧮 Mathematical Detection Logic

For each network session flow defined by `(src_ip, dst_ip, dst_port)` with timestamps $t_1, t_2, \dots, t_N$:

1. **Inter-Arrival Time Interval ($\Delta t_i$):**
   $$\Delta t_i = t_{i+1} - t_i \quad \text{for } i = 1, 2, \dots, N-1$$

2. **Mean Interval ($\mu$):**
   $$\mu = \frac{1}{N-1} \sum_{i=1}^{N-1} \Delta t_i$$

3. **Standard Deviation ($\sigma$) & Variance ($\sigma^2$):**
   $$\sigma = \sqrt{\frac{1}{N-2} \sum_{i=1}^{N-1} (\Delta t_i - \mu)^2}$$

4. **Median Absolute Deviation ($\text{MAD}$):**
   $$\text{MAD} = \text{median}(|\Delta t_i - \text{median}(\Delta t)|)$$

5. **Jitter Percentage:**
   $$\text{Jitter \%} = \left(\frac{\sigma}{\mu}\right) \times 100$$

6. **Beaconing Decision rule:**
   If $\text{Jitter \%} \le \text{Threshold}$ and total connections $> 5$, the flow is flagged as **C2 Beaconing Activity** with a threat score between `0.0` and `1.0`.

---

## ⚙️ Installation Guide

### Prerequisites
- **Python 3.8+**
- Windows: Install [Npcap](https://npcap.com/) for live interface packet capturing.
- Linux: Root/sudo access for live packet sniffing (`libpcap-dev`).

### Step-by-Step Setup

1. **Clone or Download the Repository:**
   ```bash
   git clone https://github.com/your-org/c2-hunter.git
   cd c2-hunter
   ```

2. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Install `c2-hunter` package in editable mode (Optional):**
   ```bash
   pip install -e .
   ```

---

## 🚀 Usage Examples

### 💻 Windows (PowerShell / CMD)

**1. Analyze an Offline PCAP file:**
```powershell
python -m c2_hunter.main -f "C:\Captures\malware_traffic.pcap" -j 15.0 -o console
```

**2. Analyze PCAP and Export to JSON:**
```powershell
python -m c2_hunter.main -f "C:\Captures\traffic.pcapng" -o json -of "C:\Reports\c2_analysis.json"
```

**3. Live Packet Sniffing (Requires Administrator PowerShell):**
```powershell
# Run PowerShell as Administrator
python -m c2_hunter.main -i "Ethernet" -j 10.0 -c 500 -o csv -of "live_report.csv"
```

---

### 🐧 Linux / macOS (Bash)

**1. Analyze PCAP file:**
```bash
python3 -m c2_hunter.main -f /var/log/pcaps/suspicious.pcap -j 15.0
```

**2. Live Interface Sniffing (Requires `sudo`):**
```bash
sudo python3 -m c2_hunter.main -i eth0 -j 12.0 -o console
```

**3. Export Analysis to CSV:**
```bash
python3 -m c2_hunter.main -f capture.pcap -o csv -of /tmp/c2_report.csv
```

---

## 🛠️ Command-Line Arguments Reference

| Argument | Short | Description | Default |
| :--- | :--- | :--- | :--- |
| `--file` | `-f` | Path to input PCAP / PCAPNG packet capture file | None |
| `--interface` | `-i` | Name of live network interface for sniffing | None |
| `--jitter` | `-j` | Jitter threshold percentage for beaconing detection | `15.0` |
| `--output` | `-o` | Output presentation format (`console`, `json`, `csv`) | `console` |
| `--output-file`| `-of` | Destination file path for JSON or CSV exports | None |
| `--count` | `-c` | Maximum packets to capture live (`0` = continuous) | `0` |

---

## 📄 License

Distributed under the **MIT License**. See `LICENSE` for more information.

"""
parser.py - Scapy Network & Packet Parser Module for c2-hunter.
Extracts network metadata (IP, Port, Timestamps, Domains) and groups into session flows.
"""

import sys
import os
import re
from typing import Dict, List, Any, Tuple
from pathlib import Path
from rich.console import Console

console = Console(force_terminal=True)

try:
    from scapy.all import rdpcap, sniff, IP, IPv6, TCP, UDP, DNS, DNSQR, DNSRR, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def extract_domain_from_packet(packet) -> str:
    """
    Attempts to extract Domain Name from DNS, HTTP, or TLS SNI in packet payload.
    """
    domain = None

    # 1. Check DNS Query / Response
    if packet.haslayer(DNS):
        if packet.haslayer(DNSQR) and packet[DNSQR].qname:
            try:
                domain = packet[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
            except Exception:
                pass
        elif packet.haslayer(DNSRR) and packet[DNSRR].rrname:
            try:
                domain = packet[DNSRR].rrname.decode("utf-8", errors="ignore").rstrip(".")
            except Exception:
                pass

    # 2. Check HTTP Host header in payload
    if not domain and packet.haslayer(Raw):
        try:
            payload = packet[Raw].load.decode("utf-8", errors="ignore")
            host_match = re.search(r"Host:\s*([^\r\n:]+)", payload, re.IGNORECASE)
            if host_match:
                domain = host_match.group(1).strip()
        except Exception:
            pass

    # 3. Check TLS SNI (Server Name Indication) in raw payload
    if not domain and packet.haslayer(Raw) and packet.haslayer(TCP):
        try:
            payload = packet[Raw].load
            # TLS Client Hello handshake (0x16, 0x03)
            if len(payload) > 5 and payload[0] == 0x16 and payload[1] == 0x03:
                sni_match = re.search(rb"([a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,})", payload)
                if sni_match:
                    possible_domain = sni_match.group(1).decode("ascii", errors="ignore")
                    if "." in possible_domain and not possible_domain.endswith("."):
                        domain = possible_domain
        except Exception:
            pass

    return domain


def process_packet(packet, ip_domain_map: Dict[str, str], session_flows: Dict[Tuple[str, str, int], Dict[str, Any]]):
    """
    Processes a single Scapy packet and updates IP domain mappings and session flows.
    """
    # Extract IP layer
    src_ip, dst_ip = None, None
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
    elif packet.haslayer(IPv6):
        src_ip = packet[IPv6].src
        dst_ip = packet[IPv6].dst

    if not src_ip or not dst_ip:
        return

    timestamp = float(packet.time)

    # Extract transport layer (TCP / UDP)
    dst_port = 0
    protocol = "OTHER"
    if packet.haslayer(TCP):
        dst_port = packet[TCP].dport
        protocol = "TCP"
    elif packet.haslayer(UDP):
        dst_port = packet[UDP].dport
        protocol = "UDP"
    else:
        return

    # Extract domain if present
    extracted_domain = extract_domain_from_packet(packet)
    if extracted_domain:
        ip_domain_map[dst_ip] = extracted_domain
        ip_domain_map[src_ip] = extracted_domain

    # Define session flow key: (src_ip, dst_ip, dst_port)
    flow_key = (src_ip, dst_ip, dst_port)

    if flow_key not in session_flows:
        session_flows[flow_key] = {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "protocol": protocol,
            "timestamps": [],
            "domains": set()
        }

    session_flows[flow_key]["timestamps"].append(timestamp)

    # Attach domain if resolved or previously mapped
    if extracted_domain:
        session_flows[flow_key]["domains"].add(extracted_domain)
    elif dst_ip in ip_domain_map:
        session_flows[flow_key]["domains"].add(ip_domain_map[dst_ip])


def parse_pcap(file_path: Path) -> Dict[Tuple[str, str, int], Dict[str, Any]]:
    """
    Reads a PCAP file cross-platform and extracts grouped session flows.
    
    Args:
        file_path (Path): Path to the PCAP / PCAPNG file.
        
    Returns:
        Dict: Dictionary of session flows with timestamp arrays and metadata.
    """
    if not SCAPY_AVAILABLE:
        raise ImportError("Scapy library is required for PCAP parsing. Install via 'pip install scapy'.")

    if not file_path.exists():
        raise FileNotFoundError(f"PCAP file not found at path: '{file_path}'")

    console.print(f"[bold blue][*] Reading PCAP file:[/bold blue] [yellow]{file_path}[/yellow]")
    try:
        packets = rdpcap(str(file_path))
    except Exception as e:
        raise ValueError(f"Failed to read PCAP file '{file_path}': {e}")

    console.print(f"[bold green][+] Loaded {len(packets)} packets.[/bold green]")

    ip_domain_map: Dict[str, str] = {}
    session_flows: Dict[Tuple[str, str, int], Dict[str, Any]] = {}

    for pkt in packets:
        process_packet(pkt, ip_domain_map, session_flows)

    # Sort timestamps in each session flow chronologically
    for flow in session_flows.values():
        flow["timestamps"].sort()

    return session_flows


def parse_live(interface: str, packet_count: int = 0) -> Dict[Tuple[str, str, int], Dict[str, Any]]:
    """
    Sniffs live network traffic on the specified interface.
    
    Args:
        interface (str): Interface name (e.g. 'eth0', 'Wi-Fi').
        packet_count (int): Number of packets to capture (0 = continuous until Ctrl+C).
        
    Returns:
        Dict: Dictionary of session flows.
    """
    if not SCAPY_AVAILABLE:
        raise ImportError("Scapy library is required for live network capture. Install via 'pip install scapy'.")

    console.print(f"[bold blue][*] Listening live on interface:[/bold blue] [yellow]{interface}[/yellow]")
    if packet_count > 0:
        console.print(f"[cyan][*] Sniffing up to {packet_count} packets...[/cyan]")
    else:
        console.print("[cyan][*] Sniffing continuously. Press Ctrl+C to stop capture and analyze...[/cyan]")

    ip_domain_map: Dict[str, str] = {}
    session_flows: Dict[Tuple[str, str, int], Dict[str, Any]] = {}

    def packet_callback(pkt):
        process_packet(pkt, ip_domain_map, session_flows)

    try:
        sniff(iface=interface, prn=packet_callback, count=packet_count, store=False)
    except PermissionError:
        raise PermissionError("Permission denied for live packet capture. Please run as Administrator (Windows) or root/sudo (Linux).")
    except Exception as e:
        raise RuntimeError(f"Error during live capture on interface '{interface}': {e}")

    # Sort timestamps chronologically
    for flow in session_flows.values():
        flow["timestamps"].sort()

    return session_flows

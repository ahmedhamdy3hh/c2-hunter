"""
reporter.py - Rich TUI & Exporter Module for c2-hunter.
Renders interactive CLI tables and exports detection data to JSON or CSV files.
"""

import sys
import json
import csv
from pathlib import Path
from typing import List, Dict, Any

# Force UTF-8 reconfiguration for Windows console
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console(force_terminal=True)


def format_target(ip: str, domain: str) -> str:
    """Combines Target IP and Domain into a clean display string."""
    if domain:
        return f"{ip} ({domain})"
    return ip


def display_results(detections: List[Dict[str, Any]], jitter_threshold: float = 15.0):
    """
    Renders a stylized Rich CLI table showing C2 beaconing detection results.

    Args:
        detections (List[Dict[str, Any]]): List of detection dictionaries.
        jitter_threshold (float): Jitter threshold used during detection.
    """
    table = Table(
        title="[bold red]C2 Beaconing Detection Analysis Report[/bold red]",
        title_justify="center",
        show_header=True,
        header_style="bold magenta",
        expand=True
    )

    table.add_column("Severity", justify="center", style="bold")
    table.add_column("Target C2 IP / Domain", justify="left")
    table.add_column("Dst Port", justify="center")
    table.add_column("Connections", justify="right")
    table.add_column("Mean Interval (s)", justify="right")
    table.add_column("Jitter Score (%)", justify="right")
    table.add_column("Threat Score", justify="center")

    total_flows = len(detections)
    detected_beacons = 0

    # Sort detections by threat score descending
    sorted_detections = sorted(detections, key=lambda d: d.get("threat_score", 0.0), reverse=True)

    for item in sorted_detections:
        severity = item.get("severity", "Low")
        is_beacon = item.get("is_beacon", False)
        
        if is_beacon:
            detected_beacons += 1

        # Color coding: High -> Red, Medium -> Yellow, Low -> Green
        if severity == "High":
            sev_style = "[bold red]HIGH[/bold red]"
        elif severity == "Medium":
            sev_style = "[bold yellow]MEDIUM[/bold yellow]"
        else:
            sev_style = "[bold green]LOW[/bold green]"

        dst_ip = item.get("dst_ip", "0.0.0.0")
        domain = item.get("domain", "")
        target_str = format_target(dst_ip, domain)

        dst_port = str(item.get("dst_port", 0))
        conn_count = str(item.get("connection_count", 0))
        mean_int = f"{item.get('mean_interval', 0.0):.3f}"
        jitter = f"{item.get('jitter', 0.0):.2f}%"
        threat_score = f"{item.get('threat_score', 0.0):.2f}"

        table.add_row(
            sev_style,
            target_str,
            dst_port,
            conn_count,
            mean_int,
            jitter,
            threat_score
        )

    console.print("\n")
    console.print(table)

    # Display Summary Panel
    summary_text = (
        f"[bold white]Total Network Sessions Analyzed:[/bold white] {total_flows}\n"
        f"[bold red]Flagged C2 Beaconing Targets:[/bold red] {detected_beacons}\n"
        f"[bold yellow]Configured Jitter Threshold:[/bold yellow] {jitter_threshold}%\n"
    )
    
    if detected_beacons > 0:
        summary_panel = Panel(
            summary_text,
            title="[bold red]THREAT SUMMARY WARNING[/bold red]",
            border_style="red"
        )
    else:
        summary_panel = Panel(
            summary_text + "\n[bold green]No active C2 beaconing signatures identified.[/bold green]",
            title="[bold green]SECURITY STATUS CLEAN[/bold green]",
            border_style="green"
        )

    console.print(summary_panel)


def export_json(detections: List[Dict[str, Any]], file_path: Path):
    """
    Exports detection results to a formatted JSON file.
    """
    file_path = Path(file_path).resolve()
    file_path.parent.mkdir(parents=True, exist_ok=True)

    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(detections, f, indent=4)

    console.print(f"[bold green][+] Successfully exported JSON report to:[/bold green] [yellow]{file_path}[/yellow]")


def export_csv(detections: List[Dict[str, Any]], file_path: Path):
    """
    Exports detection results to a CSV file.
    """
    file_path = Path(file_path).resolve()
    file_path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "src_ip", "dst_ip", "dst_port", "domain", "protocol",
        "severity", "is_beacon", "threat_score", "connection_count",
        "mean_interval", "std_dev", "variance", "mad", "jitter", "reason"
    ]

    with open(file_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for d in detections:
            row = {
                "src_ip": d.get("src_ip", ""),
                "dst_ip": d.get("dst_ip", ""),
                "dst_port": d.get("dst_port", 0),
                "domain": d.get("domain", ""),
                "protocol": d.get("protocol", ""),
                "severity": d.get("severity", "Low"),
                "is_beacon": d.get("is_beacon", False),
                "threat_score": d.get("threat_score", 0.0),
                "connection_count": d.get("connection_count", 0),
                "mean_interval": d.get("mean_interval", 0.0),
                "std_dev": d.get("std_dev", 0.0),
                "variance": d.get("variance", 0.0),
                "mad": d.get("mad", 0.0),
                "jitter": d.get("jitter", 0.0),
                "reason": d.get("reason", "")
            }
            writer.writerow(row)

    console.print(f"[bold green][+] Successfully exported CSV report to:[/bold green] [yellow]{file_path}[/yellow]")

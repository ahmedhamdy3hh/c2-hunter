"""
main.py - Integration Entrypoint for c2-hunter CLI Cybersecurity Tool.
Ties cli, parser, detector, and reporter modules together with graceful error handling.
"""

import sys
import os
from pathlib import Path

# Force UTF-8 stream reconfiguration for Windows terminals
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Add parent directory to sys.path if needed when executed directly
current_dir = Path(__file__).resolve().parent
parent_dir = current_dir.parent
if str(parent_dir) not in sys.path:
    sys.path.insert(0, str(parent_dir))

from c2_hunter.cli import parse_arguments, display_banner
from c2_hunter.parser import parse_pcap, parse_live
from c2_hunter.detector import BeaconDetector
from c2_hunter.reporter import display_results, export_json, export_csv

from rich.console import Console

console = Console(force_terminal=True)


def main():
    """Main program execution flow."""
    display_banner()

    try:
        args = parse_arguments()

        # Step 1: Network Packet Parsing
        session_flows = {}
        if args.file_path:
            session_flows = parse_pcap(args.file_path)
        elif args.interface:
            session_flows = parse_live(args.interface, packet_count=args.count)

        if not session_flows:
            console.print("[bold yellow][!] No valid TCP/UDP network session flows were captured or found.[/bold yellow]")
            sys.exit(0)

        # Step 2: Mathematical Beacon Detection
        console.print(f"[bold blue][*] Running Beaconing Detection Engine (Jitter Threshold: {args.jitter}%)...[/bold blue]")
        detector = BeaconDetector(jitter_threshold=args.jitter)
        detections = []

        for flow_key, flow in session_flows.items():
            src_ip, dst_ip, dst_port = flow_key
            timestamps = flow.get("timestamps", [])
            domains = list(flow.get("domains", []))
            primary_domain = domains[0] if domains else ""

            stats = detector.analyze_timestamps(timestamps)

            detection_entry = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "domain": primary_domain,
                "protocol": flow.get("protocol", "TCP"),
                **stats
            }
            detections.append(detection_entry)

        # Step 3: Display TUI Table Report
        display_results(detections, jitter_threshold=args.jitter)

        # Step 4: Export logic
        if args.output == "json" or (args.output_file_path and args.output_file_path.suffix == ".json"):
            target_file = args.output_file_path or Path("c2_report.json")
            export_json(detections, target_file)

        elif args.output == "csv" or (args.output_file_path and args.output_file_path.suffix == ".csv"):
            target_file = args.output_file_path or Path("c2_report.csv")
            export_csv(detections, target_file)

    except FileNotFoundError as e:
        console.print(f"\n[bold red][ERROR] File Not Found:[/bold red] {e}")
        sys.exit(1)

    except PermissionError as e:
        console.print(f"\n[bold red][ERROR] Permission Denied:[/bold red] {e}")
        console.print("[yellow][i] Hint: Live capture requires elevated privileges. Run with Administrator rights on Windows or sudo on Linux.[/yellow]")
        sys.exit(1)

    except KeyboardInterrupt:
        console.print("\n[bold yellow][!] Operation cancelled by user (Ctrl+C). Exiting safely.[/bold yellow]")
        sys.exit(0)

    except Exception as e:
        console.print(f"\n[bold red][CRITICAL ERROR]:[/bold red] {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

"""
cli.py - Command-Line Interface module for c2-hunter.
Handles argument parsing, path normalization, and rich help displays.
"""

import sys
import os
import argparse
from pathlib import Path

# Ensure UTF-8 output encoding for legacy Windows terminals
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from rich.console import Console
from rich.panel import Panel
from c2_hunter import __version__

console = Console(force_terminal=True)

BANNER = r"""
 [bold red]  ____ ___    _   _  ____  _  _ _____ _____ _____ ____  [/bold red]
 [bold red] / ___|___ \ | | | ||  _ \| || || ____|_   _| ____|  _ \ [/bold red]
 [bold yellow]| |     __) || |_| || |_| | || ||  _|   | | |  _| | |_) |[/bold yellow]
 [bold yellow]| |___ / __/ |  _  ||  _ <|__   _| |___  | | | |___|  _ < [/bold yellow]
 [bold green] \____|_____||_| |_||_| \_\  |_| |_____| |_| |_____|_| \_\[/bold green]
 [bold cyan]           Cross-Platform C2 Beaconing Detection Engine v1.0         [/bold cyan]
"""


class RichArgumentParser(argparse.ArgumentParser):
    """Custom ArgumentParser providing rich-formatted help messages."""
    
    def print_help(self, file=None):
        console.print(BANNER)
        super().print_help(file)


def display_banner():
    """Prints the application banner to the terminal."""
    console.print(BANNER)


def parse_arguments(args=None):
    """
    Parses command-line arguments cross-platform.
    
    Returns:
        argparse.Namespace: Parsed CLI options.
    """
    parser = RichArgumentParser(
        prog="c2-hunter",
        description="c2-hunter - Detect Command & Control (C2) beaconing traffic from PCAP files or live network capture.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        "-f", "--file",
        type=str,
        help="Path to input PCAP or PCAPNG packet capture file."
    )
    input_group.add_argument(
        "-i", "--interface",
        type=str,
        help="Name of live network interface for packet sniffing (e.g. eth0, Wi-Fi, Ethernet)."
    )

    parser.add_argument(
        "-j", "--jitter",
        type=float,
        default=15.0,
        help="Jitter threshold percentage for beaconing detection (default: 15.0%%)."
    )

    parser.add_argument(
        "-o", "--output",
        choices=["console", "json", "csv"],
        default="console",
        help="Output presentation format."
    )

    parser.add_argument(
        "-of", "--output-file",
        type=str,
        default=None,
        help="Destination file path for JSON or CSV exports (optional)."
    )

    parser.add_argument(
        "-c", "--count",
        type=int,
        default=0,
        help="Maximum packet count for live capture (0 = continuous capture until Ctrl+C)."
    )

    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"c2-hunter v{__version__}",
        help="Show program's version number and exit."
    )

    parsed_args = parser.parse_args(args)

    # Normalize file paths cross-platform using pathlib
    if parsed_args.file:
        parsed_args.file_path = Path(parsed_args.file).resolve()
    else:
        parsed_args.file_path = None

    if parsed_args.output_file:
        parsed_args.output_file_path = Path(parsed_args.output_file).resolve()
    else:
        parsed_args.output_file_path = None

    return parsed_args


if __name__ == "__main__":
    display_banner()
    opts = parse_arguments()
    console.print(f"[green]Parsed Arguments:[/green] {opts}")

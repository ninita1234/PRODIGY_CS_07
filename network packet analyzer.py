#!/usr/bin/env python3
"""
packet_sniffer.py

Educational packet sniffer using Scapy.

Run with root/administrator privileges on most systems.

Authors: educational example only.
"""

import argparse
import sys
import time
from datetime import datetime

# Try to import scapy
try:
    from scapy.all import (
        sniff,
        IP,
        IPv6,
        TCP,
        UDP,
        ICMP,
        ARP,
        Ether,
        Raw,
        wrpcap,
        conf,
    )
except Exception as e:
    sys.exit(
        "Scapy is required. Install with: pip install scapy\nImport error: {}\n".format(e)
    )


def hexdump_preview(payload_bytes: bytes, length: int = 64) -> str:
    """Return a compact hex + ASCII preview of payload bytes (up to length)."""
    if not payload_bytes:
        return ""
    snippet = payload_bytes[:length]
    hexpart = " ".join(f"{b:02x}" for b in snippet)
    # ASCII: printable bytes or dot
    asciipart = "".join((chr(b) if 32 <= b < 127 else ".") for b in snippet)
    if len(payload_bytes) > length:
        hexpart += " .."
        asciipart += ".."
    return f"HEX: {hexpart}\nASCII: {asciipart}"


def summarize_packet(pkt) -> str:
    """Create a human-readable single string summary for a packet."""
    ts = datetime.fromtimestamp(pkt.time).isoformat(sep=" ", timespec="seconds")

    # Link layer
    link_src = link_dst = None
    if Ether in pkt:
        link_src = pkt[Ether].src
        link_dst = pkt[Ether].dst

    # Network layer
    proto = "OTHER"
    src = dst = ""
    sport = dport = None
    payload = b""

    if IP in pkt:
        ip = pkt[IP]
        src = ip.src
        dst = ip.dst
        if TCP in pkt:
            proto = "TCP"
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
        elif UDP in pkt:
            proto = "UDP"
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
        elif ICMP in pkt:
            proto = "ICMP"
        else:
            proto = f"IP/{ip.proto}"
    elif IPv6 in pkt:
        ip6 = pkt[IPv6]
        src = ip6.src
        dst = ip6.dst
        if TCP in pkt:
            proto = "TCP"
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
        elif UDP in pkt:
            proto = "UDP"
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
        elif ICMP in pkt:
            proto = "ICMPv6"
        else:
            proto = "IPv6"
    elif ARP in pkt:
        arp = pkt[ARP]
        proto = "ARP"
        src = arp.psrc
        dst = arp.pdst
    else:
        # fallback to link layer info
        proto = pkt.name
        if link_src:
            src = link_src
            dst = link_dst

    # payload extraction
    if Raw in pkt:
        payload = bytes(pkt[Raw])

    # Build summary lines
    addr_part = f"{src} -> {dst}" if src and dst else f"{link_src} -> {link_dst}"
    ports_part = f"{sport}->{dport}" if sport or dport else ""
    payload_preview = hexdump_preview(payload, length=80) if payload else "(no payload)"

    summary = (
        f"[{ts}] {proto} {addr_part}"
        + (f" [{ports_part}]" if ports_part else "")
        + f"\n{payload_preview}\n"
        + "-" * 80
    )
    return summary


def on_packet(pkt):
    """Callback invoked for each captured packet."""
    try:
        print(summarize_packet(pkt))
    except Exception as e:
        # Do not crash the sniffer because of a formatting error
        print(f"[!] Error summarizing packet: {e}")


def main():
    parser = argparse.ArgumentParser(description="Educational packet sniffer (Scapy).")
    parser.add_argument(
        "--iface",
        "-i",
        default=None,
        help="Interface to listen on (default: Scapy's default).",
    )
    parser.add_argument(
        "--filter",
        "-f",
        default=None,
        help='BPF filter (e.g., "tcp and port 80").',
    )
    parser.add_argument(
        "--count",
        "-c",
        type=int,
        default=0,
        help="Number of packets to capture (0 = unlimited until interrupted).",
    )
    parser.add_argument(
        "--timeout",
        "-t",
        type=int,
        default=0,
        help="Time in seconds to capture (0 = no timeout).",
    )
    parser.add_argument(
        "--pcap",
        "-w",
        default=None,
        help="Optional path to save captured packets as pcap.",
    )
    args = parser.parse_args()

    # Inform about privileges
    print("** Educational Packet Sniffer **")
    print("Make sure you have permission to capture on this network/interface.")
    print("Press Ctrl+C to stop.\n")

    # Adjust scapy conf to avoid verbose output
    conf.verb = 0

    captured = []

    try:
        sniff_kwargs = {
            "prn": on_packet,
            "store": False,  # we will optionally store separately if writing to pcap
        }
        if args.iface:
            sniff_kwargs["iface"] = args.iface
        if args.filter:
            sniff_kwargs["filter"] = args.filter
        if args.count and args.count > 0:
            sniff_kwargs["count"] = args.count
        if args.timeout and args.timeout > 0:
            sniff_kwargs["timeout"] = args.timeout

        # If user asked to save pcap, we must store packets
        if args.pcap:
            sniff_kwargs["store"] = True
            # We'll capture into a local list by using a lambda wrapper
            def collect(pkt):
                captured.append(pkt)
                on_packet(pkt)

            sniff_kwargs["prn"] = collect

        # Run sniff (blocking until count reached, timeout, or Ctrl+C)
        sniff(**sniff_kwargs)

    except PermissionError:
        sys.exit("Permission denied. Run as root/administrator to capture packets.")
    except KeyboardInterrupt:
        print("\nCapture stopped by user (Ctrl+C).")
    except Exception as e:
        sys.exit(f"Sniffing error: {e}")

    # Save pcap if requested
    if args.pcap and captured:
        try:
            wrpcap(args.pcap, captured)
            print(f"Saved {len(captured)} packets to {args.pcap}")
        except Exception as e:
            print(f"[!] Failed to write pcap: {e}")


if __name__ == "__main__":
    main()

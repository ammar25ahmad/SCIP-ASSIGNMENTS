
from datetime import datetime
from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, DNS, ARP, wrpcap


captured_packets = []


def analyze_packet(packet):
    """Display basic information about a captured packet."""

    captured_packets.append(packet)

    timestamp = datetime.now().strftime("%H:%M:%S")

    # Identify the network-layer addresses
    if IP in packet:
        source = packet[IP].src
        destination = packet[IP].dst
    elif IPv6 in packet:
        source = packet[IPv6].src
        destination = packet[IPv6].dst
    elif ARP in packet:
        source = packet[ARP].psrc
        destination = packet[ARP].pdst
    else:
        source = "Unknown"
        destination = "Unknown"

    # Identify protocol and ports
    protocol = "Other"
    details = ""

    if DNS in packet:
        protocol = "DNS"
    elif TCP in packet:
        protocol = "TCP"
        details = f"Port {packet[TCP].sport} -> {packet[TCP].dport}"
    elif UDP in packet:
        protocol = "UDP"
        details = f"Port {packet[UDP].sport} -> {packet[UDP].dport}"
    elif ICMP in packet:
        protocol = "ICMP"
    elif ARP in packet:
        protocol = "ARP"

    print(
        f"[{timestamp}] {protocol:5} | "
        f"{source} -> {destination} | "
        f"Length: {len(packet)} bytes | {details}"
    )


def main():
    print("=" * 65)
    print("          PYTHON NETWORK PACKET SNIFFER")
    print("=" * 65)
    print("Interface: Default interface")
    print("Press Ctrl+C to stop capturing.")
    print("-" * 65)

    try:
        # Capture packets without printing their raw payloads
        sniff(
            prn=analyze_packet,
            store=False
        )

    except KeyboardInterrupt:
        print("\n\nCapture stopped.")

    finally:
        if captured_packets:
            filename = "capture.pcap"
            wrpcap(filename, captured_packets)
            print(f"Saved {len(captured_packets)} packets to {filename}")
        else:
            print("No packets captured.")


if __name__ == "__main__":
    main()

from scapy.all import *
import datetime

# --- Configuration ---
# IMPORTANT: Change this to your actual network interface name
# On Linux, use `ifconfig` or `ip a` (e.g., 'eth0', 'wlan0', 'enp0s3')
# On Windows, use `ipconfig` (e.g., 'Ethernet', 'Wi-Fi', or adapter GUIDs)
# You can also uncomment the line below to let Scapy try to guess the default interface,
# but manually specifying is usually more reliable.
# INTERFACE = conf.iface
INTERFACE = "Ethernet" # <--- REPLACE WITH YOUR ACTUAL INTERFACE NAME

PACKET_COUNT = 20  # Number of packets to capture. Set to 0 for continuous capture (Ctrl+C to stop).
FILTER_EXPRESSION = "ip or arp" # BPF (Berkeley Packet Filter) syntax.
                                # Examples:
                                # "tcp"           - Only TCP packets
                                # "udp"           - Only UDP packets
                                # "icmp"          - Only ICMP (ping) packets
                                # "port 80"       - Only traffic on port 80 (HTTP)
                                # "host 192.168.1.1" - Traffic to/from a specific IP
                                # "src host 192.168.1.1" - Traffic from a specific source IP
                                # "dst port 443"  - Traffic to destination port 433 (HTTPS)
                                # "arp"           - Only ARP packets
                                # "tcp or udp"    - Both TCP and UDP packets

# --- Helper Dictionary for IP Protocols ---
# This makes the IP protocol number (e.g., 6, 17, 1) more human-readable.
IP_PROTOS = {
    1: 'ICMP',
    6: 'TCP',
    17: 'UDP',
    47: 'GRE',
    50: 'ESP',
    51: 'AH',
    58: 'ICMPv6',
    89: 'OSPF',
    132: 'SCTP'
}

# --- Packet Analysis Function ---
def analyze_packet(packet):
    """
    Analyzes a captured packet and prints relevant information,
    breaking down its layers and content.
    """
    # Get the timestamp of the packet capture
    timestamp = datetime.datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    print(f"\n--- Packet Captured at: {timestamp} ---")

    # --- Layer 2: Ethernet ---
    if packet.haslayer(Ether):
        eth_layer = packet.getlayer(Ether)
        print(f"  [Ethernet Layer (Layer 2)]")
        print(f"    Source MAC: {eth_layer.src}")
        print(f"    Destination MAC: {eth_layer.dst}")
        # print(f"    EtherType: {eth_layer.type} (0x800 for IP, 0x806 for ARP, etc.)") # Uncomment for more detail

    # --- Layer 3: IP (IPv4 or IPv6) ---
    if packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        print(f"  [IP Layer (Layer 3)]")
        print(f"    Source IP: {ip_layer.src}")
        print(f"    Destination IP: {ip_layer.dst}")
        # Map IP protocol number to a human-readable name
        protocol_name = IP_PROTOS.get(ip_layer.proto, f"Unknown ({ip_layer.proto})")
        print(f"    Protocol: {protocol_name}")
        print(f"    Time To Live (TTL): {ip_layer.ttl}")

        # --- Layer 4: TCP ---
        if packet.haslayer(TCP):
            tcp_layer = packet.getlayer(TCP)
            print(f"  [TCP Layer (Layer 4)]")
            print(f"    Source Port: {tcp_layer.sport}")
            print(f"    Destination Port: {tcp_layer.dport}")
            print(f"    Flags: {tcp_layer.flags} (SYN, ACK, FIN, PSH, URG, RST)")
            print(f"    Sequence Number: {tcp_layer.seq}")
            print(f"    Acknowledgement Number: {tcp_layer.ack}")
            print(f"    Window Size: {tcp_layer.window}")

            # Extract TCP Payload
            if tcp_layer.payload:
                payload = bytes(tcp_layer.payload)
                print(f"    Payload Length: {len(payload)} bytes")
                # Display payload in hexadecimal for non-printable data
                print(f"    Payload (hex, first 64 bytes): {payload[:64].hex()}...")
                # Attempt to decode as UTF-8/ASCII if it looks like text
                try:
                    decoded_payload = payload.decode('utf-8', errors='ignore').strip()
                    if any(c.isprintable() for c in decoded_payload):
                        print(f"    Payload (decoded, partial): \"{decoded_payload}\"")
                except UnicodeDecodeError:
                    pass # Ignore if it's not decodeable as UTF-8 text

        # --- Layer 4: UDP ---
        elif packet.haslayer(UDP):
            udp_layer = packet.getlayer(UDP)
            print(f"  [UDP Layer (Layer 4)]")
            print(f"    Source Port: {udp_layer.sport}")
            print(f"    Destination Port: {udp_layer.dport}")

            # Extract UDP Payload
            if udp_layer.payload:
                payload = bytes(udp_layer.payload)
                print(f"    Payload Length: {len(payload)} bytes")
                print(f"    Payload (hex, first 64 bytes): {payload[:64].hex()}...")
                try:
                    decoded_payload = payload.decode('utf-8', errors='ignore').strip()
                    if any(c.isprintable() for c in decoded_payload):
                        print(f"    Payload (decoded, partial): \"{decoded_payload}\"")
                except UnicodeDecodeError:
                    pass

        # --- Layer 4: ICMP (used by ping, traceroute) ---
        elif packet.haslayer(ICMP):
            icmp_layer = packet.getlayer(ICMP)
            print(f"  [ICMP Layer (Layer 4 - part of IP)]")
            print(f"    Type: {icmp_layer.type} ({ICMP_TYPES.get(icmp_layer.type, 'Unknown Type')})")
            print(f"    Code: {icmp_layer.code} ({ICMP_CODES.get(icmp_layer.type, {}).get(icmp_layer.code, 'Unknown Code')})")
            # ICMP often has payload for ping requests/replies
            if icmp_layer.payload:
                payload = bytes(icmp_layer.payload)
                print(f"    Payload (hex, first 64 bytes): {payload[:64].hex()}...")

    # --- Layer 3: ARP (Address Resolution Protocol) ---
    # ARP is typically considered Layer 2.5 or part of Layer 3, but it's not IP.
    elif packet.haslayer(ARP):
        arp_layer = packet.getlayer(ARP)
        print(f"  [ARP Layer (Address Resolution Protocol)]")
        print(f"    Operation: {'Request' if arp_layer.op == 1 else 'Reply' if arp_layer.op == 2 else 'Other'}")
        print(f"    Sender MAC: {arp_layer.hwsrc}")
        print(f"    Sender IP: {arp_layer.psrc}")
        print(f"    Target MAC: {arp_layer.hwdst}")
        print(f"    Target IP: {arp_layer.pdst}")

    # --- Other layers or Raw data ---
    # If a packet has no recognized higher layers, sometimes it just has raw data
    if packet.haslayer(Raw):
        raw_layer = packet.getlayer(Raw)
        if raw_layer.load:
            payload = bytes(raw_layer.load)
            print(f"  [Raw Payload (Unparsed)]")
            print(f"    Raw data Length: {len(payload)} bytes")
            print(f"    Raw data (hex, first 64 bytes): {payload[:64].hex()}...")
            try:
                decoded_raw = payload.decode('utf-8', errors='ignore').strip()
                if any(c.isprintable() for c in decoded_raw):
                    print(f"    Raw data (decoded, partial): \"{decoded_raw}\"")
            except UnicodeDecodeError:
                pass

    print("-" * 60) # Separator for readability


# --- Main Packet Capturing Function ---
def start_sniffing():
    """
    Starts the packet sniffing process using Scapy's sniff function.
    """
    print(f"[*] Starting packet capture on interface: '{INTERFACE}'")
    if PACKET_COUNT > 0:
        print(f"[*] Capturing {PACKET_COUNT} packets.")
    else:
        print(f"[*] Capturing packets continuously (Ctrl+C to stop).")
    print(f"[*] Applying BPF filter: '{FILTER_EXPRESSION}'")
    print("[*] Generating some network traffic (e.g., open a website, ping) to see results.")

    try:
        # sniff() is Scapy's primary function for live packet capture.
        # prn: A function to be applied to each packet captured.
        # count: The number of packets to capture. 0 means infinite.
        # iface: The network interface to sniff on.
        # filter: A BPF (Berkeley Packet Filter) expression to filter packets.
        # store: Set to 0 to not store packets in memory, saving resources for long captures.
        sniff(prn=analyze_packet, count=PACKET_COUNT, iface=INTERFACE, filter=FILTER_EXPRESSION, store=0)
        print("\n[*] Packet capture finished.")
    except PermissionError:
        print("\n[ERROR] Permission denied. Please run the script with elevated privileges (e.g., `sudo python your_script_name.py` on Linux, or as Administrator on Windows).")
    except OSError as e:
        if "No such device" in str(e) or "Interface not found" in str(e):
            print(f"\n[ERROR] Network interface '{INTERFACE}' not found.")
            print("       Please check your interface name. Common names: 'eth0', 'wlan0' (Linux), 'Ethernet', 'Wi-Fi' (Windows).")
            print("       You can list interfaces using `ifconfig` (Linux) or `ipconfig` (Windows).")
        else:
            print(f"\n[ERROR] An operating system error occurred: {e}")
    except KeyboardInterrupt:
        print("\n[*] Packet capture interrupted by user (Ctrl+C).")
    except Exception as e:
        print(f"\n[ERROR] An unexpected error occurred: {e}")

# --- Execute the sniffer when the script is run ---
if __name__ == "__main__":
    start_sniffing()
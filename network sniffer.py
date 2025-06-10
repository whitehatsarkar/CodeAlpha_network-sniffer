from scapy.all import sniff
from scapy.layers.inet import IP, TCP

def packet_callback(packet):
    print("="*60)
    print(f"[+] Packet Captured")

    # Check if packet has IP layer
    if packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        print(f"    Source IP      : {ip_layer.src}")
        print(f"    Destination IP : {ip_layer.dst}")

    # Check if packet has TCP layer
    if packet.haslayer(TCP):
        tcp_layer = packet.getlayer(TCP)
        print(f"    Source Port    : {tcp_layer.sport}")
        print(f"    Destination Port : {tcp_layer.dport}")

    # Optional: print the summary
    print(f"    Summary        : {packet.summary()}")
    print("="*60)

# Start sniffing (use iface="wlan0" or "eth0" if needed)
print("Starting network sniffer... Press CTRL+C to stop.\n")
sniff(prn=packet_callback, store=False)

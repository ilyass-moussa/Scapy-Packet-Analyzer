from scapy.all import sniff, IP, TCP, UDP, DNS

def packet_callback(packet):
    if packet.haslayer(TCP):
        print(f"[TCP] {packet[IP].src} -> {packet[IP].dst} : Port {packet[TCP].dport}")
    elif packet.haslayer(UDP):
        print(f"[UDP] {packet[IP].src} -> {packet[IP].dst} : Port {packet[UDP].dport}")
    elif packet.haslayer(DNS):
        print(f"[DNS] {packet[IP].src} -> {packet[IP].dst} : DNS Request")

print("🔍 Démarrage de la capture (TCP/UDP/DNS)...")
sniff(filter="ip", prn=packet_callback, store=False)

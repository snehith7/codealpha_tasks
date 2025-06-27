from scapy.all import sniff, IP, TCP, UDP

def process_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = "Other"

        if TCP in packet:
            protocol = "TCP"
        elif UDP in packet:
            protocol = "UDP"

        print(f"[+] {protocol} Packet: {src_ip} -> {dst_ip}")
        print(f"    Payload: {bytes(packet.payload)}\n")

# Start packet sniffing (requires admin/root privileges)
print("Sniffing packets... Press CTRL+C to stop.")
sniff(prn=process_packet, store=False)
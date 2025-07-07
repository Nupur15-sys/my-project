# Network Packet Sniffer Project Based on Flow Diagram

import scapy.all as scapy
import time
import threading
import json

class PacketSniffer:
    def __init__(self, protocol_filter=None):
        self.packet_log = []
        self.protocol_filter = protocol_filter  # 'TCP', 'ARP', etc.
        self.captured_packets = []

    def start_sniffing(self):
        print(f"[INFO] Starting packet sniffing with protocol filter: {self.protocol_filter or 'None'}...")
        scapy.sniff(prn=self.process_packet, store=False)

    def process_packet(self, packet):
        if self.filter_packet(packet):
            info = self.analyze_packet(packet)
            self.packet_log.append(info)
            self.captured_packets.append(packet)
            self.detect_anomalies(info)
            self.store_packet(info)

    def filter_packet(self, packet):
        if self.protocol_filter == 'TCP' and not packet.haslayer(scapy.TCP):
            return False
        if self.protocol_filter == 'ARP' and not packet.haslayer(scapy.ARP):
            return False
        if not packet.haslayer(scapy.IP) and self.protocol_filter != 'ARP':
            return False
        return True

    def analyze_packet(self, packet):
        if packet.haslayer(scapy.IP):
            ip_layer = packet[scapy.IP]
            proto = ip_layer.proto
            src = ip_layer.src
            dst = ip_layer.dst
        elif packet.haslayer(scapy.ARP):
            arp_layer = packet[scapy.ARP]
            proto = 'ARP'
            src = arp_layer.psrc
            dst = arp_layer.pdst
        else:
            proto = 'UNKNOWN'
            src = 'N/A'
            dst = 'N/A'

        return {
            "src": src,
            "dst": dst,
            "proto": proto,
            "timestamp": time.time()
        }

    def detect_anomalies(self, info):
        # Dummy logic for anomaly detection
        if info["proto"] not in [6, 17, 'ARP']:
            self.alert_notification(info)

    def alert_notification(self, info):
        print(f"[ALERT] Unusual protocol detected from {info['src']} to {info['dst']} (Proto: {info['proto']})")

    def store_packet(self, info):
        with open("packet_log.txt", "a") as log_file:
            log_file.write(json.dumps(info) + "\n")

    def save_pcap_file(self):
        if self.captured_packets:
            scapy.wrpcap("captured_packets.pcap", self.captured_packets)
            print("[INFO] Packets saved to captured_packets.pcap")
        else:
            print("[INFO] No packets to save to .pcap file.")

    def generate_report(self):
        print("\n[INFO] Generating report...")
        try:
            with open("packet_log.txt", "r") as f:
                for line in f:
                    print(json.loads(line))
        except FileNotFoundError:
            print("No data available for report.")


if __name__ == "__main__":
    print("Select Protocol to Filter (leave blank for all):")
    print("1. TCP")
    print("2. ARP")
    choice = input("Enter your choice (1/2): ")

    protocol = None
    if choice == '1':
        protocol = 'TCP'
    elif choice == '2':
        protocol = 'ARP'

    sniffer = PacketSniffer(protocol_filter=protocol)

    sniff_thread = threading.Thread(target=sniffer.start_sniffing)
    sniff_thread.daemon = True
    sniff_thread.start()

    try:
        while True:
            time.sleep(10)
            sniffer.generate_report()
    except KeyboardInterrupt:
        print("\n[INFO] Sniffing stopped by user.")
        sniffer.save_pcap_file()

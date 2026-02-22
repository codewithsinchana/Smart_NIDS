from scapy.all import sniff
from detector import analyze_packet

def start_sniffing():
    print("Smart Network Intrusion Detection System Started...")
    print("Monitoring network traffic...\n")
    sniff(prn=analyze_packet, store=False)

if __name__ == "__main__":
    start_sniffing()
    
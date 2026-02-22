from collections import defaultdict
from logger import log_alert
import time

ip_activity = defaultdict(list)

PORT_SCAN_THRESHOLD = 15   
TIME_WINDOW = 5           

def analyze_packet(packet):
    if packet.haslayer("IP"):
        src_ip = packet["IP"].src
        current_time = time.time()

        ip_activity[src_ip].append(current_time)

        ip_activity[src_ip] = [
            t for t in ip_activity[src_ip]
            if current_time - t < TIME_WINDOW
        ]

        if len(ip_activity[src_ip]) > PORT_SCAN_THRESHOLD:
            log_alert(f"Possible Port Scan Detected from {src_ip}")
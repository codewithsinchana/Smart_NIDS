from collections import defaultdict, deque
from datetime import datetime
from threading import Lock
from time import time
import smtplib
from email.mime.text import MIMEText

from scapy.layers.inet import ICMP, IP, TCP, UDP

from database import save_alert



PORT_SCAN_THRESHOLD = 10
PORT_SCAN_WINDOW = 10

SYN_FLOOD_THRESHOLD = 40
UDP_FLOOD_THRESHOLD = 60
ICMP_FLOOD_THRESHOLD = 30

FLOOD_TIME_WINDOW = 10

MAX_ALERTS = 100
MAX_TRAFFIC_RECORDS = 200


class NetworkDetector:

    def __init__(self):

        self.port_activity = defaultdict(deque)

        self.syn_activity = defaultdict(deque)

        self.udp_activity = defaultdict(deque)

        self.icmp_activity = defaultdict(deque)

        self.alerts = deque(maxlen=MAX_ALERTS)

        self.traffic = deque(maxlen=MAX_TRAFFIC_RECORDS)

        self.protocol_counts = {
            "TCP": 0,
            "UDP": 0,
            "ICMP": 0,
            "Other": 0,
        }

        self.total_packets = 0

        self.recent_alerts = {}

        self.lock = Lock()


    # -----------------------------
    # Email Notification
    # -----------------------------

    def send_email(self, alert):

        sender = "YOUR_GMAIL@gmail.com"

        password = "YOUR_APP_PASSWORD"

        receiver = "YOUR_GMAIL@gmail.com"

        body = f"""
Smart Network Intrusion Detection System

Attack Type : {alert['type']}

Source IP : {alert['source_ip']}

Destination IP : {alert['destination_ip']}

Severity : {alert['severity']}

Time : {alert['timestamp']}
"""

        try:

            message = MIMEText(body)

            message["Subject"] = "🚨 Smart NIDS Security Alert"

            message["From"] = sender

            message["To"] = receiver

            server = smtplib.SMTP(
                "smtp.gmail.com",
                587
            )

            server.starttls()

            server.login(
                sender,
                password
            )

            server.sendmail(
                sender,
                receiver,
                message.as_string()
            )

            server.quit()

            print("Email Notification Sent")

        except Exception as error:

            print("Email Error:", error)


    # -----------------------------
    # Packet Processing
    # -----------------------------

    def process_packet(self, packet):

        if IP not in packet:
            return

        current_time = time()

        timestamp = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        source_ip = packet[IP].src

        destination_ip = packet[IP].dst

        destination_port = 0

        protocol = "Other"

        if TCP in packet:

            destination_port = int(
                packet[TCP].dport
            )

            protocol = "TCP"

        elif UDP in packet:

            destination_port = int(
                packet[UDP].dport
            )

            protocol = "UDP"

        elif ICMP in packet:

            protocol = "ICMP"

        packet_data = {

            "timestamp": timestamp,

            "source_ip": source_ip,

            "destination_ip": destination_ip,

            "destination_port": destination_port,

            "protocol": protocol,

        }

        with self.lock:

            self.total_packets += 1

            self.protocol_counts[protocol] += 1

            self.traffic.appendleft(packet_data)
            
            if TCP in packet:

                self.detect_port_scan(
                    source_ip,
                    destination_ip,
                    destination_port,
                    current_time,
                    timestamp,
                )

                self.detect_syn_flood(
                    packet,
                    source_ip,
                    destination_ip,
                    current_time,
                    timestamp,
                )

            elif UDP in packet:

                self.detect_udp_flood(
                    source_ip,
                    destination_ip,
                    current_time,
                    timestamp,
                )

            elif ICMP in packet:

                self.detect_icmp_flood(
                    source_ip,
                    destination_ip,
                    current_time,
                    timestamp,
                )

    # -----------------------------------

    def remove_old_records(
        self,
        activity,
        current_time,
        time_window,
    ):

        while (
            activity
            and current_time - activity[0] > time_window
        ):
            activity.popleft()

    # -----------------------------------

    def detect_port_scan(
        self,
        source_ip,
        destination_ip,
        destination_port,
        current_time,
        timestamp,
    ):

        if destination_port <= 0:
            return

        activity = self.port_activity[source_ip]

        activity.append(
            (
                current_time,
                destination_port
            )
        )

        while (
            activity
            and current_time - activity[0][0]
            > PORT_SCAN_WINDOW
        ):
            activity.popleft()

        unique_ports = {

            port

            for _, port in activity

        }

        if len(unique_ports) >= PORT_SCAN_THRESHOLD:

            self.create_alert(

                attack_type="Possible Port Scan",

                source_ip=source_ip,

                destination_ip=destination_ip,

                severity="High",

                timestamp=timestamp,

                current_time=current_time,

                packet_count=len(activity),

                port_count=len(unique_ports),

            )

    # -----------------------------------

    def detect_syn_flood(
        self,
        packet,
        source_ip,
        destination_ip,
        current_time,
        timestamp,
    ):

        tcp_flags = packet[TCP].flags

        if tcp_flags & 0x02 and not tcp_flags & 0x10:

            activity = self.syn_activity[source_ip]

            activity.append(current_time)

            self.remove_old_records(

                activity,

                current_time,

                FLOOD_TIME_WINDOW,

            )

            if len(activity) >= SYN_FLOOD_THRESHOLD:

                self.create_alert(

                    attack_type="Possible SYN Flood",

                    source_ip=source_ip,

                    destination_ip=destination_ip,

                    severity="Critical",

                    timestamp=timestamp,

                    current_time=current_time,

                    packet_count=len(activity),

                )
                
        # -----------------------------------

    def detect_udp_flood(
        self,
        source_ip,
        destination_ip,
        current_time,
        timestamp,
    ):

        activity = self.udp_activity[source_ip]

        activity.append(current_time)

        self.remove_old_records(
            activity,
            current_time,
            FLOOD_TIME_WINDOW,
        )

        if len(activity) >= UDP_FLOOD_THRESHOLD:

            self.create_alert(
                attack_type="Possible UDP Flood",
                source_ip=source_ip,
                destination_ip=destination_ip,
                severity="High",
                timestamp=timestamp,
                current_time=current_time,
                packet_count=len(activity),
            )

    # -----------------------------------

    def detect_icmp_flood(
        self,
        source_ip,
        destination_ip,
        current_time,
        timestamp,
    ):

        activity = self.icmp_activity[source_ip]

        activity.append(current_time)

        self.remove_old_records(
            activity,
            current_time,
            FLOOD_TIME_WINDOW,
        )

        if len(activity) >= ICMP_FLOOD_THRESHOLD:

            self.create_alert(
                attack_type="Possible ICMP Flood",
                source_ip=source_ip,
                destination_ip=destination_ip,
                severity="High",
                timestamp=timestamp,
                current_time=current_time,
                packet_count=len(activity),
            )

    # -----------------------------------

    def create_alert(
        self,
        attack_type,
        source_ip,
        destination_ip,
        severity,
        timestamp,
        current_time,
        packet_count=0,
        port_count=0,
    ):

        alert_key = f"{source_ip}:{attack_type}"

        previous_alert_time = self.recent_alerts.get(
            alert_key,
            0,
        )

        if (
            current_time - previous_alert_time
            < FLOOD_TIME_WINDOW
        ):
            return

        alert = {

            "timestamp": timestamp,

            "type": attack_type,

            "source_ip": source_ip,

            "destination_ip": destination_ip,

            "severity": severity,

            "packet_count": packet_count,

            "port_count": port_count,

        }

        self.alerts.appendleft(alert)

        self.recent_alerts[alert_key] = current_time

        save_alert(alert)

        if severity in ["High", "Critical"]:
            self.send_email(alert)

        alert_message = (
            f"[{timestamp}] "
            f"{attack_type} detected from "
            f"{source_ip} targeting "
            f"{destination_ip}"
        )

        print(alert_message)

        try:

            with open(
                "alerts.log",
                "a",
                encoding="utf-8",
            ) as log_file:

                log_file.write(
                    alert_message + "\n"
                )

        except OSError as error:

            print(
                f"Unable to write alert log: {error}"
            )

    # -----------------------------------

    def get_statistics(self):

        with self.lock:

            return {

                "total_packets": self.total_packets,

                "total_alerts": len(self.alerts),

                "protocol_counts": dict(
                    self.protocol_counts
                ),

                "status": "Monitoring",

                "detection_rules": [

                    "Port Scan",

                    "SYN Flood",

                    "UDP Flood",

                    "ICMP Flood",

                ],

            }

    # -----------------------------------

    def get_alerts(self):

        with self.lock:

            return list(self.alerts)

    # -----------------------------------

    def get_traffic(self):

        with self.lock:

            return list(self.traffic)


network_detector = NetworkDetector()
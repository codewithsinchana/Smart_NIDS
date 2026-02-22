# Smart Network Intrusion Detection System :

      A Python-based intrusion detection system that monitors network traffic and detects suspicious behavior such as port scanning.

**Features**
- Real-time packet sniffing
- Port scan detection
- Alert logging
- Extensible detection rules

**Technologies Used**
- Python
- Scapy
- Flask

**How It Works**
1. The system listens to live network traffic.
2. It tracks packet frequency from each source IP.
3. If packet count exceeds a defined threshold within a time window,
   it flags the activity as suspicious.
4. Alerts are printed in the terminal and saved to alerts.log.

**Example Output**

  Smart Network Intrusion Detection System Started...

  Monitoring network traffic...

  [2026-02-22 14:10:35] Possible Port Scan Detected from 192.168.1.100

Author : Developed by Sinchana T R


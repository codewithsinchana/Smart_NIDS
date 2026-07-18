**Smart Network Intrusion Detection System using Web Dashboard** : A real-time network intrusion detection dashboard built with Flask, Scapy, and React. It sniffs
live network traffic, detects common attack patterns (port scans, SYN/UDP/ICMP floods), logs alerts to a database, and visualizes everything through a live,
auto-refreshing dashboard — with CSV/PDF export,IP geolocation lookups, and email alerting.

**Features**

1.Web dashboard visualization
2.JWT Authentication 
3.Real-time packet monitoring
4.Port scan detection
5.Traffic analysis
6.Attack Detection
7.SQLite Database
8.CSV Export / PDF Report Generation
9.Email Notifications
10.IP Geolocation

**Technologies Used**

**Backend**:
Python, Flask, Flask-CORS ,
Flask-JWT-Extended (authentication) ,
Scapy (packet sniffing) ,
ReportLab (PDF generation) ,
SQLite (alert storage) ,
smtplib (email alerts) ,
requests (IP geolocation lookups)

**Frontend**
React (functional components + hooks) ,
Axios (HTTP client, with a JWT-attaching interceptor) ,
Recharts (Area/Pie/Bar charts) ,
Vite ,
CSS.

**How It Works**

1.Packet Capture — On startup, a background thread runs scapy.sniff(), feeding every captured packet into a network_detector module that classifies protocol 
(TCP/UDP/ICMP/Other) and screens for attack signatures (repeated SYNs to varying ports = port scan, high-volume single-source floods = SYN/UDP/ICMP flood).

2.Alert Logging — When an attack pattern is detected, an alert record (timestamp, source/destination IP, attack type, severity, packet/port counts) is
written to SQLite.

3.Authentication — /api/login checks credentials and issues a JWT. The React app stores this token in localStorage and an Axios interceptor attaches 
Authorization: Bearer <token> to every subsequent request. All data routes are protected with @jwt_required().

4.Dashboard Polling — Once logged in, the frontend polls /api/statistics, /api/alerts, /api/traffic, and /api/analytics every 2 seconds and re-renders 
the charts/tables.

5.Exports — CSV and PDF exports are fetched as authenticated blob downloads (not simple links, since the endpoints require a JWT) and triggered
via a generated <a download> element.

6.Geolocation — Clicking "Locate" on an alert calls /api/location/<ip>, which proxies to ip-api.com and returns country/region/city/ISP/lat/lon, shown 
in a dismissible popup.

7.Email Alerts — /api/notify/status reports whether SMTP credentials are configured; /api/notify/test sends a real test email via GmailSMTP so you can 
confirm alerting works end-to-end.

**How to run**

**Backend**
1.cd backend
2.pip install flask flask-cors scapy pandas
3.python app.py
4.It will run at http://127.0.0.1:5000

**Frontend**
npm create vite@latest frontend -- --template react
1.cd frontend
2.npm install
3.npm install axios
4.npm install recharts
5.npm run dev
6.It will run at http://localhost:5173

Username : admin
Password : admin123

import csv
import io
import os
import tempfile
import requests
import smtplib
from threading import Thread
from collections import Counter
from email.mime.text import MIMEText

from flask import (
    Flask,
    jsonify,
    request,
    Response,
    send_file
)

from flask_cors import CORS

from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    jwt_required
)

from reportlab.platypus import (
    SimpleDocTemplate,
    Table,
)

from reportlab.lib import colors

from scapy.all import sniff

from database import (
    get_all_alerts,
    initialize_database,
)

from detector import network_detector


app = Flask(__name__)

CORS(app)

app.config["JWT_SECRET_KEY"] = "smartnids123"

jwt = JWTManager(app)


@jwt.invalid_token_loader
def invalid_token_callback(error):
    print("INVALID TOKEN:", error)
    return jsonify({"msg": error}), 422


@jwt.unauthorized_loader
def missing_token_callback(error):
    print("MISSING TOKEN:", error)
    return jsonify({"msg": error}), 401


SENDER_EMAIL = "YOUR_GMAIL@gmail.com"
SENDER_PASSWORD = "YOUR_APP_PASSWORD"
RECEIVER_EMAIL = "YOUR_GMAIL@gmail.com"

EMAIL_CONFIGURED = (
    SENDER_EMAIL != "YOUR_GMAIL@gmail.com"
    and SENDER_PASSWORD != "YOUR_APP_PASSWORD"
)


def send_email(ip, attack):

    if not EMAIL_CONFIGURED:
        print("Email not configured, skipping send.")
        return False

    try:

        msg = MIMEText(f""" Smart Network Intrusion Detection System Attack Detected 
                       Attack Type : {attack} Source IP : {ip}
                       Please check the dashboard immediately.""" )

        msg["Subject"] = "Smart NIDS Security Alert"
        msg["From"] = SENDER_EMAIL
        msg["To"] = RECEIVER_EMAIL

        server = smtplib.SMTP("smtp.gmail.com", 587)

        server.starttls()

        server.login(
            SENDER_EMAIL,
            SENDER_PASSWORD,
        )

        server.sendmail(
            SENDER_EMAIL,
            RECEIVER_EMAIL,
            msg.as_string(),
        )

        server.quit()

        return True

    except Exception as e:
        print("Email Error :", e)
        return False


def start_sniffer():

    print("Smart Network Intrusion Detection System Started...")
    print("Monitoring network traffic...")

    try:

        sniff(
            prn=network_detector.process_packet,
            store=False,
        )

    except PermissionError:

        print(
            "Run VS Code as Administrator."
        )

    except Exception as e:

        print(e)


@app.route("/")
def home():

    return jsonify(
        {
            "message": "Smart NIDS Flask API is running",
            "author": "Sinchana T R",
        }
    )


@app.route("/api/login", methods=["POST"])
def login():

    data = request.get_json()

    username = data.get("username")

    password = data.get("password")

    if username == "admin" and password == "admin123":

        token = create_access_token(
            identity=username
        )

        return jsonify(
            {
                "success": True,
                "token": token,
            }
        )

    return jsonify(
        {
            "success": False,
            "message": "Invalid Credentials",
        }
    ), 401


@app.route("/api/statistics")
@jwt_required()
def statistics():

    return jsonify(
        network_detector.get_statistics()
    )


@app.route("/api/traffic")
@jwt_required()
def traffic():

    return jsonify(
        network_detector.get_traffic()
    )


@app.route("/api/alerts")
@jwt_required()
def alerts():

    source_ip = request.args.get("source_ip", "").strip()
    attack_type = request.args.get("attack_type", "").strip()
    severity = request.args.get("severity", "").strip()

    alert_data = get_all_alerts(
        source_ip=source_ip,
        attack_type=attack_type,
        severity=severity,
    )

    return jsonify(alert_data)


@app.route("/api/analytics")
@jwt_required()
def analytics():

    alert_data = get_all_alerts()

    attack_types = Counter()

    top_ips = Counter()

    protocols = Counter()

    for alert in alert_data:

        attack_types[alert["type"]] += 1

        top_ips[alert["source_ip"]] += 1

    traffic_data = network_detector.get_traffic()

    for packet in traffic_data:

        protocols[packet["protocol"]] += 1

    return jsonify({

        "attack_types": dict(attack_types),

        "top_ips": dict(top_ips),

        "protocols": dict(protocols)

    })


@app.route("/api/location/<ip>")
@jwt_required()
def location(ip):

    try:

        response = requests.get(
            f"http://ip-api.com/json/{ip}",
            timeout=5
        )

        return jsonify(response.json())

    except Exception as e:

        return jsonify({

            "status": "fail",

            "message": str(e)

        })


# -----------------------------
# Email Notifications
# -----------------------------

@app.route("/api/notify/status")
@jwt_required()
def notify_status():

    return jsonify({
        "configured": EMAIL_CONFIGURED,
        "receiver": RECEIVER_EMAIL if EMAIL_CONFIGURED else None,
    })


@app.route("/api/notify/test", methods=["POST"])
@jwt_required()
def notify_test():

    data = request.get_json(silent=True) or {}

    ip = data.get("source_ip", "0.0.0.0")
    attack = data.get("attack_type", "Test Alert")

    sent = send_email(ip, attack)

    if sent:
        return jsonify({
            "success": True,
            "message": "Test email sent successfully.",
        })

    return jsonify({
        "success": False,
        "message": "Email not sent. Check SENDER_EMAIL / SENDER_PASSWORD configuration.",
    }), 500


# -----------------------------
# CSV Export
# -----------------------------

@app.route("/api/alerts/export")
@jwt_required()
def export_alerts():

    alert_data = get_all_alerts()

    output = io.StringIO()

    writer = csv.writer(output)

    writer.writerow([
        "ID",
        "Timestamp",
        "Source IP",
        "Destination IP",
        "Attack Type",
        "Severity",
        "Packet Count",
        "Port Count"
    ])

    for alert in alert_data:

        writer.writerow([

            alert["id"],

            alert["timestamp"],

            alert["source_ip"],

            alert["destination_ip"],

            alert["type"],

            alert["severity"],

            alert["packet_count"],

            alert["port_count"]

        ])

    csv_data = output.getvalue()

    output.close()

    return Response(

        csv_data,

        mimetype="text/csv",

        headers={

            "Content-Disposition":

            "attachment; filename=Smart_NIDS_Alerts.csv"

        }

    )


@app.route("/api/report")
@jwt_required()
def report():

    alerts = get_all_alerts()

    data = [[

        "Timestamp",

        "Attack",

        "Source IP",

        "Severity"

    ]]

    for alert in alerts:

        data.append([

            alert["timestamp"],

            alert["type"],

            alert["source_ip"],

            alert["severity"]

        ])

    table = Table(data)

    table.setStyle([

        ("BACKGROUND", (0,0), (-1,0), colors.grey),

        ("TEXTCOLOR", (0,0), (-1,0), colors.whitesmoke),

        ("GRID", (0,0), (-1,-1), 1, colors.black),

        ("BACKGROUND", (0,1), (-1,-1), colors.beige)

    ])

    # Use a unique temp file per request so concurrent report
    # requests can't race on the same filename.
    tmp = tempfile.NamedTemporaryFile(suffix=".pdf", delete=False)
    tmp.close()

    pdf = SimpleDocTemplate(tmp.name)

    pdf.build([table])

    response = send_file(
        tmp.name,
        as_attachment=True,
        download_name="Security_Report.pdf",
    )

    @response.call_on_close
    def cleanup():
        try:
            os.remove(tmp.name)
        except OSError:
            pass

    return response


if __name__ == "__main__":

    initialize_database()

    sniffer_thread = Thread(

        target=start_sniffer,

        daemon=True

    )

    sniffer_thread.start()

    app.run(

        host="127.0.0.1",

        port=5000,

        debug=False

    )
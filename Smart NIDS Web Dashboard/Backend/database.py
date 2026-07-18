import sqlite3


DATABASE = "alerts.db"


def get_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def initialize_database():
    conn = get_connection()

    conn.execute("""
    CREATE TABLE IF NOT EXISTS alerts(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        source_ip TEXT,
        destination_ip TEXT,
        attack_type TEXT,
        severity TEXT,
        packet_count INTEGER,
        port_count INTEGER
    )
    """)

    conn.commit()
    conn.close()


def save_alert(alert):
    conn = get_connection()

    conn.execute("""
    INSERT INTO alerts(
        timestamp,
        source_ip,
        destination_ip,
        attack_type,
        severity,
        packet_count,
        port_count
    )
    VALUES(?,?,?,?,?,?,?)
    """, (
        alert["timestamp"],
        alert["source_ip"],
        alert.get("destination_ip", ""),
        alert["type"],
        alert["severity"],
        alert.get("packet_count", 0),
        alert.get("port_count", 0)
    ))

    conn.commit()
    conn.close()


def get_all_alerts(
    source_ip="",
    attack_type="",
    severity=""
):

    conn = get_connection()

    query = """
    SELECT *
    FROM alerts
    WHERE 1=1
    """

    params = []

    if source_ip:
        query += " AND source_ip LIKE ?"
        params.append(f"%{source_ip}%")

    if attack_type:
        query += " AND attack_type=?"
        params.append(attack_type)

    if severity:
        query += " AND severity=?"
        params.append(severity)

    query += " ORDER BY id DESC"

    rows = conn.execute(query, params).fetchall()

    conn.close()

    alerts = []

    for row in rows:
        alerts.append({
            "id": row["id"],
            "timestamp": row["timestamp"],
            "source_ip": row["source_ip"],
            "destination_ip": row["destination_ip"],
            "type": row["attack_type"],
            "severity": row["severity"],
            "packet_count": row["packet_count"],
            "port_count": row["port_count"]
        })

    return alerts
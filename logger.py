from datetime import datetime

def log_alert(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    log_message = f"[{timestamp}] {message}"

    with open("alerts.log", "a") as file:
        file.write(log_message + "\n")

    print(log_message)
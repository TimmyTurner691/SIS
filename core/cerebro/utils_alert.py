import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

SMTP_SERVER = os.getenv("SIS_SMTP_SERVER", "")
SMTP_PORT = int(os.getenv("SIS_SMTP_PORT", "587"))
SENDER_EMAIL = os.getenv("SIS_SMTP_SENDER_EMAIL", "")
SENDER_PASSWORD = os.getenv("SIS_SMTP_SENDER_PASSWORD", "")
RECEIVER_EMAIL = os.getenv("SIS_SMTP_RECEIVER_EMAIL", "")
SMTP_USE_TLS = os.getenv("SIS_SMTP_USE_TLS", "true").lower() == "true"


def send_email_alert(subject, body, level="INFO"):
    if not all([SMTP_SERVER, SENDER_EMAIL, SENDER_PASSWORD, RECEIVER_EMAIL]):
        print("⚠️ [EMAIL] Configuración SMTP incompleta. Se omite envío.", flush=True)
        return False

    try:
        msg = MIMEMultipart()
        msg["From"] = SENDER_EMAIL
        msg["To"] = RECEIVER_EMAIL
        msg["Subject"] = f"[{level}] SIEM OT ALERTA: {subject}"
        msg.attach(MIMEText(body, "plain"))

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        if SMTP_USE_TLS:
            server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, msg.as_string())
        server.quit()

        print(f"📧 [EMAIL] Enviado a {RECEIVER_EMAIL} | Asunto: {subject}", flush=True)
        return True
    except Exception as e:
        print(f"❌ [EMAIL] Error: {e}", flush=True)
        return False

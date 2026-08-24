import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from utils_env import get_env_int, get_env_bool

SMTP_SERVER = os.getenv("SIS_SMTP_SERVER", "")
SMTP_PORT = get_env_int("SIS_SMTP_PORT", 587)
SENDER_EMAIL = os.getenv("SIS_SMTP_SENDER_EMAIL", "")
SENDER_PASSWORD = os.getenv("SIS_SMTP_SENDER_PASSWORD", "")
DEFAULT_RECEIVER_EMAIL = os.getenv("SIS_SMTP_RECEIVER_EMAIL", "")
SMTP_USE_TLS = get_env_bool("SIS_SMTP_USE_TLS", True)

# Añadimos el parámetro receiver_email
def send_email_alert(subject, body, level="INFO", receiver_email=None):
    # Si le enviamos un correo dinámico lo usa, si no, usa el del .env
    final_receiver = receiver_email if receiver_email else DEFAULT_RECEIVER_EMAIL

    if not all([SMTP_SERVER, SENDER_EMAIL, SENDER_PASSWORD, final_receiver]):
        print("⚠️ [EMAIL] Configuración SMTP incompleta. Se omite envío.", flush=True)
        return "CONFIG_ERROR"

    try:
        msg = MIMEMultipart()
        msg["From"] = SENDER_EMAIL
        msg["To"] = final_receiver
        msg["Subject"] = f"[{level}] SIEM OT ALERTA: {subject}"
        msg.attach(MIMEText(body, "plain"))

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        if SMTP_USE_TLS:
            server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.sendmail(SENDER_EMAIL, final_receiver, msg.as_string())
        server.quit()

        print(f"📧 [EMAIL] Enviado a {final_receiver} | Asunto: {subject}", flush=True)
        return True
    except Exception as e:
        print(f"❌ [EMAIL] Error: {e}", flush=True)
        return "SEND_ERROR"
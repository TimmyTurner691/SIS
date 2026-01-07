# python_core/utils_alert.py
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# --- CONFIGURACIÓN ---
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SENDER_EMAIL = "segnetsis@gmail.com"  
SENDER_PASSWORD = "ects hifw guee udap"               
RECEIVER_EMAIL = "mvallejos.sa@gmail.com"         

def send_email_alert(subject, body, level="INFO"): #función para enviar alertas por correo electrónico
    try:
        msg = MIMEMultipart()
        msg['From'] = SENDER_EMAIL
        msg['To'] = RECEIVER_EMAIL
        msg['Subject'] = f"[{level}] SIEM OT ALERTA: {subject}"

        msg.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        text = msg.as_string()
        server.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, text)
        server.quit()
        
        print(f"📧 [EMAIL] Enviado a {RECEIVER_EMAIL} | Asunto: {subject}", flush=True)
        return True
    except Exception as e:
        print(f"❌ [EMAIL] Error: {e}", flush=True)
        return False
# python_core/utils_alert.py
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os

# CONFIGURACIÓN (Idealmente usa variables de entorno en producción)
SMTP_SERVER = "smtp.gmail.com" # O tu servidor corporativo
SMTP_PORT = 587
SENDER_EMAIL = "tu_correo@gmail.com"
SENDER_PASSWORD = "tu_contraseña_de_aplicacion" # Ojo: En Gmail usa "App Password", no tu clave normal
RECEIVER_EMAIL = "operador_sala_control@empresa.com"

def send_email_alert(subject, body, level="INFO"):
    try:
        msg = MIMEMultipart()
        msg['From'] = SENDER_EMAIL
        msg['To'] = RECEIVER_EMAIL
        msg['Subject'] = f"[{level}] SIEM OT ALERTA: {subject}"

        msg.attach(MIMEText(body, 'plain'))

        # Conexión Segura
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        text = msg.as_string()
        server.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, text)
        server.quit()
        
        print(f"📧 Alerta enviada a {RECEIVER_EMAIL}")
        return True
    except Exception as e:
        print(f"❌ Error enviando correo: {e}")
        return False

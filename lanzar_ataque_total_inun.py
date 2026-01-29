import os
import time
import json
import random

# --- CONFIGURACIÓN ---
TARGET_IP = "192.168.5.103"
ATTACKER_IP = "66.66.66.66"
LOG_FILE = "logs/logs_snort/alert"
INVENTORY_FILE = "ot_inventory.json"
CVE_FILE = "cve_report.csv"

def configurar_archivos():
    # 1. Configuramos el activo como CRITICO para asegurar impacto
    inventory = [{"ip": TARGET_IP, "name": "PLC_Hornos", "criticality": "CRITICAL"}]
    with open(INVENTORY_FILE, "w") as f:
        json.dump(inventory, f)
    
    # 2. Configuramos CVE
    with open(CVE_FILE, "w") as f:
        f.write(f"ip,device,cve_id,severity\n{TARGET_IP},PLC_Hornos,CVE-2023-999,CRITICAL\n")
    
    print("✅ Archivos de configuración listos.")

def esperar_entrenamiento():
    print("\n🔄 Reiniciando cerebro...")
    #os.system("docker compose restart")
    
    print("\n🧘 CALIBRANDO IA (Entrenando normalidad)...")
    print("   Necesitamos que la IA vea 'silencio' para contrastar el ataque.")
    print("   Espera 30 segundos...", end="", flush=True)

    # Esperamos 30 segundos para llenar el deque history con ceros [0,0]
    for i in range(30):
        time.sleep(1)
        if i % 5 == 0: print(".", end="", flush=True)
    print(" ¡LISTO!")

def lanzar_flood():
    print("\n🚀 LANZANDO FLOOD MASIVO (Simulando DoS Real)...")
    
    # El ataque DoS real no es 1 paquete, son cientos por segundo.
    cantidad_paquetes = 300 
    
    msg_base = f"[**] [1:1000001:1] DOS ATTACK FLOOD [**] [Priority: 1] {{TCP}} {ATTACKER_IP} -> {TARGET_IP}"
    
    try:
        with open(LOG_FILE, "a") as f:
            # Escribimos 300 líneas de golpe
            for _ in range(cantidad_paquetes):
                # Variamos ligeramente el puerto o ID para realismo (opcional)
                f.write(msg_base + "\n")
                
        print(f"🔥 ¡BUM! Se inyectaron {cantidad_paquetes} logs en 0.1 segundos.")
        print("📊 Esto debería disparar stats_snort de 0 -> 300.")
        print("📉 La IA debería marcar Anomaly Score cercano a -1.0 (Muy Anómalo).")
        
    except PermissionError:
        print("❌ Error de permisos: Usa sudo.")

if __name__ == "__main__":
    #configurar_archivos()
    #esperar_entrenamiento()
    lanzar_flood()
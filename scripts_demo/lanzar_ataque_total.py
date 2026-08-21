import os
import time
import json

# --- CONFIGURACIÓN ---
TARGET_IP = "192.168.1.66"  # La víctima (Simularemos que es el activo más importante)
ATTACKER_IP = "66.6.6.6"    # El atacante
LOG_FILE = "logs/logs_snort/alert"
INVENTORY_FILE = "ot_inventory.json"
CVE_FILE = "cve_report.csv"

def paso_1_preparar_terreno():
    print(f"🛠️  PASO 1: Configurando Activo Crítico ({TARGET_IP})...")
    
    # 1. Crear Inventario Operativo (Impacto 5)
    inventory_data = [
        {
            "ip": TARGET_IP,
            "name": "REACTOR_NUCLEAR_PRINCIPAL",
            "type": "SCADA_CORE",
            "criticality": "CRITICAL"
        }
    ]
    with open(INVENTORY_FILE, "w") as f:
        json.dump(inventory_data, f, indent=4)
    print("   ✅ ot_inventory.json creado (Criticality: CRITICAL).")

    # 2. Crear Reporte de Vulnerabilidades (Respaldo de Impacto 5 y arreglo de formato)
    csv_content = f"ip,device,cve_id,severity\n{TARGET_IP},Reactor_Core,CVE-2025-0001,CRITICAL\n"
    with open(CVE_FILE, "w") as f:
        f.write(csv_content)
    print("   ✅ cve_report.csv creado (Severity: CRITICAL).")

def paso_2_reiniciar_cerebro():
    print("\n🔄 PASO 2: Reiniciando Python Core para leer nuevas configuraciones...")
    # Reiniciamos solo el contenedor de python para que lea los archivos nuevos
    os.system("docker compose restart")
    
    print("   ⏳ Esperando 30 segundos a que el SIEM arranque...")
    time.sleep(30) 
    print("   ✅ Sistema reiniciado y listo.")

def paso_3_lanzar_misil():
    print("\n🚀 PASO 3: Inyectando Ataque de Alta Probabilidad (DoS)...")
    
    # Formato exacto que espera tu parser de Snort
    # Usamos "DOS ATTACK" para asegurar Score MITRE de 25 (Risk 5)
    ataque = f"[**] [1:1000001:1] DOS ATTACK CRITICAL FLOOD [**] [Priority: 1] {{TCP}} {ATTACKER_IP} -> {TARGET_IP}\n"
    
    try:
        with open(LOG_FILE, "a") as f:
            f.write(ataque)
        print(f"   🔥 LOG INYECTADO: {ataque.strip()}")
        print("\n✅ ATAQUE COMPLETADO.")
        print("   -> El SIEM debería detectar: Probabilidad(5) x Impacto(5) = TOTAL 25")
        print("   -> Revisa los logs con: docker logs -f python_core")
    except PermissionError:
        print("   ❌ ERROR DE PERMISOS: Ejecuta este script con 'sudo' para escribir en los logs.")

if __name__ == "__main__":
    print("--- INICIANDO SIMULACIÓN DE ATAQUE TOTAL ---")
    paso_1_preparar_terreno()
    paso_2_reiniciar_cerebro()
    paso_3_lanzar_misil()
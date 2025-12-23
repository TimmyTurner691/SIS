import time
import os
import random
import json
from datetime import datetime

# === CONFIGURACIÓN ===
# Rutas deben coincidir con las de main.py
LOG_SNORT = '/var/log/snort/alert'
LOG_ZEEK = '/var/log/zeek/conn.log'
LOG_IEC = '/var/log/zeek/iec104.log'
CSV_VULN = '/app/cve_report.csv'

# DATOS DEL ATAQUE
TARGET_IP = "192.168.1.100"  # La IP de nuestra "Víctima"
ATTACKER_IP = "45.66.77.88"  # La IP del "Atacante"

def setup_critical_asset():
    """
    Paso 1: Inyectar vulnerabilidad crítica.
    Esto asegura que el eje X (Impacto) sea 5/5.
    """
    print(f"💉 Inyectando Activo Crítico ({TARGET_IP}) en reporte CVE...")
    
    header = "device,ip,cve_id,description,severity,score,link\n"
    # Una vulnerabilidad CRITICAL falsa
    payload = f"PLC-Critical-Turbine,{TARGET_IP},CVE-2024-TEST,Buffer Overflow in SCADA Core,CRITICAL,9.8,http://nvd.nist.gov\n"
    
    # Si no existe, creamos con header
    if not os.path.exists(CSV_VULN):
        with open(CSV_VULN, 'w') as f: f.write(header + payload)
    else:
        # Si existe, solo agregamos si no está ya
        with open(CSV_VULN, 'r+') as f:
            content = f.read()
            if TARGET_IP not in content:
                f.write(payload)
    print("✅ Activo marcado como CRÍTICO (Impacto=5).")

def simulate_mitre_attack():
    """
    Paso 2: Generar Logs de Ataque.
    Esto asegura que el eje Y (Amenaza) sea 5/5 (MITRE + IA).
    """
    print("⚔️ Iniciando Simulación de Kill Chain...")

    # A. Fase de Reconocimiento (Scanning) - Zeek
    print("   -> Generando tráfico de escaneo (Zeek)...")
    with open(LOG_ZEEK, 'a') as f:
        for port in [102, 502, 2404, 443, 80]:
            log = {
                "ts": time.time(),
                "id.orig_h": ATTACKER_IP,
                "id.resp_h": TARGET_IP,
                "id.resp_p": port,
                "proto": "tcp",
                "service": "iec104" if port == 2404 else "http",
                "duration": 0.01,
                "orig_bytes": 100,
                "resp_bytes": 0
            }
            f.write(json.dumps(log) + "\n")
    time.sleep(1)

    # B. Fase de Impacto (DoS) - Snort
    # La palabra clave "DoS" activa la regla MITRE T0814 en tu main.py
    print("   -> Inyectando alerta de Snort (DoS)...")
    snort_alert = f"[**] [1:10001:1] SCADA DoS Attack Detected targeting PLC [**] [Priority: 1] {{TCP}} {ATTACKER_IP}:4567 -> {TARGET_IP}:2404\n"
    
    with open(LOG_SNORT, 'a') as f:
        # Escribimos varias veces para alterar la estadística de la IA también
        for _ in range(5):
            f.write(snort_alert)
    
    print("✅ Amenaza inyectada: Ataque DoS detectado (Probabilidad=5).")

def main():
    print("=========================================")
    print("   SIMULADOR DE ATAQUE SIS - RED TEAM    ")
    print("=========================================")
    
    # 1. Preparar el terreno (Vulnerabilidad)
    setup_critical_asset()
    
    # 2. Esperar que main.py lea el CSV (opcional, main lo lee al inicio)
    time.sleep(1)
    
    # 3. Lanzar el ataque (Amenaza)
    simulate_mitre_attack()
    
    print("\n💥 ATAQUE COMPLETADO.")
    print(f"Resultados esperados en Dashboard para {TARGET_IP}:")
    print("1. Impacto (Eje X): 5 (CRITICAL)")
    print("2. Amenaza (Eje Y): 5 (MITRE DoS T0814)")
    print("3. RIESGO TOTAL:    25/25 (ROJO)")
    print("=========================================")

if __name__ == "__main__":
    main()
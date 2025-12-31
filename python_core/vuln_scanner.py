import requests
import json
import time
import logging
import sys
import csv
import os

# --- CONFIGURACIÓN DE RUTAS (Absolutas para Docker) ---
INVENTORY_FILE = "/app/ot_inventory.json"
REPORT_FILE = "/app/cve_report.csv"

# Configuración de logs
logger = logging.getLogger()
logger.setLevel(logging.INFO)
handler = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter('🔍 SCANNER: %(message)s')
handler.setFormatter(formatter)
if not logger.handlers:
    logger.addHandler(handler)

def scan_vulnerabilities():
    report = []
    devices = []

    # 1. CARGAR INVENTARIO
    try:
        if os.path.exists(INVENTORY_FILE):
            with open(INVENTORY_FILE, 'r') as f:
                devices = json.load(f)
        else:
            logger.warning("⚠️ No se encontró inventario. Usando lista vacía.")
    except Exception as e:
        logger.error(f"❌ Error leyendo inventario: {e}")
        return []

    logger.info(f"🚀 Iniciando escaneo para {len(devices)} dispositivos...")

    # ==============================================================================
    # 🛡️ MODO HARDCORE/DEMO: INYECCIÓN DE VULNERABILIDADES FALSAS PARA LA DEMO
    # Esto asegura que el ataque a la 192.168.1.50 SIEMPRE muestre riesgo CRÍTICO
    # ==============================================================================
    
    # Buscamos si nuestra víctima está en el inventario
    target_ip = "192.168.1.50"
    victim_device = next((d for d in devices if d.get('ip') == target_ip), None)
    
    if victim_device:
        logger.info(f"💀 INYECTANDO CVE CRÍTICO PARA DEMO EN: {target_ip}")
        report.append({
            "ip": target_ip,
            "device": victim_device.get("name", "PLC_Simulado"),
            "cve_id": "CVE-2024-9999-DEMO", # ID Ficticio para demo
            "description": "VULNERABILIDAD CRÍTICA SIMULADA: Desbordamiento de búfer en pila Modbus TCP permitiendo ejecución remota de código (RCE) y parada de proceso.",
            "severity": "CRITICAL",
            "score": 10.0,
            "link": "https://nvd.nist.gov/vuln-metrics/cvss"
        })
    # ==============================================================================

    # 2. ESCANEO REAL (NIST API)
    NIST_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    for device in devices:
        # Extraemos datos con seguridad
        name = device.get("name")
        ip = device.get("ip", "0.0.0.0")
        
        # Saltamos la IP de demo para no duplicar (o si prefieres, déjalo para tener más CVEs)
        if ip == target_ip: 
            continue 

        if not name: continue

        logger.info(f"🔎 Consultando NIST para: '{name}' ({ip})")
        
        params = {'keywordSearch': name, 'resultsPerPage': 1} # Solo 1 para ir rápido
        headers = {'User-Agent': 'SIS-Project/1.0'}

        try:
            response = requests.get(NIST_API_URL, params=params, headers=headers, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get("vulnerabilities", [])
                
                if vulnerabilities:
                    item = vulnerabilities[0] # Tomamos la primera/más reciente
                    cve = item.get("cve", {})
                    metrics = cve.get("metrics", {})
                    
                    # Intentar obtener score V3.1, V3.0 o V2
                    cvss = {}
                    if "cvssMetricV31" in metrics: cvss = metrics["cvssMetricV31"][0].get("cvssData", {})
                    elif "cvssMetricV30" in metrics: cvss = metrics["cvssMetricV30"][0].get("cvssData", {})
                    elif "cvssMetricV2" in metrics: cvss = metrics["cvssMetricV2"][0].get("cvssData", {})

                    report.append({
                        "ip": ip,
                        "device": name,
                        "cve_id": cve.get("id", "N/A"),
                        "description": cve.get("descriptions", [{}])[0].get("value", "Sin descripción"),
                        "severity": cvss.get("baseSeverity", "MEDIUM"), # Default Medium si no hay datos
                        "score": cvss.get("baseScore", 5.0),
                        "link": f"https://nvd.nist.gov/vuln/detail/{cve.get('id')}"
                    })
                    logger.info(f"   ✅ Encontrado: {cve.get('id')}")
                else:
                    logger.info("   ℹ️ Sin CVEs reportados.")
            
            time.sleep(2) # Respetar rate limit de NIST

        except Exception as e:
            logger.error(f"   ⚠️ Error de conexión NIST: {e}")

    return report

if __name__ == "__main__":
    # Ejecutar lógica
    vuln_data = scan_vulnerabilities()
    
    # 3. GUARDAR CSV (Compatible con Dashboard)
    # Definimos columnas fijas para que siempre tenga el mismo orden
    csv_columns = ["ip", "device", "cve_id", "description", "severity", "score", "link"]
    
    try:
        with open(REPORT_FILE, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=csv_columns)
            writer.writeheader()
            if vuln_data:
                writer.writerows(vuln_data)
        
        logger.info(f"💾 Reporte guardado en: {REPORT_FILE}")
        logger.info(f"📊 Total Vulnerabilidades: {len(vuln_data)}")
        
    except Exception as e:
        logger.error(f"❌ Error escribiendo CSV: {e}")
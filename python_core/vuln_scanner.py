import requests
import json
import time
import logging
import sys
import csv  # <--- IMPORTANTE: Necesitamos esto para escribir el archivo

# Configuración de logs
logger = logging.getLogger()
logger.setLevel(logging.INFO)
handler = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter('DEBUG-SCANNER: %(asctime)s - %(message)s')
handler.setFormatter(formatter)
if not logger.handlers:
    logger.addHandler(handler)

def scan_vulnerabilities(inventory_file):
    report = []
    
    try:
        with open(inventory_file, 'r') as f:
            data = json.load(f)
            devices = data.get("devices", [])
    except Exception as e:
        logger.error(f"❌ Error crítico leyendo archivo de inventario: {e}")
        return []

    NIST_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    logger.info(f"🚀 Iniciando escaneo para {len(devices)} dispositivos...")

    for device in devices:
        # Detectar si es texto o diccionario
        if isinstance(device, dict):
            name = device.get("name")
        elif isinstance(device, str):
            name = device
        else:
            continue
            
        if not name:
            continue
            
        logger.info(f"--------------------------------------------------")
        logger.info(f"🔍 Consultando: '{name}'")
        
        params = {'keywordSearch': name, 'resultsPerPage': 5}
        headers = {'User-Agent': 'SIS-Academic-Project/1.0'}

        try:
            logger.info(f"📡 Conectando a NIST...")
            response = requests.get(NIST_API_URL, params=params, headers=headers, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get("vulnerabilities", [])
                logger.info(f"✅ Resultados encontrados: {len(vulnerabilities)}")

                for item in vulnerabilities:
                    cve_item = item.get("cve", {})
                    cve_id = cve_item.get("id", "N/A")
                    
                    descriptions = cve_item.get("descriptions", [])
                    desc_text = descriptions[0].get("value", "Sin descripción") if descriptions else "Sin descripción"
                    
                    metrics = cve_item.get("metrics", {})
                    cvss_data = {}
                    if "cvssMetricV31" in metrics:
                        cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
                    elif "cvssMetricV30" in metrics:
                        cvss_data = metrics["cvssMetricV30"][0].get("cvssData", {})
                    elif "cvssMetricV2" in metrics:
                         cvss_data = metrics["cvssMetricV2"][0].get("cvssData", {})
                    
                    score = cvss_data.get("baseScore", 0.0)
                    severity = cvss_data.get("baseSeverity", "UNKNOWN")

                    report.append({
                        "device": name,
                        "cve_id": cve_id,
                        "description": desc_text,
                        "severity": severity,
                        "score": score,
                        "link": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                    })
            else:
                logger.error(f"❌ Error HTTP: {response.status_code}")

        except Exception as e:
            logger.error(f"🔌 Error de red: {e}")
        
        time.sleep(6)

    logger.info(f"🏁 Escaneo finalizado. Total CVEs en memoria: {len(report)}")
    return report

if __name__ == "__main__":
    # 1. Ejecutar el escaneo
    results = scan_vulnerabilities("ot_inventory.json")
    
    # 2. GUARDAR LOS RESULTADOS EN CSV (¡ESTO FALTABA!)
    csv_filename = "cve_report.csv"
    try:
        if results:
            keys = results[0].keys()
            with open(csv_filename, 'w', newline='', encoding='utf-8') as f:
                dict_writer = csv.DictWriter(f, fieldnames=keys)
                dict_writer.writeheader()
                dict_writer.writerows(results)
            logger.info(f"💾 EXITO: Reporte guardado en '{csv_filename}'. El Dashboard ya puede leerlo.")
        else:
            # Si no hay resultados, creamos un archivo vacío con cabeceras para no romper el dashboard
            with open(csv_filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(["device", "cve_id", "description", "severity", "score", "link"])
            logger.warning("⚠️ Sin vulnerabilidades. Se generó reporte vacío.")
            
    except Exception as e:
        logger.error(f"❌ Error guardando el archivo CSV: {e}")
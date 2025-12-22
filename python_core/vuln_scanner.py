import requests
import pandas as pd
import os
import sys

# Importamos la función de carga desde el script vecino
try:
    from inventory_manager import load_inventory
except ImportError:
    print("❌ Error: No se encuentra 'inventory_manager.py'. Asegúrate de que está en la misma carpeta.")
    sys.exit(1)

# API del NIST (NVD)
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Ubicación del reporte (También lo guardamos en la raíz para que el Dashboard lo vea)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORT_FILE = os.path.join(BASE_DIR, "cve_report.csv")

def check_cves(keyword):
    print(f"🔍 Buscando vulnerabilidades para: {keyword}...")
    try:
        params = {
            'keywordSearch': keyword,
            'resultsPerPage': 5,
            'sortOrder': 'DESC',
        }
        
        # Timeout de 10s
        r = requests.get(NVD_API_URL, params=params, timeout=10)
        
        if r.status_code != 200:
            print(f"⚠️ Error API NVD ({r.status_code}) para {keyword}")
            return []

        data = r.json()
        vulnerabilities = []

        for item in data.get('vulnerabilities', []):
            cve = item['cve']
            metrics = cve.get('metrics', {})
            
            score = 0.0
            severity = "UNKNOWN"
            
            if 'cvssMetricV31' in metrics:
                data_v3 = metrics['cvssMetricV31'][0]['cvssData']
                score = data_v3['baseScore']
                severity = data_v3['baseSeverity']
            elif 'cvssMetricV2' in metrics:
                data_v2 = metrics['cvssMetricV2'][0]['cvssData']
                score = data_v2['baseScore']
                severity = "HIGH" if score >= 7.0 else "MEDIUM"

            vulnerabilities.append({
                "Dispositivo": keyword,
                "CVE ID": cve['id'],
                "Severidad": severity,
                "Score": score,
                "Descripción": cve['descriptions'][0]['value'][:150] + "...",
                "Publicado": cve['published'][:10],
                "Link": f"https://nvd.nist.gov/vuln/detail/{cve['id']}"
            })
            
        return vulnerabilities

    except Exception as e:
        print(f"❌ Error conectando a NVD: {e}")
        return []

def run_scan():
    print("🚀 Iniciando escaneo de vulnerabilidades OT...")
    
    # 1. Cargar inventario dinámico
    target_devices = load_inventory()
    
    if not target_devices:
        print("⚠️ El inventario está vacío.")
        return

    all_vulns = []
    
    # 2. Escanear cada dispositivo
    for device in target_devices:
        vulns = check_cves(device)
        all_vulns.extend(vulns)
    
    # 3. Guardar resultados
    if all_vulns:
        df = pd.DataFrame(all_vulns)
        df.sort_values(by="Score", ascending=False, inplace=True)
        df.to_csv(REPORT_FILE, index=False)
        print(f"✅ Reporte generado en: {REPORT_FILE} ({len(all_vulns)} hallazgos)")
    else:
        print("✅ No se encontraron vulnerabilidades recientes.")
        # Crear CSV vacío con cabeceras para que el dashboard no falle
        empty_df = pd.DataFrame(columns=["Dispositivo", "CVE ID", "Severidad", "Score", "Descripción", "Publicado", "Link"])
        empty_df.to_csv(REPORT_FILE, index=False)

if __name__ == "__main__":
    run_scan()
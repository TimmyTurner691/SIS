import streamlit as st
import pandas as pd
from elasticsearch import Elasticsearch
import plotly.express as px
import plotly.graph_objects as go
import datetime
import os
import json
import time
import subprocess

# --- CONFIGURACIÓN DE PÁGINA ---
st.set_page_config(
    page_title="SIS - SIEM Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- ESTILOS CSS ---
st.markdown("""
<style>
    .metric-card {border: 1px solid #e6e6e6; padding: 10px; border-radius: 5px;}
    .stMetric { background-color: #0E1117; padding: 10px; border-radius: 5px; border: 1px solid #333; }
</style>
""", unsafe_allow_html=True)

# --- CONFIGURACIÓN DE RUTAS (ADAPTADO A DOCKER) ---
# En docker-compose definimos working_dir: /app
INVENTORY_FILE = "/app/ot_inventory.json"
REPORT_FILE = "/app/cve_report.csv"
# El script está montado en /python_core según el docker-compose
SCANNER_SCRIPT = "/python_core/vuln_scanner.py"

# --- CONEXIÓN ELASTICSEARCH ---
try:
    es = Elasticsearch("http://elasticsearch:9200")
except:
    st.error("🚨 Error de conexión con Elasticsearch")
    es = None

# --- FUNCIONES DE CARGA ---

def get_data(minutes=60, start=None, end=None, limit=5000):
    """Obtiene logs de Elasticsearch"""
    if not es: return pd.DataFrame()

    if start and end:
        start_dt = datetime.datetime.combine(start, datetime.time.min)
        end_dt = datetime.datetime.combine(end, datetime.time.max)
        time_range = {"gte": start_dt.isoformat(), "lte": end_dt.isoformat()}
    else:
        time_range = {"gte": f"now-{minutes}m/m"}

    query = {
        "query": {"range": {"@timestamp": time_range}},
        "sort": [{"@timestamp": "desc"}],
        "size": limit
    }

    try:
        res = es.search(index="sis-logs-v1", body=query)
        hits = [h['_source'] for h in res['hits']['hits']]
        df = pd.DataFrame(hits)

        if not df.empty:
            df['@timestamp'] = pd.to_datetime(df['@timestamp'])
            if 'ai_score' not in df.columns: df['ai_score'] = 0.0
            df['ai_score'] = df['ai_score'].fillna(0.0)
            df['risk_score'] = df['ai_score'].apply(lambda x: abs(x) * 1000 if x < 0 else 0)

            if 'dst_ip' in df.columns and 'protocol' in df.columns:
                df['Target'] = df['dst_ip'].astype(str) + ":" + df['protocol'].astype(str)
            else:
                df['Target'] = "Desconocido"
            return df
        else:
            return pd.DataFrame()
    except Exception as e:
        return pd.DataFrame()

def cargar_reporte_cve():
    """Lee el CSV de vulnerabilidades SIN CACHÉ para ver cambios al instante"""
    if not os.path.exists(REPORT_FILE):
        return pd.DataFrame()
    
    try:
        df = pd.read_csv(REPORT_FILE)
        return df
    except Exception as e:
        st.error(f"Error leyendo archivo CSV: {e}")
        return pd.DataFrame()

# --- SIDEBAR ---
st.sidebar.title("🎛️ Centro de Comando")
modo = st.sidebar.radio("Vista", ["En Vivo (Live)", "Históricos"])

df = pd.DataFrame()

if modo == "En Vivo (Live)":
    rango = st.sidebar.slider("Ventana (minutos)", 5, 1440, 60)
    if st.sidebar.button("🔄 Actualizar") or True:
        st.cache_data.clear()
        df = get_data(minutes=rango)
        st.title(f"📡 Monitoreo en Tiempo Real (Últimos {rango} min)")
else:
    col1, col2 = st.sidebar.columns(2)
    fecha_inicio = col1.date_input("Inicio", datetime.date.today())
    fecha_fin = col2.date_input("Fin", datetime.date.today())
    if st.sidebar.button("🔍 Buscar Historial"):
        df = get_data(start=fecha_inicio, end=fecha_fin, limit=10000)
        st.title("📂 Análisis Forense (Histórico)")


# --- PESTAÑAS PRINCIPALES ---
tab_ia, tab_snort, tab_zeek, tab_iec, tab_vuln, tab_raw = st.tabs([
    "🧠 IA & Riesgo", 
    "🛡️ Alertas IDS", 
    "🌐 Tráfico Red", 
    "🏭 Industrial (SCADA)", 
    "⚠️ CVEs & Inventario", 
    "📝 Logs"
])

# ==========================================
# PESTAÑA 1: IA
# ==========================================
with tab_ia:
    if df.empty:
        st.info("Esperando datos de tráfico para IA...")
    else:
        st.markdown("### 🧬 Detección de Amenazas")
        avg_risk = df['risk_score'].mean()
        max_risk = df['risk_score'].max()
        
        kpi1, kpi2, kpi3 = st.columns(3)
        kpi1.metric("Nivel de Amenaza Global", f"{avg_risk:.1f}/100")
        kpi2.metric("Pico Máximo", f"{max_risk:.1f}/100")
        kpi3.metric("Eventos Analizados", len(df))
        
        st.markdown("---")
        
        col1, col2 = st.columns([1,2])
        with col1:
             fig_gauge = go.Figure(go.Indicator(
                mode = "gauge+number",
                value = min(max_risk, 100),
                title = {'text': "Probabilidad de Ataque"},
                gauge = {'axis': {'range': [None, 100]}, 'bar': {'color': "darkred"}}
            ))
             st.plotly_chart(fig_gauge, use_container_width=True)
        with col2:
             if 'src_ip' in df.columns:
                st.plotly_chart(px.histogram(df, x="src_ip", y="risk_score", title="Riesgo por IP Origen"), use_container_width=True)

# ==========================================
# PESTAÑA 2: SNORT
# ==========================================
with tab_snort:
    if not df.empty and not df[df['source'] == 'snort'].empty:
        st.dataframe(df[df['source'] == 'snort'], use_container_width=True)
    else:
        st.info("Sin alertas de Snort.")

# ==========================================
# PESTAÑA 3: ZEEK
# ==========================================
with tab_zeek:
    if not df.empty:
        df_zeek = df[(df['source'] == 'zeek') & (df.get('protocol') != 'iec104')]
        st.dataframe(df_zeek.head(100), use_container_width=True)
    else:
        st.info("Sin datos de red.")

# ==========================================
# PESTAÑA 4: INDUSTRIAL
# ==========================================
with tab_iec:
    if not df.empty:
        mask_iec = (df['sub_source'] == 'zeek_iec104') | (df.get('protocol') == 'iec104')
        df_iec = df[mask_iec]
        if not df_iec.empty:
            st.metric("Paquetes SCADA", len(df_iec))
            st.dataframe(df_iec, use_container_width=True)
        else:
            st.info("Esperando tráfico IEC-104...")
    else:
        st.info("Sin datos.")

# ==========================================
# PESTAÑA 5: VULNERABILIDADES (CORREGIDA)
# ==========================================
with tab_vuln:
    st.header("🛡️ Gestión de Vulnerabilidades Industrial (OT)")
    
    col_inv, col_scan = st.columns([1, 2])

    # --- IZQUIERDA: INVENTARIO JSON ---
    with col_inv:
        st.subheader("🏭 Inventario de Activos")
        
        # Cargar JSON
        current_inv = []
        if os.path.exists(INVENTORY_FILE):
            try:
                with open(INVENTORY_FILE, 'r') as f:
                    data = json.load(f)
                    # Manejo flexible: si es lista de strings o lista de objetos
                    raw_list = data.get("devices", [])
                    current_inv = []
                    for item in raw_list:
                        if isinstance(item, dict): current_inv.append(item.get("name"))
                        else: current_inv.append(str(item))
            except:
                st.error("Error leyendo JSON.")
        
        # Multiselect para ver/borrar
        selected_devices = st.multiselect("Equipos:", options=current_inv, default=current_inv)
        
        # Guardar cambios (borrado)
        if len(selected_devices) < len(current_inv):
            if st.button("💾 Actualizar Inventario"):
                # Guardamos siempre como objetos para compatibilidad futura
                save_data = {"devices": [{"name": d} for d in selected_devices]}
                with open(INVENTORY_FILE, 'w') as f:
                    json.dump(save_data, f, indent=4)
                st.rerun()
        
        st.divider()
        new_dev = st.text_input("Agregar equipo:", placeholder="Ej: Siemens S7-1200")
        if st.button("➕ Agregar"):
            if new_dev and new_dev not in selected_devices:
                # Leemos, agregamos y guardamos formato objeto
                try:
                    with open(INVENTORY_FILE, 'r') as f:
                        d = json.load(f)
                        devs = d.get("devices", [])
                    
                    devs.append({"name": new_dev})
                    
                    with open(INVENTORY_FILE, 'w') as f:
                        json.dump({"devices": devs}, f, indent=4)
                    st.success(f"Agregado: {new_dev}")
                    time.sleep(1)
                    st.rerun()
                except Exception as e:
                    st.error(f"Error al guardar: {e}")

    # --- DERECHA: REPORTE CSV ---
    with col_scan:
        st.subheader("🔍 Escaneo de Seguridad (NIST/NVD)")
        
        if st.button("🔄 Ejecutar Escaneo de Vulnerabilidades"):
            with st.spinner("Contactando NIST... esto puede tomar unos segundos."):
                try:
                    # Usamos subprocess para mejor control
                    result = subprocess.run(
                        ["python3", SCANNER_SCRIPT],
                        capture_output=True,
                        text=True
                    )
                    
                    if result.returncode == 0:
                        st.success("✅ Escaneo completado.")
                    else:
                        st.error("❌ Error en el script del scanner")
                        st.code(result.stderr)
                        
                except Exception as e:
                    st.error(f"No se pudo ejecutar el script: {e}")

        # Cargar datos frescos
        df_cve = cargar_reporte_cve()

        if not df_cve.empty and 'severity' in df_cve.columns:
            # Métricas
            c1, c2, c3 = st.columns(3)
            # Filtramos asegurando mayúsculas para evitar errores de case sensitive
            criticas = len(df_cve[df_cve['severity'].str.upper() == 'CRITICAL'])
            altas = len(df_cve[df_cve['severity'].str.upper() == 'HIGH'])
            
            c1.metric("Críticas", criticas)
            c2.metric("Altas", altas)
            c3.metric("Total Hallazgos", len(df_cve))

            # Estilos de colores para la tabla
            def color_severity(val):
                val = str(val).upper()
                if val == 'CRITICAL': return 'background-color: #ff4b4b; color: white'
                elif val == 'HIGH': return 'background-color: #ffa500; color: black'
                return ''

            # Mostrar tabla
            try:
                st.dataframe(
                    df_cve.style.applymap(color_severity, subset=['severity']),
                    use_container_width=True,
                    column_config={
                        "link": st.column_config.LinkColumn("Enlace NVD"),
                        "score": st.column_config.ProgressColumn("CVSS", min_value=0, max_value=10, format="%.1f"),
                        "device": "Dispositivo",
                        "severity": "Severidad",
                        "description": "Descripción CVE"
                    },
                    hide_index=True
                )
            except Exception as e:
                st.warning("No se pudo aplicar estilos a la tabla, mostrando datos crudos:")
                st.dataframe(df_cve)

        else:
            st.info("ℹ️ No hay reporte disponible o no se encontraron vulnerabilidades.")
            
            # Debug Expander para ver si el archivo tiene algo raro
            with st.expander("🛠️ Debug - Ver contenido del archivo CSV"):
                if os.path.exists(REPORT_FILE):
                    with open(REPORT_FILE, "r") as f:
                        st.text(f.read())
                else:
                    st.text("El archivo CSV no existe.")

# ==========================================
# PESTAÑA 6: LOGS RAW
# ==========================================
with tab_raw:
    if not df.empty:
        st.dataframe(df)
    else:
        st.info("Sin logs disponibles.")
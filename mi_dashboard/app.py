import streamlit as st
import pandas as pd
from elasticsearch import Elasticsearch
import plotly.express as px
import datetime
import os
import json
import subprocess
import re
import time
import redis  # <--- NUEVO: Necesario para enviar comandos

# --- CONFIGURACIÓN ---
st.set_page_config(page_title="SIS - SIEM Dashboard", page_icon="🛡️", layout="wide")

# CSS para Tarjetas de Riesgo
st.markdown("""
<style>
    .risk-card-critical { border-left: 5px solid #ff4b4b; background-color: #262730; padding: 15px; border-radius: 5px; margin-bottom: 10px; }
    .risk-card-medium { border-left: 5px solid #ffa500; background-color: #262730; padding: 15px; border-radius: 5px; margin-bottom: 10px; }
    .mitre-badge { background-color: #0e1117; padding: 2px 8px; border-radius: 4px; border: 1px solid #444; font-size: 0.8em; margin-right: 5px; }
    .stSpinner { text-align: center; }
</style>
""", unsafe_allow_html=True)

INVENTORY_FILE = "/app/ot_inventory.json"
REPORT_FILE = "/app/cve_report.csv"
SCANNER_SCRIPT = "/python_core/vuln_scanner.py"

# --- CONEXIONES (ELASTIC Y REDIS) ---
try: 
    es = Elasticsearch("http://elasticsearch:9200")
except: 
    es = None

# Conexión a Redis para el Panel de Control
try:
    r = redis.Redis(host='redis', port=6379, db=0, decode_responses=True)
except:
    r = None

# ==========================================
# LÓGICA DE NEGOCIO (HELPER FUNCTIONS)
# ==========================================
# ... (Sin cambios en get_data, lógica_interpretar_scada_fallback, etc.) ...
def get_data(minutes=60, start=None, end=None, limit=5000):
    # Definimos las columnas obligatorias ANTES de cualquier cosa
    cols_blindadas = [
        'protocol', 'src_port', 'dst_port', 'src_ip', 'dst_ip', 'conn_state',
        'risk_total_score', 'risk_label', 'mitre_msg', 'source', 'sub_source', 
        'ai_score', 'raw_log', 'mitre_tactics', 'mitre_techniques',
        'comando_humano', '@timestamp'
    ]

    if not es: 
        return pd.DataFrame(columns=cols_blindadas)
    
    # 1. Construir Query de Tiempo
    if start and end:
        time_range = {"gte": datetime.datetime.combine(start, datetime.time.min).isoformat(),
                      "lte": datetime.datetime.combine(end, datetime.time.max).isoformat()}
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
        
        if not hits:
            return pd.DataFrame(columns=cols_blindadas)
            
        df = pd.DataFrame(hits)
        
        # --- ZONA DE BLINDAJE ---
        for col in cols_blindadas:
            if col not in df.columns:
                df[col] = "N/A"
                
        # Conversiones numéricas
        df['risk_total_score'] = pd.to_numeric(df['risk_total_score'], errors='coerce').fillna(0)
        df['ai_score'] = pd.to_numeric(df['ai_score'], errors='coerce').fillna(0.5)

        # Procesamiento de Fechas
        df['@timestamp'] = pd.to_datetime(df['@timestamp'])
        if df['@timestamp'].dt.tz is None:
            df['@timestamp'] = df['@timestamp'].dt.tz_localize('UTC')
        df['@timestamp'] = df['@timestamp'].dt.tz_convert('America/Santiago')
        
        # Limpieza visual de listas
        if 'mitre_tactics' in df.columns:
            df['mitre_tactics'] = df['mitre_tactics'].apply(lambda x: ", ".join(x) if isinstance(x, list) else str(x))
        
        return df

    except Exception as e:
        print(f"Error recuperando datos: {e}")
        return pd.DataFrame(columns=cols_blindadas)

def lógica_interpretar_scada_fallback(row):
    val_backend = str(row.get('comando_humano', 'N/A'))
    if val_backend != "N/A" and val_backend != "nan":
        return val_backend
    texto_raw = (str(row.get('raw_log', '')) + " " + str(row.get('message', ''))).upper()
    texto = f" {texto_raw} " 
    if 'STARTDT' in texto: return "🟢 Inicio Conexión"
    if 'STOPDT' in texto:  return "🔴 Fin Conexión"
    if 'TESTFR' in texto:  return "💓 Latido / Test"
    if 'C_IC' in texto: return "❓ Interrogación General"
    if 'M_SP' in texto: return "📡 Info Punto Simple"
    if 'C_SC' in texto: return "⚙️ Comando Control (Switch)"
    return "📦 Tráfico Industrial"

def lógica_calcular_anomalia_pct(valor):
    try:
        val = float(valor)
        return int(abs(val) * 100) if val < 0 else 0
    except: return 0

def lógica_limpiar_snort_msg(row):
    raw = str(row.get('raw_log', ''))
    match = re.search(r'\[\d+:\d+:\d+\]\s+(.*)', raw)
    if match:
        msg = match.group(1).strip()
        if msg == "[TEST]": return "⚠️ Alerta de Prueba (TEST)"
        return msg.replace('[**]', '').strip()
    return raw.replace('[**]', '').split('] ')[-1]

# ==========================================
# INTERFAZ DE USUARIO
# ==========================================

st.sidebar.title("🎛️ Centro de Comando")

# --- NUEVO: SECCIÓN CONTROL NEURAL ---
with st.sidebar.expander("🧠 Control IA & Memoria", expanded=True):
    st.markdown("Gestión del Cerebro:")
    
    if st.button("♻️ RESET TOTAL (Borrar Memoria)", type="primary"):
        if r:
            try:
                # 1. Enviar orden al cerebro
                r.set("cmd_reset_brain", "true")
                # 2. Borrar la cola de tráfico pendiente (sis_queue)
                r.delete("sis_queue")
                st.success("Orden enviada: Memoria borrada y Cola vaciada.")
                time.sleep(1)
                st.rerun()
            except Exception as e:
                st.error(f"Error Redis: {e}")
        else:
            st.error("No hay conexión con Redis.")

    if st.button("🎓 Forzar Re-entrenamiento"):
        if r:
            r.set("cmd_force_train", "true")
            st.info("Solicitud enviada.")

# -------------------------------------

modo = st.sidebar.radio("Vista", ["En Vivo", "Histórico"])
df = pd.DataFrame()

# Variables de auto-refresh
auto_refresh = False
refresh_rate = 5

if modo == "En Vivo":
    st.sidebar.markdown("### ⏱️ Control de Tiempo")
    mins = st.sidebar.slider("Ventana de Datos (Min)", 5, 1440, 60)
    
    c_auto, c_sec = st.sidebar.columns([1, 1])
    with c_auto:
        auto_refresh = st.toggle("Auto-Refresh", value=True) 
    with c_sec:
        refresh_rate = st.number_input("Segundos", min_value=1, max_value=60, value=2)

    if st.sidebar.button("🔄 Refrescar Manual"):
        st.cache_data.clear()

    # Carga de datos
    st.cache_data.clear() 
    df = get_data(minutes=mins)
    
    st.title(f"🛡️ SIS - SIEM Dashboard (En Vivo)")
    if auto_refresh:
        st.caption(f"Actualizando automáticamente cada {refresh_rate} segundos...")

else:
    d1 = st.sidebar.date_input("Inicio"); d2 = st.sidebar.date_input("Fin")
    if st.sidebar.button("Buscar"):
        df = get_data(start=d1, end=d2)

# ==========================================
# PESTAÑAS Y VISUALIZACIÓN (Sin cambios abajo)
# ==========================================
tab_risk, tab_snort, tab_net, tab_ot, tab_vuln, tab_raw = st.tabs([
    "🚨 Fusión de Riesgos", "🛡️ IDS", "🌐 Red", "🏭 SCADA", "⚠️ Vulnerabilidades", "📝 Logs Raw"
])

# ---------------- PESTAÑA 1: RIESGOS ----------------
with tab_risk:
    if df.empty:
        st.warning("⚠️ Esperando datos... (Si acabas de resetear, espera a que llegue tráfico nuevo)")
    else:
        k1, k2, k3, k4 = st.columns(4)
        
        max_score = df['risk_total_score'].max()
        criticos = len(df[df['risk_total_score'] >= 17])
        
        peor_score_ia = df['ai_score'].min() if 'ai_score' in df.columns else 0
        nivel_anomalia_kpi = lógica_calcular_anomalia_pct(peor_score_ia)
            
        activos = df['dst_ip'].nunique() if 'dst_ip' in df.columns else 0

        k1.metric("Riesgo Máximo", f"{max_score}/25")
        k2.metric("Incidentes Críticos", criticos)
        k3.metric("Nivel Anomalía IA", f"{nivel_anomalia_kpi}%", 
                  delta="CRÍTICO" if nivel_anomalia_kpi > 60 else "Normal", 
                  delta_color="inverse")
        k4.metric("Activos Afectados", activos)

        st.divider()

        col_incidents = st.columns(1)[0]
        with col_incidents:
            st.subheader("Últimos Incidentes Detectados")
            df_risk = df[df['risk_total_score'] >= 8].drop_duplicates(subset=['src_ip', 'mitre_msg']).head(5)
            
            if df_risk.empty:
                st.success("✅ Sistema estable. No hay incidentes de riesgo Medio/Alto.")
            
            for index, row in df_risk.iterrows():
                css_class = "risk-card-critical" if row['risk_total_score'] >= 17 else "risk-card-medium"
                icon = "🚨" if row['risk_total_score'] >= 17 else "⚠️"
                anomalia_pct_row = lógica_calcular_anomalia_pct(row['ai_score'])
                impacto = row.get('risk_impact', 0)
                tactica = row.get('mitre_tactics', 'N/A')
                msg = row.get('mitre_msg', 'Detectado por Reglas')

                html_content = f"""
                <div class="{css_class}">
                    <h4>{icon} {row['risk_label']} ({row['risk_total_score']}/25) - {row.get('src_ip')} ➡️ {row.get('dst_ip')}</h4>
                    <p><b>Diagnóstico:</b> {msg}</p>
                    <p>
                        <span class="mitre-badge">🤖 IA: {anomalia_pct_row}% Anomalía</span>
                        <span class="mitre-badge">📚 MITRE: {tactica}</span>
                        <span class="mitre-badge">🏭 Impacto: {impacto}/5</span>
                    </p>
                </div>
                """
                st.markdown(html_content, unsafe_allow_html=True)

        st.divider()
        col_viz = st.columns(1)[0]
        with col_viz:
            st.subheader("Matriz de Calor")
            if not df.empty and 'risk_impact' in df.columns and 'risk_probability' in df.columns:
                fig = px.density_heatmap(
                    df, x="risk_impact", y="risk_probability", nbinsx=5, nbinsy=5, 
                    title="Amenaza (Y) vs Impacto (X)", range_x=[0.5, 5.5], range_y=[0.5, 5.5], color_continuous_scale="Reds"
                )
                st.plotly_chart(fig, use_container_width=True)

# ... (El resto de las pestañas sigue igual) ...
# Pestaña Snort
with tab_snort:
    if not df.empty and 'source' in df.columns:
        df_snort = df[df['source'] == 'snort'].copy()
        if not df_snort.empty:
            df_snort['mensaje_limpio'] = df_snort.apply(lógica_limpiar_snort_msg, axis=1)
            st.dataframe(df_snort[['@timestamp', 'mensaje_limpio', 'risk_label', 'risk_total_score', 'src_ip', 'dst_ip']], 
                         use_container_width=True, hide_index=True)
        else: st.info("✅ No hay alertas de Snort.")
    else: st.info("✅ Sin alertas.")

# Pestaña Red
with tab_net:
    if not df.empty:
        mask_net = (df['source'] == 'zeek') & (df['protocol'] != 'iec104')
        df_net = df[mask_net].copy()
        if not df_net.empty:
            st.dataframe(df_net[['@timestamp', 'protocol', 'src_ip', 'dst_ip', 'dst_port', 'conn_state']], 
                         use_container_width=True, hide_index=True)
        else: st.info("✅ Sin tráfico de red general.")

# Pestaña OT
with tab_ot:
    if not df.empty:
        mask_ot = ((df['protocol'] == 'iec104') | (df['dst_port'].astype(str).isin(['2404', '502', '102'])) | (df.get('sub_source') == 'zeek_iec104'))
        df_ot = df[mask_ot].copy()

        if not df_ot.empty:
            df_ot['comando_humano'] = df_ot.apply(lógica_interpretar_scada_fallback, axis=1)
            df_ot['ia_pct'] = df_ot['ai_score'].apply(lógica_calcular_anomalia_pct)
            st.dataframe(df_ot[['@timestamp', 'comando_humano', 'src_ip', 'dst_ip', 'risk_total_score', 'ia_pct']].head(50), 
                         use_container_width=True, hide_index=True)
        else:
            st.info("🏭 Esperando tráfico industrial...")
    else:
        st.info("🏭 Esperando datos...")

# Pestaña Vuln
with tab_vuln:
    st.header("🛡️ Gestión de Vulnerabilidades")
    c1, c2 = st.columns([1, 2])
    
    with c1:
        st.subheader("📦 Inventario Operativo")
        with st.form("form_add_asset", clear_on_submit=True):
            st.markdown("#### ➕ Agregar Nuevo Activo")
            new_ip = st.text_input("Dirección IP", placeholder="Ej: 192.168.1.50")
            new_name = st.text_input("Nombre del Dispositivo", placeholder="Ej: PLC_Hornos")
            new_crit = st.selectbox("Nivel de Criticidad", ["LOW", "MEDIUM", "HIGH", "CRITICAL"])
            
            submitted = st.form_submit_button("💾 Guardar Activo")
            if submitted and new_ip and new_name:
                try:
                    current_data = []
                    if os.path.exists(INVENTORY_FILE):
                        with open(INVENTORY_FILE, 'r') as f:
                            try: current_data = json.loads(f.read())
                            except: pass
                    
                    current_data = [x for x in current_data if x.get('ip') != new_ip.strip()]
                    current_data.append({"ip": new_ip.strip(), "name": new_name.strip(), "criticality": new_crit})
                    
                    with open(INVENTORY_FILE, 'w') as f: json.dump(current_data, f, indent=4)
                    st.success(f"✅ Guardado: {new_name}")
                except Exception as e: st.error(f"❌ Error: {e}")

        st.divider()
        st.markdown("#### 📋 Activos Registrados")
        if os.path.exists(INVENTORY_FILE):
            try:
                with open(INVENTORY_FILE, 'r') as f:
                    inventory_data = json.load(f)
                if inventory_data:
                    st.dataframe(pd.DataFrame(inventory_data), use_container_width=True, hide_index=True)
                else: st.info("Inventario vacío.")
            except: st.warning("Error leyendo inventario.")

    with c2:
        st.subheader("🔍 Escáner de Vulnerabilidades (CVEs)")
        if st.button("🚀 Iniciar Escaneo", type="primary"):
            with st.spinner("Escaneando activos..."):
                try:
                    subprocess.run(["python3", SCANNER_SCRIPT], check=False)
                    st.success("Escaneo finalizado.")
                    st.cache_data.clear()
                except Exception as e: st.error(f"Error: {e}")
        
        if os.path.exists(REPORT_FILE):
            try:
                df_cve = pd.read_csv(REPORT_FILE, on_bad_lines='skip')
                if not df_cve.empty:
                    df_cve.columns = [c.lower().strip() for c in df_cve.columns]
                    st.dataframe(df_cve, use_container_width=True)
                else: st.info("✅ Reporte vacío.")
            except: st.error("Error leyendo reporte.")
        else: st.info("ℹ️ Sin reportes.")

# Pestaña Raw
with tab_raw:
    st.write("Datos crudos:")
    st.dataframe(df, use_container_width=True)

# ==========================================
# LÓGICA DE AUTO-REFRESH (AL FINAL)
# ==========================================
if modo == "En Vivo" and auto_refresh:
    time.sleep(refresh_rate)
    try:
        st.rerun() 
    except AttributeError:
        st.experimental_rerun()
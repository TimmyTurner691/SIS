import streamlit as st
import pandas as pd
from elasticsearch import Elasticsearch
import plotly.express as px
import plotly.graph_objects as go
import numpy as np
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

INVENTORY_FILE = os.getenv("SIS_DASHBOARD_INVENTORY_PATH", "/app/ot_inventory.json")
REPORT_FILE = os.getenv("SIS_DASHBOARD_REPORT_PATH", "/app/cve_report.csv")
SCANNER_SCRIPT = os.getenv("SIS_DASHBOARD_SCANNER_SCRIPT", "/python_core/vuln_scanner.py")
ES_HOST = os.getenv("SIS_DASHBOARD_ELASTIC_HOST", "elasticsearch")
ES_PORT = os.getenv("SIS_DASHBOARD_ELASTIC_PORT", "9200")
REDIS_HOST = os.getenv("SIS_DASHBOARD_REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("SIS_DASHBOARD_REDIS_PORT", "6379"))
INDEX_NAME = os.getenv("SIS_DASHBOARD_INDEX", "sis-logs-v1")

# --- CONEXIONES (ELASTIC Y REDIS) ---
try:
    es = Elasticsearch(f"http://{ES_HOST}:{ES_PORT}")
except Exception:
    es = None

# Conexión a Redis para el Panel de Control
try:
    r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=0, decode_responses=True)
except Exception:
    r = None

# ==========================================
# LÓGICA DE NEGOCIO (HELPER FUNCTIONS)
# ==========================================
# ... (Sin cambios en get_data, lógica_interpretar_scada_fallback, etc.) ...
def get_data(minutes=60, start=None, end=None, limit=5000):
    # Definimos las columnas obligatorias ANTES de cualquier cosa
    cols_blindadas = [
        'protocol', 'src_port', 'dst_port', 'src_ip', 'dst_ip', 'conn_state',
        'risk_total_score', 'risk_label', 'risk_impact', 'risk_probability',
        'mitre_msg', 'source', 'sub_source',
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
        res = es.search(index=INDEX_NAME, body=query)
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
        df['risk_impact'] = pd.to_numeric(df['risk_impact'], errors='coerce').fillna(1)
        df['risk_probability'] = pd.to_numeric(df['risk_probability'], errors='coerce').fillna(1)

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

def construir_matriz_riesgo(df):
    df = df.copy()

    df["risk_probability"] = pd.to_numeric(df["risk_probability"], errors="coerce").fillna(1).clip(1, 5).astype(int)
    df["risk_impact"] = pd.to_numeric(df["risk_impact"], errors="coerce").fillna(1).clip(1, 5).astype(int)

    conteo = (
        df.groupby(["risk_impact", "risk_probability"])
        .size()
        .reset_index(name="count")
    )

    matriz_conteo = np.zeros((5, 5), dtype=int)

    for _, row in conteo.iterrows():
        impacto = int(row["risk_impact"]) - 1
        prob = int(row["risk_probability"]) - 1
        matriz_conteo[impacto, prob] = int(row["count"])

    return matriz_conteo


def construir_matriz_niveles():
    """
    Matriz fija de colores:
    1 = verde
    2 = amarillo
    3 = naranjo
    4 = rojo

    Convención:
    filas = impacto (Y) de 1 a 5
    columnas = probabilidad (X) de 1 a 5
    """

    matriz_nivel = np.zeros((5, 5), dtype=int)

    # Verde:
    # 1x1-4 y 2x1-2
    verdes = [
        (1, 1), (1, 2), (1, 3), (1, 4),
        (2, 1), (2, 2)
    ]

    # Amarillo:
    # 1x5 y 2x3-5 y 3x1-3 y 4x1
    amarillos = [
        (1, 5),
        (2, 3), (2, 4), (2, 5),
        (3, 1), (3, 2), (3, 3),
        (4, 1)
    ]

    # Naranjo:
    # 3x4-5 y 4x2-3 y 5x1
    naranjos = [
        (3, 4), (3, 5),
        (4, 2), (4, 3),
        (5, 1)
    ]

    # Rojo:
    # 4x4-5 y 5x2-5
    rojos = [
        (4, 4), (4, 5),
        (5, 2), (5, 3), (5, 4), (5, 5)
    ]

    for impacto, probabilidad in verdes:
        matriz_nivel[impacto - 1, probabilidad - 1] = 1

    for impacto, probabilidad in amarillos:
        matriz_nivel[impacto - 1, probabilidad - 1] = 2

    for impacto, probabilidad in naranjos:
        matriz_nivel[impacto - 1, probabilidad - 1] = 3

    for impacto, probabilidad in rojos:
        matriz_nivel[impacto - 1, probabilidad - 1] = 4

    return matriz_nivel


def graficar_matriz_riesgo(df):
    matriz_conteo = construir_matriz_riesgo(df)

    etiquetas_x = ["1. Remota", "2. Improbable", "3. Probable", "4. Esperable", "5. Casi cierta"]
    etiquetas_y = ["1. Muy bajo", "2. Bajo", "3. Moderado", "4. Alto", "5. Crítico"]

    # Mapa fijo de colores por celda
    colores = {
        1: "#7CB342",  # verde
        2: "#FBC02D",  # amarillo
        3: "#FB8C00",  # naranjo
        4: "#EF5350",  # rojo
    }

    # Matriz fija según tus reglas
    niveles = {
        # Verde
        (1, 1): 1, (1, 2): 1, (1, 3): 1, (1, 4): 1,
        (2, 1): 1, (2, 2): 1,

        # Amarillo
        (1, 5): 2,
        (2, 3): 2, (2, 4): 2, (2, 5): 2,
        (3, 1): 2, (3, 2): 2, (3, 3): 2,
        (4, 1): 2,

        # Naranjo
        (3, 4): 3, (3, 5): 3,
        (4, 2): 3, (4, 3): 3,
        (5, 1): 3,

        # Rojo
        (4, 4): 4, (4, 5): 4,
        (5, 2): 4, (5, 3): 4, (5, 4): 4, (5, 5): 4,
    }

    fig = go.Figure()

    # Dibujar 25 rectángulos fijos
    for impacto in range(1, 6):          # Y
        for probabilidad in range(1, 6):  # X
            nivel = niveles[(impacto, probabilidad)]
            color = colores[nivel]

            x0 = probabilidad - 1
            x1 = probabilidad
            y0 = impacto - 1
            y1 = impacto

            fig.add_shape(
                type="rect",
                x0=x0, x1=x1,
                y0=y0, y1=y1,
                line=dict(color="white", width=2),
                fillcolor=color,
                layer="below"
            )

            conteo = int(matriz_conteo[impacto - 1, probabilidad - 1])

            fig.add_annotation(
                x=probabilidad - 0.5,
                y=impacto - 0.5,
                text=str(conteo),
                showarrow=False,
                font=dict(size=20, color="white")
            )

    fig.update_xaxes(
        tickmode="array",
        tickvals=[0.5, 1.5, 2.5, 3.5, 4.5],
        ticktext=etiquetas_x,
        range=[0, 5],
        title="Probabilidad",
        showgrid=False,
        zeroline=False
    )

    fig.update_yaxes(
        tickmode="array",
        tickvals=[0.5, 1.5, 2.5, 3.5, 4.5],
        ticktext=etiquetas_y,
        range=[0, 5],
        title="Impacto",
        showgrid=False,
        zeroline=False
    )

    fig.update_layout(
        title="Probabilidad (X) vs Impacto (Y)",
        template="plotly_dark",
        height=700,
        margin=dict(l=40, r=40, t=80, b=40),
        font=dict(size=16),
        paper_bgcolor="#0E1117",
        plot_bgcolor="#0E1117"
    )

    return fig

# ==========================================
# INTERFAZ DE USUARIO
# ==========================================

st.sidebar.title("🎛️ Centro de Comando")

# --- NUEVO: SECCIÓN CONTROL NEURAL ---
with st.sidebar.expander("🧠 Control IA & Memoria", expanded=True):
    st.markdown("Gestión del Cerebro:")

    if st.button("♻️ RESET IA", type="secondary"):
        if r:
            try:
                r.set("cmd_reset_brain", "true")
                r.delete("sis_queue")
                st.success("Orden enviada: memoria IA y cola vaciadas.")
                time.sleep(1)
                st.rerun()
            except Exception as e:
                st.error(f"Error Redis: {e}")
        else:
            st.error("No hay conexión con Redis.")

    if st.button("🧹 RESET DEMO TOTAL", type="primary"):
        if r:
            try:
                r.set("cmd_full_reset_demo", "true")
                r.delete("sis_queue")
                st.success("Orden enviada: reinicio total de demo solicitado.")
                time.sleep(1)
                st.rerun()
            except Exception as e:
                st.error(f"Error Redis: {e}")
        else:
            st.error("No hay conexión con Redis.")

    if st.button("🎓 Forzar Re-entrenamiento"):
        if r:
            try:
                r.set("cmd_force_train", "true")
                st.info("Solicitud enviada.")
            except Exception as e:
                st.error(f"Error Redis: {e}")
        else:
            st.error("No hay conexión con Redis.")

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
                fig = graficar_matriz_riesgo(df)
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
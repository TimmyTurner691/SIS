import streamlit as st
import pandas as pd
import plotly.express as px
import redis
import json
import time
import os
import re
from datetime import datetime

# ==========================================
# 1. CONFIGURACIÓN DE PÁGINA (Minimalista)
# ==========================================
st.set_page_config(
    page_title="SIS Monitor", 
    layout="wide", 
    page_icon="🛡️",
    initial_sidebar_state="collapsed"
)

# Estilos CSS Limpios
st.markdown("""
<style>
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    
    .big-metric { font-size: 50px !important; font-weight: bold; }
    .stProgress > div > div > div > div { background-color: #00b6ff; }
</style>
""", unsafe_allow_html=True)

# Rutas y Constantes
LOGO_PATH = 'sis_logo.png' 
SNORT_LOG_FILE = '/var/log/snort/alert'
ZEEK_CONN_LOG = '/var/log/zeek/conn.log'
ZEEK_IEC104_LOG = '/var/log/zeek/iec104.log'
COLOR_CELESTE = '#00b6ff'

# ==========================================
# 2. FUNCIONES DE DATOS (Backend)
# ==========================================

# --- REDIS (Cerebro) ---
try:
    r = redis.Redis(host='redis', port=6379, db=0, decode_responses=True)
except Exception as e:
    r = None

def obtener_estado_matriz():
    if not r: return None
    try:
        datos = r.get('sis:matriz_estado')
        if datos: return json.loads(datos)
    except: pass
    return None

# --- PARSEO DE LOGS ---
def clean_snort_timestamp(raw_ts):
    try:
        clean_str = raw_ts.split('.')[0] 
        dt_obj = datetime.strptime(clean_str, "%m/%d-%H:%M:%S")
        dt_obj = dt_obj.replace(year=datetime.now().year)
        return dt_obj.strftime("%Y-%m-%d %H:%M:%S")
    except: return raw_ts

def parse_snort_logs(filepath):
    data = []
    pattern = re.compile(r'^(\S+)\s+.*?\[\*\*\]\s+(.*?)\s+\[\*\*\]\s+.*?\{(.*?)\}\s+(\S+)\s+->\s+(\S+)')
    if not os.path.exists(filepath): return pd.DataFrame()
    try:
        with open(filepath, 'r') as f:
            lines = f.readlines()[-100:] 
            for line in reversed(lines):
                match = pattern.search(line)
                if match:
                    raw_ts, msg, proto, src, dst = match.groups()
                    data.append({
                        "timestamp": clean_snort_timestamp(raw_ts),
                        "alerta": msg,
                        "protocolo": proto,
                        "src_ip": src.split(':')[0],
                        "dst_ip": dst.split(':')[0]
                    })
    except: pass
    return pd.DataFrame(data)

def parse_zeek_logs(filepath):
    if not os.path.exists(filepath): return pd.DataFrame()
    try:
        df = pd.read_csv(filepath, sep='\t', comment='#', header=None, on_bad_lines='skip')
        if not df.empty and 0 in df.columns:
            df[0] = pd.to_datetime(df[0], unit='s').dt.strftime('%Y-%m-%d %H:%M:%S')
        return df
    except: return pd.DataFrame()

# ==========================================
# 3. CARGA DE DATOS
# ==========================================
estado = obtener_estado_matriz()
if not estado:
    estado = {"color": "VERDE", "riesgo_total": 0, "mensaje": "Esperando análisis...", "nivel": "BAJO"}

df_snort = parse_snort_logs(SNORT_LOG_FILE)
df_conn = parse_zeek_logs(ZEEK_CONN_LOG)
count_conn = len(df_conn) if not df_conn.empty else 0
df_iec104 = parse_zeek_logs(ZEEK_IEC104_LOG)
count_iec104 = len(df_iec104) if not df_iec104.empty else 0

# Colores Dinámicos
color_recibido = estado.get('color', 'VERDE')
riesgo_num = estado.get('riesgo_total', 0)

if color_recibido == "ROJO_CRITICO":
    texto_nivel = "CRÍTICO"
    color_css = "#ff2b2b"
elif color_recibido == "AMARILLO":
    texto_nivel = "ALERTA MEDIA"
    color_css = "#ffcc00"
else:
    texto_nivel = "BAJO / SEGURO"
    color_css = "#00cc44"

# ==========================================
# 4. DASHBOARD (Interfaz Limpia)
# ==========================================

# --- CABECERA SIMPLE ---
col_logo, col_titulo = st.columns([1, 10])

with col_logo:
    if os.path.exists(LOGO_PATH):
        st.image(LOGO_PATH, width=90)
    else:
        st.write("🛡️")

with col_titulo:
    # Alineación vertical con CSS inline simple
    st.markdown("<h1 style='margin-top: 5px; margin-bottom: 0px;'>SIS: Segnet Intelligence System</h1>", unsafe_allow_html=True)
    st.markdown("<div style='color: gray; font-size: 14px;'>Monitor de Seguridad Industrial OT</div>", unsafe_allow_html=True)

st.markdown("---")

# --- SECCIÓN 1: MATRIZ DE RIESGO ---
st.subheader("Matriz de Riesgo")
c1, c2, c3 = st.columns([1, 1, 2])

with c1:
    st.markdown("### Nivel de Amenaza")
    st.markdown(f"<div style='color: {color_css}; font-size: 45px; font-weight: bold;'>{texto_nivel}</div>", unsafe_allow_html=True)

with c2:
    st.metric(label="Puntaje de Riesgo", value=f"{riesgo_num} / 25")
    progreso = min(riesgo_num * 4, 100)
    st.progress(progreso / 100)

with c3:
    st.info(f"📋 **Diagnóstico:** {estado.get('mensaje', '...')}")
    ts_alerta = estado.get('timestamp', '---')
    st.caption(f"Última detección: {ts_alerta} | Origen: {estado.get('origen', '---')}")

st.markdown("---")

# --- SECCIÓN 2: KPIs ---
k1, k2, k3 = st.columns(3)
with k1: st.metric("🚨 Alertas IDS (Snort)", len(df_snort))
with k2: st.metric("🌐 Conexiones Totales", count_conn)
with k3: st.metric("⚡ Paquetes IEC-104", count_iec104, delta="Industrial")

st.write("")

# --- SECCIÓN 3: GRÁFICOS ---
if not df_snort.empty:
    g1, g2 = st.columns(2)
    with g1:
        st.subheader("🔥 Top IPs Atacantes")
        if 'src_ip' in df_snort.columns:
            top_src = df_snort['src_ip'].value_counts().head(5).reset_index()
            top_src.columns = ['IP Origen', 'Alertas']
            fig = px.bar(top_src, x='IP Origen', y='Alertas', text='Alertas', color_discrete_sequence=[COLOR_CELESTE])
            fig.update_traces(textposition='outside')
            fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
            st.plotly_chart(fig, use_container_width=True)
    with g2:
        st.subheader("📡 Protocolos Detectados")
        if 'protocolo' in df_snort.columns:
            fig2 = px.pie(df_snort, names='protocolo', hole=0.4, color_discrete_sequence=px.colors.sequential.Teal_r)
            fig2.update_layout(paper_bgcolor="rgba(0,0,0,0)")
            st.plotly_chart(fig2, use_container_width=True)
else:
    st.info("ℹ️ Esperando tráfico de Snort...")

# --- SECCIÓN 4: TABLAS DE DATOS ---
st.markdown("### 📜 Registros Detallados")
tab1, tab2, tab3 = st.tabs(["🔴 Alertas Snort", "⚡ Tráfico IEC-104", "🔵 Conexiones Zeek"])

with tab1:
    st.dataframe(df_snort, use_container_width=True)

with tab2:
    if not df_iec104.empty: st.dataframe(df_iec104, use_container_width=True)
    else: st.write("Sin tráfico SCADA.")

with tab3:
    if not df_conn.empty and df_conn.shape[1] > 6:
        cols_mostrar = [0, 2, 4, 6, 8]
        df_zeek_show = df_conn.iloc[:, cols_mostrar].copy()
        df_zeek_show.columns = ['Timestamp', 'IP Origen', 'IP Destino', 'Proto', 'Servicio']
        st.dataframe(df_zeek_show, use_container_width=True)
    else:
        st.write("Sin datos de conexión.")

# --- ACTUALIZACIÓN SILENCIOSA (Sin reloj visual) ---
time.sleep(2)
st.rerun()

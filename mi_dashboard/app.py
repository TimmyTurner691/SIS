import streamlit as st
import pandas as pd
import re
import os
import plotly.express as px

# ==========================================
# 1. CONFIGURACIÓN DE LA PÁGINA
# ==========================================
st.set_page_config(
    page_title="SIS: Segnet Intelligence System",
    page_icon="🛡️",
    layout="wide"
)

# ==========================================
# 2. DEFINICIÓN DE RUTAS (INTERNAS DOCKER)
# ==========================================
SNORT_LOG_FILE  = '/var/log/snort/alert'
ZEEK_CONN_LOG   = '/var/log/zeek/conn.log'
ZEEK_IEC104_LOG = '/var/log/zeek/iec104.log'
LOGO_PATH       = 'logo-segnet.png'  # Debe estar en la misma carpeta que app.py
COLOR_CELESTE   = '#00b6ff'       # Tu color personalizado

# ==========================================
# 3. FUNCIONES DE PROCESAMIENTO (PARSERS)
# ==========================================
def parse_snort_logs(filepath):
    """Lee y procesa el archivo de alertas de Snort (formato fast)"""
    data = []
    pattern = re.compile(r'^(\S+)\s+.*?\[\*\*\]\s+(.*?)\s+\[\*\*\]\s+.*?\{(.*?)\}\s+(\S+)\s+->\s+(\S+)')
    if not os.path.exists(filepath): return pd.DataFrame()
    try:
        with open(filepath, 'r') as f:
            lines = f.readlines()[::-1]
            for line in lines:
                match = pattern.search(line)
                if match:
                    timestamp, msg, proto, src, dst = match.groups()
                    data.append({
                        "timestamp": timestamp,
                        "alerta": msg,
                        "protocolo": proto,
                        "src_ip": src.split(':')[0],
                        "dst_ip": dst.split(':')[0]
                    })
    except Exception: return pd.DataFrame()
    return pd.DataFrame(data)

def parse_zeek_logs(filepath):
    """Lee y procesa logs de Zeek en formato TSV"""
    if not os.path.exists(filepath): return pd.DataFrame()
    try:
        df = pd.read_csv(filepath, sep='\t', comment='#', header=None)
        columns = []
        with open(filepath, 'r') as f:
            for line in f:
                if line.startswith("#fields"):
                    columns = line.strip().split('\t')[1:]
                    break
        if columns and not df.empty and len(df.columns) == len(columns):
            df.columns = columns
            if 'ts' in df.columns:
                df['ts'] = pd.to_datetime(df['ts'], unit='s')
                df = df.sort_values(by='ts', ascending=False)
            return df
    except Exception: return pd.DataFrame()
    return pd.DataFrame()

# ==========================================
# 4. INTERFAZ GRÁFICA (FRONTEND)
# ==========================================

# --- CABECERA CON LOGO ALINEADO ---
col_logo, col_title = st.columns([1, 7])

with col_logo:
    if os.path.exists(LOGO_PATH):
        st.image(LOGO_PATH, width=100)
    else:
        st.warning("Logo no encontrado")

with col_title:
    # Usamos markdown con CSS para bajar el título y alinearlo con el logo
    st.markdown("""
        <h1 style='margin-top: 15px;'>SIS: Segnet Intelligence System</h1>
        """, unsafe_allow_html=True)

st.markdown("##### 🕵️‍♂️ Monitorización de Seguridad Industrial e IT (Snort + Zeek)")
st.markdown("---")

# --- BARRA LATERAL ---
with st.sidebar:
    st.header("Control Panel")
    if st.button('🔄 Actualizar Datos', use_container_width=True):
        st.rerun()
    st.info("Sistema corriendo en Docker.")

# --- CARGA DE DATOS ---
df_snort = parse_snort_logs(SNORT_LOG_FILE)
df_zeek  = parse_zeek_logs(ZEEK_CONN_LOG)
df_iec   = parse_zeek_logs(ZEEK_IEC104_LOG)

# --- KPI / MÉTRICAS ---
m1, m2, m3 = st.columns(3)
with m1: st.metric("🚨 Alertas IDS (Snort)", len(df_snort))
with m2: st.metric("🌐 Conexiones Totales", len(df_zeek))
with m3: st.metric("⚡ Paquetes IEC-104", len(df_iec))

st.write("")

# --- GRÁFICOS (CON COLOR CELESTE) ---
if not df_snort.empty:
    g1, g2 = st.columns(2)
    
    with g1:
        st.subheader("🔥 Top 5 IPs Atacantes")
        top_src = df_snort['src_ip'].value_counts().head(5).reset_index()
        top_src.columns = ['IP Origen', 'Alertas']
        
        # Usamos el color celeste personalizado
        fig_bar = px.bar(top_src, x='IP Origen', y='Alertas', 
                         text='Alertas',
                         color_discrete_sequence=[COLOR_CELESTE]) # <--- Color aquí
        
        fig_bar.update_traces(textposition='outside')
        st.plotly_chart(fig_bar, use_container_width=True)

    with g2:
        st.subheader("📡 Distribución de Protocolos")
        # Usamos el color celeste como base para la paleta
        fig_pie = px.pie(df_snort, names='protocolo', hole=0.4,
                         color_discrete_sequence=px.colors.sequential.Teal_r) # <--- Paleta celeste/azul
        st.plotly_chart(fig_pie, use_container_width=True)

# --- TABLAS DETALLADAS (PESTAÑAS) ---
tab1, tab2, tab3 = st.tabs(["🔴 Alertas Snort", "🔵 Tráfico de Red (Zeek)", "⚡ Protocolo IEC-104"])

with tab1:
    st.subheader("Registro de Intrusiones")
    if not df_snort.empty:
        cols = ["timestamp", "src_ip", "dst_ip", "protocolo", "alerta"]
        st.dataframe(df_snort[cols], use_container_width=True, hide_index=True)
    else: st.info("No hay alertas de seguridad registradas en este momento.")

with tab2:
    st.subheader("Monitor de Conexiones (conn.log)")
    if not df_zeek.empty:
        cols_deseadas = ['ts', 'id.orig_h', 'id.resp_h', 'proto', 'service', 'duration', 'orig_bytes', 'resp_bytes']
        cols_finales = [c for c in cols_deseadas if c in df_zeek.columns]
        st.dataframe(df_zeek[cols_finales], use_container_width=True, hide_index=True)
    else: st.warning("No se encontraron datos de tráfico en Zeek.")

with tab3:
    st.subheader("Tráfico Industrial SCADA (IEC 60870-5-104)")
    if not df_iec.empty:
        st.success("⚠️ ¡Tráfico OT detectado!")
        st.dataframe(df_iec, use_container_width=True, hide_index=True)
    else: st.info("El sistema está escuchando, pero no se ha detectado tráfico IEC-104 todavía.")

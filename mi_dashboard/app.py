import streamlit as st
import pandas as pd
from elasticsearch import Elasticsearch
import plotly.express as px
import plotly.graph_objects as go
import datetime

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

# --- CONEXIÓN ---
try:
    es = Elasticsearch("http://elasticsearch:9200")
except:
    st.error("🚨 Error de conexión con Elasticsearch")
    es = None

# --- FUNCIONES DE CARGA ---
def get_data(minutes=60, start=None, end=None, limit=5000):
    if not es: return pd.DataFrame()

    # LÓGICA DE TIEMPO
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

            # --- NORMALIZACIÓN DE SCORE DE IA ---
            if 'ai_score' not in df.columns: df['ai_score'] = 0.0
            df['ai_score'] = df['ai_score'].fillna(0.0)

            # Convertimos score negativo en positivo visual (0-100)
            df['risk_score'] = df['ai_score'].apply(lambda x: abs(x) * 1000 if x < 0 else 0)

            # Target visual
            if 'dst_ip' in df.columns and 'protocol' in df.columns:
                df['Target'] = df['dst_ip'].astype(str) + ":" + df['protocol'].astype(str)
            else:
                df['Target'] = "Desconocido"

            return df
        else:
            return pd.DataFrame()

    except Exception as e:
        # st.error(f"Error trayendo datos: {e}") # Descomentar para debug
        return pd.DataFrame()

# --- SIDEBAR ---
st.sidebar.title("🎛️ Centro de Comando")
modo = st.sidebar.radio("Vista", ["En Vivo (Live)", "Históricos"])

df = pd.DataFrame()

if modo == "En Vivo (Live)":
    rango = st.sidebar.slider("Ventana (minutos)", 5, 1440, 60)
    if st.sidebar.button("🔄 Actualizar") or True: # Auto-load al inicio
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

# --- LÓGICA PRINCIPAL ---

if df.empty:
    st.info("⏳ Esperando datos... (Si estás en Historial, asegúrate de que hubo tráfico en esa fecha)")
else:
    tab_ia, tab_snort, tab_zeek, tab_iec, tab_raw = st.tabs([
        "🧠 IA & Riesgo", "🛡️ Alertas IDS", "🌐 Tráfico Red", "🏭 Industrial (SCADA)", "📝 Logs"
    ])

    # ==========================================
    # PESTAÑA 1: IA (MEJORADA)
    # ==========================================
    with tab_ia:
        st.markdown("### 🧬 Detección de Amenazas (Normalizado)")

        avg_risk = df['risk_score'].mean()
        max_risk = df['risk_score'].max()
        anomalies = df[df['ai_anomaly'] == True].shape[0] if 'ai_anomaly' in df.columns else 0

        kpi1, kpi2, kpi3, kpi4 = st.columns(4)
        kpi1.metric("Nivel de Amenaza Global", f"{avg_risk:.1f}/100")
        kpi2.metric("Pico Máximo Detectado", f"{max_risk:.1f}/100")
        kpi3.metric("Paquetes Anómalos", anomalies)
        kpi4.metric("Total Eventos", len(df))

        st.markdown("---")

        col_gauge, col_matrix = st.columns([1, 2])

        with col_gauge:
            max_val_gauge = min(max_risk, 100)
            fig_gauge = go.Figure(go.Indicator(
                mode = "gauge+number",
                value = max_val_gauge,
                domain = {'x': [0, 1], 'y': [0, 1]},
                title = {'text': "Probabilidad de Ataque (%)"},
                gauge = {
                    'axis': {'range': [None, 100]},
                    'bar': {'color': "darkred"},
                    'steps': [
                        {'range': [0, 30], 'color': "lightgreen"},
                        {'range': [30, 70], 'color': "yellow"},
                        {'range': [70, 100], 'color': "red"}],
                }
            ))
            st.plotly_chart(fig_gauge, use_container_width=True)

        with col_matrix:
            if 'src_ip' in df.columns:
                fig_matrix = px.density_heatmap(
                    df,
                    x="Target",
                    y="src_ip",
                    z="risk_score",
                    histfunc="max",
                    color_continuous_scale="Magma",
                    title="Mapa de Calor de Riesgo"
                )
                st.plotly_chart(fig_matrix, use_container_width=True)

        # Scatter
        df['visual_size'] = df['risk_score'] + 5
        fig_scatter = px.scatter(
            df,
            x="@timestamp",
            y="risk_score",
            color="risk_score",
            size="visual_size",
            size_max=50,
            color_continuous_scale="OrRd",
            title="Línea de Tiempo de Intensidad de Amenaza"
        )
        st.plotly_chart(fig_scatter, use_container_width=True)

    # ==========================================
    # PESTAÑA 2: SNORT
    # ==========================================
    with tab_snort:
        df_snort = df[df['source'] == 'snort']
        if df_snort.empty:
            st.success("✅ Sin alertas de Snort.")
        else:
            cols = ['@timestamp', 'priority', 'classification', 'message', 'src_ip', 'dst_ip']
            safe_cols = [c for c in cols if c in df_snort.columns]
            st.dataframe(df_snort[safe_cols], use_container_width=True)

    # ==========================================
    # PESTAÑA 3: ZEEK
    # ==========================================
    with tab_zeek:
        # Filtramos lo que NO es IEC104 para no duplicar info
        df_zeek = df[(df['source'] == 'zeek') & (df.get('protocol') != 'iec104')]
        
        col1, col2 = st.columns(2)
        with col1:
            if 'protocol' in df_zeek.columns:
                st.plotly_chart(px.bar(df_zeek['protocol'].value_counts(), title="Protocolos"), use_container_width=True)
        with col2:
            if 'src_ip' in df_zeek.columns:
                st.plotly_chart(px.bar(df_zeek['src_ip'].value_counts().head(10), orientation='h', title="Top IPs Origen"), use_container_width=True)
        
        st.dataframe(df_zeek.head(100), use_container_width=True)

    # ==========================================
    # PESTAÑA 4: INDUSTRIAL (SCADA)
    # ==========================================
    with tab_iec:
        # Filtro robusto: Busca logs que sean explicitamente iec104 O que el protocolo sea iec104
        mask_iec = (df['sub_source'] == 'zeek_iec104') | (df.get('protocol') == 'iec104')
        df_iec = df[mask_iec].copy()

        if df_iec.empty:
            st.info("🏭 Esperando tráfico SCADA (IEC-104)...")
        else:
            # Métricas SCADA
            c1, c2, c3 = st.columns(3)
            c1.metric("Paquetes IEC-104", len(df_iec))
            
            # --- FIX KEYERROR: Cálculo seguro de modas ---
            
            # 1. Trama más común
            top_trama = "N/A"
            if 'tipo_trama' in df_iec.columns:
                # Eliminamos nulos antes de calcular la moda
                series_trama = df_iec['tipo_trama'].dropna()
                if not series_trama.empty:
                    modes_trama = series_trama.mode()
                    if not modes_trama.empty:
                        top_trama = modes_trama.iloc[0]
            c2.metric("Trama más común", top_trama)
            
            # 2. Instrucción más común
            top_instr = "N/A"
            if 'instruccion' in df_iec.columns:
                # Eliminamos nulos antes de calcular la moda
                series_instr = df_iec['instruccion'].dropna()
                if not series_instr.empty:
                    modes_instr = series_instr.mode()
                    if not modes_instr.empty:
                        top_instr = modes_instr.iloc[0]
            c3.metric("Instrucción Frecuente", top_instr)

            # Gráficos SCADA
            col_chart1, col_chart2 = st.columns(2)
            
            with col_chart1:
                if 'instruccion' in df_iec.columns:
                    # Filtrar nulos para el gráfico
                    df_pie = df_iec[df_iec['instruccion'].notna()]
                    if not df_pie.empty:
                        st.plotly_chart(px.pie(df_pie, names='instruccion', title="Distribución de Instrucciones"), use_container_width=True)
                    else:
                        st.text("Sin datos suficientes para gráfica de instrucciones.")
            
            with col_chart2:
                if 'tipo_trama' in df_iec.columns:
                    # Filtrar nulos para el gráfico
                    df_bar = df_iec[df_iec['tipo_trama'].notna()]
                    if not df_bar.empty:
                        st.plotly_chart(px.bar(df_bar['tipo_trama'].value_counts(), title="Tipos de Trama (Control vs Datos)"), use_container_width=True)
                    else:
                         st.text("Sin datos suficientes para gráfica de tramas.")

            # Tabla Detallada
            st.markdown("##### 📜 Detalle de Paquetes")
            cols_iec = ['@timestamp', 'src_ip', 'dst_ip', 'tipo_trama', 'instruccion', 'raw_log']
            safe_cols_iec = [c for c in cols_iec if c in df_iec.columns]
            st.dataframe(df_iec[safe_cols_iec], use_container_width=True)

    with tab_raw:
        st.dataframe(df.head(50))
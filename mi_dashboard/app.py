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
    
    # LÓGICA DE TIEMPO CORREGIDA PARA HISTORIAL
    if start and end:
        # Convertimos la fecha 'end' para que incluya hasta el último segundo del día
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
            
            # --- NORMALIZACIÓN DE SCORE DE IA (TRUCO VISUAL) ---
            if 'ai_score' not in df.columns: df['ai_score'] = 0.0
            df['ai_score'] = df['ai_score'].fillna(0.0)
            
            # Convertimos el score negativo matemático en un "Score de Riesgo" positivo (0 a 100)
            # Asumimos que valores muy negativos son malos. Invertimos y escalamos.
            # Multiplicamos por 1000 y tomamos valor absoluto para efecto visual
            df['risk_score'] = df['ai_score'].apply(lambda x: abs(x) * 1000 if x < 0 else 0)
            
            # Target visual
            df['Target'] = df['dst_ip'].astype(str) + ":" + df['protocol'].astype(str)
        return df
    except Exception as e:
        return pd.DataFrame()

# --- SIDEBAR ---
st.sidebar.title("🎛️ Centro de Comando")
modo = st.sidebar.radio("Vista", ["En Vivo (Live)", "Históricos"])

df = pd.DataFrame()

if modo == "En Vivo (Live)":
    rango = st.sidebar.slider("Ventana (minutos)", 5, 1440, 60)
    if st.sidebar.button("🔄 Actualizar"):
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
        "🧠 IA & Riesgo", "🛡️ Alertas IDS", "🌐 Tráfico Red", "🏭 Industrial", "📝 Logs"
    ])

    # ==========================================
    # PESTAÑA 1: IA (MEJORADA)
    # ==========================================
    with tab_ia:
        st.markdown("### 🧬 Detección de Amenazas (Normalizado)")
        
        # Usamos el nuevo 'risk_score' positivo para los KPIs
        avg_risk = df['risk_score'].mean()
        max_risk = df['risk_score'].max()
        anomalies = df[df['ai_anomaly'] == True].shape[0] if 'ai_anomaly' in df.columns else 0
        
        kpi1, kpi2, kpi3, kpi4 = st.columns(4)
        
        # Explicación de los KPIs:
        # Nivel de Amenaza: Un número basado en qué tan "raro" es el tráfico.
        kpi1.metric("Nivel de Amenaza Global", f"{avg_risk:.1f}/100")
        kpi2.metric("Pico Máximo Detectado", f"{max_risk:.1f}/100")
        kpi3.metric("Paquetes Anómalos", anomalies, help="Cantidad de eventos marcados como 'raros' por la IA")
        kpi4.metric("Total Eventos", len(df))

        st.markdown("---")

        col_gauge, col_matrix = st.columns([1, 2])
        
        with col_gauge:
            # Gauge normalizado de 0 a 100
            max_val_gauge = min(max_risk, 100) # Tope en 100 visualmente
            
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
                    z="risk_score", # Usamos el score positivo
                    histfunc="max", 
                    color_continuous_scale="Magma", # Color fuego
                    title="Mapa de Calor de Riesgo"
                )
                st.plotly_chart(fig_matrix, use_container_width=True)

        # Scatter Plot corregido y positivo
        df['visual_size'] = df['risk_score'] + 5 # Tamaño mínimo base
        
        fig_scatter = px.scatter(
            df, 
            x="@timestamp", 
            y="risk_score", # Eje Y positivo
            color="risk_score",
            size="visual_size",
            size_max=50,
            color_continuous_scale="OrRd", # Blanco a Rojo
            title="Línea de Tiempo de Intensidad de Amenaza"
        )
        st.plotly_chart(fig_scatter, use_container_width=True)

    # ==========================================
    # PESTAÑA 2: SNORT (BLINDADO)
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
        df_zeek = df[(df['source'] == 'zeek') & (df['sub_source'] != 'zeek_iec104')]
        col1, col2 = st.columns(2)
        with col1:
            if 'protocol' in df_zeek.columns:
                st.plotly_chart(px.bar(df_zeek['protocol'].value_counts(), title="Protocolos"), use_container_width=True)
        with col2:
             if 'src_ip' in df_zeek.columns:
                st.plotly_chart(px.bar(df_zeek['src_ip'].value_counts().head(10), orientation='h', title="Top IPs Origen"), use_container_width=True)
        st.dataframe(df_zeek.head(100), use_container_width=True)

    # ==========================================
    # PESTAÑA 4: INDUSTRIAL
    # ==========================================
    with tab_iec:
        mask_iec = (df['sub_source'] == 'zeek_iec104') | (df.get('protocol') == 'iec104')
        df_iec = df[mask_iec]
        if df_iec.empty:
            st.info("Sin tráfico SCADA detectado.")
        else:
            st.metric("Comandos IEC-104", len(df_iec))
            st.dataframe(df_iec, use_container_width=True)

    with tab_raw:
        st.dataframe(df.head(50))
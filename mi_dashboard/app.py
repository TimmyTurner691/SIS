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

# --- CONFIGURACIÓN ---
st.set_page_config(page_title="SIS - SIEM Dashboard", page_icon="🛡️", layout="wide")

# CSS para Tarjetas de Riesgo
st.markdown("""
<style>
    .risk-card-critical { border-left: 5px solid #ff4b4b; background-color: #262730; padding: 15px; border-radius: 5px; margin-bottom: 10px; }
    .risk-card-medium { border-left: 5px solid #ffa500; background-color: #262730; padding: 15px; border-radius: 5px; margin-bottom: 10px; }
    .mitre-badge { background-color: #0e1117; padding: 2px 8px; border-radius: 4px; border: 1px solid #444; font-size: 0.8em; margin-right: 5px; }
</style>
""", unsafe_allow_html=True)

INVENTORY_FILE = "/app/ot_inventory.json"
REPORT_FILE = "/app/cve_report.csv"
SCANNER_SCRIPT = "/python_core/vuln_scanner.py"

try: es = Elasticsearch("http://elasticsearch:9200")
except: es = None

# --- CARGA DE DATOS ---
def get_data(minutes=60, start=None, end=None, limit=5000):
    if not es: return pd.DataFrame()
    
    # Rango de tiempo
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
        df = pd.DataFrame([h['_source'] for h in res['hits']['hits']])
        
        if not df.empty:
            df['@timestamp'] = pd.to_datetime(df['@timestamp'])
            if df['@timestamp'].dt.tz is None:
                df['@timestamp'] = df['@timestamp'].dt.tz_localize('UTC')
            
            df['@timestamp'] = df['@timestamp'].dt.tz_convert('America/Santiago')
            # Asegurar columnas nuevas existan
            cols_req = ['risk_total_score', 'risk_label', 'mitre_msg', 'risk_probability', 'risk_impact']
            for c in cols_req:
                if c not in df.columns: df[c] = 0 if 'score' in c or 'risk' in c else "N/A"
            
            # Normalizar listas de MITRE para visualización
            if 'mitre_tactics' in df.columns:
                df['mitre_tactics'] = df['mitre_tactics'].apply(lambda x: ", ".join(x) if isinstance(x, list) else str(x))
            
            return df
        return pd.DataFrame()
    except: return pd.DataFrame()

# --- SIDEBAR ---
st.sidebar.title("🎛️ Centro de Comando")
modo = st.sidebar.radio("Vista", ["En Vivo", "Histórico"])
df = pd.DataFrame()

if modo == "En Vivo":
    mins = st.sidebar.slider("Minutos", 5, 1440, 60)
    if st.sidebar.button("🔄 Actualizar") or True:
        df = get_data(minutes=mins)
        st.title("🛡️ SIS - SIEM Dashboard (En Vivo)")
else:
    d1 = st.sidebar.date_input("Inicio"); d2 = st.sidebar.date_input("Fin")
    if st.sidebar.button("Buscar"):
        df = get_data(start=d1, end=d2)

# --- PESTAÑAS ---
tab_risk, tab_snort, tab_net, tab_ot, tab_vuln, tab_raw = st.tabs([
    "🚨 Fusión de Riesgos", "🛡️ IDS", "🌐 Red", "🏭 SCADA", "⚠️ Vulnerabilidades", "📝 Logs Raw"
])
# ==========================================
# PESTAÑA 1: FUSIÓN DE RIESGOS (INCIDENT CARD)
# ==========================================
with tab_risk:
    if df.empty:
        st.info("Sin datos recientes.")
    else:
        # KPIs Superiores
        k1, k2, k3, k4 = st.columns(4)
        max_score = df['risk_total_score'].max()
        criticos = len(df[df['risk_total_score'] >= 17])
        
        k1.metric("Riesgo Máximo Actual", f"{max_score}/25")
        k2.metric("Incidentes Críticos", criticos)
        k3.metric("Anomalía IA (Prom)", f"{df['ai_score'].mean():.2f}")
        k4.metric("Activos Afectados", df['dst_ip'].nunique())

        st.divider()

        # MATRIZ VISUAL DE RIESGO - Cambiado el orden
        col_incidents = st.columns(1)[0]  # Ocupa toda la página
        
        with col_incidents:
            st.subheader("Últimos Incidentes Detectados")
            # Filtrar solo eventos con riesgo relevante para no saturar
            df_risk = df[df['risk_total_score'] >= 8].drop_duplicates(subset=['src_ip', 'mitre_msg']).head(5)
            
            if df_risk.empty:
                st.success("✅ Sistema estable. No hay incidentes de riesgo Medio/Alto.")
            
            for index, row in df_risk.iterrows():
                css_class = "risk-card-critical" if row['risk_total_score'] >= 17 else "risk-card-medium"
                icon = "🚨" if row['risk_total_score'] >= 17 else "⚠️"
                
                html_content = f"""
                <div class="{css_class}">
                    <h4>{icon} {row['risk_label']} ({row['risk_total_score']}/25) - {row['src_ip']} ➡️ {row['dst_ip']}</h4>
                    <p><b>Diagnóstico:</b> {row['mitre_msg']}</p>
                    <p>
                        <span class="mitre-badge">🛡️ IA: {row['ai_score']:.2f}</span>
                        <span class="mitre-badge">📚 MITRE: {row['mitre_tactics']}</span>
                        <span class="mitre-badge">🏭 Vuln Destino: {row['risk_impact']}/5</span>
                    </p>
                </div>
                """
                st.markdown(html_content, unsafe_allow_html=True)

        st.divider()  # Separador entre secciones
        
        # Matriz de calor después de los incidentes
        col_viz = st.columns(1)[0]  # Ocupa toda la página
        
        with col_viz:
            st.subheader("Matriz de Calor")
            if not df.empty:
                fig = px.density_heatmap(
                    df, x="risk_impact", y="risk_probability", 
                    nbinsx=5, nbinsy=5, 
                    title="Amenaza (Y) vs Impacto (X)",
                    range_x=[0.5, 5.5], range_y=[0.5, 5.5],
                    color_continuous_scale="Reds"
                )
                fig.update_layout(xaxis_title="Vulnerabilidad Activo (CVE)", yaxis_title="Probabilidad Amenaza (MITRE/IA)")
                st.plotly_chart(fig, use_container_width=True)

# ==========================================
# PESTAÑA 2: SNORT
# ==========================================
with tab_snort:
    if not df.empty and 'source' in df.columns:
        # 1. Filtramos datos de Snort
        df_snort = df[df['source'] == 'snort'].copy()
        
        # --- HERRAMIENTA PARA VER COLUMNAS (Despliega esto en el dashboard) ---
        with st.expander("🔍 Ver nombres de columnas disponibles (Debug)"):
            st.write("Copia los nombres exactos de aquí y ponlos en la lista 'desired_order':")
            st.write(df_snort.columns.tolist())
        # ---------------------------------------------------------------------

        # 2. TU LISTA DE ORDEN (Agrega aquí las columnas nuevas que encuentres arriba)
        lista_ordenada = [
            '@timestamp',
            'source',
            'risk_label', 
            'risk_total_score', 
            'src_ip', 
            'src_port',    # <--- puerto origen
            'dst_ip', 
            'dst_port',    # <--- puerto destino
            'protocol',    # <--- Protocolo
            'message', 
            'mitre_tactics', # <--- Tácticas MITRE
            'mitre_techniques', # <--- Técnicas MITRE
            'mitre_msg',    # <--- Mensaje MITRE
            'risk_probability', # <--- Probabilidad de riesgo,
            'risk_impact',     # <--- Impacto de riesgo,
            'ai_score',       # <--- Puntuación IA,
            'raw_log' ,     # <--- Log crudo
        ]
        
        # 3. Filtramos para que solo muestre las que existen (evita errores)
        columnas_finales = [c for c in lista_ordenada if c in df_snort.columns]
        
        # 4. Renderizamos la tabla bonita
        st.dataframe(
            df_snort[columnas_finales], 
            use_container_width=True,
            hide_index=True,
            column_config={
                "@timestamp": st.column_config.DatetimeColumn("Fecha/Hora", format="DD/MM/YYYY HH:mm:ss"),
                "risk_label": "Nivel",
                "source": "Fuente",
                "risk_total_score": "Score",
                "src_ip": "Origen",
                "dst_ip": "Destino",
                "message": "Mensaje",
                "raw_log": "Log Crudo"
                # Si agregas columnas arriba (ej. 'src_port'), no es obligatorio ponerlas aquí, 
                # pero si quieres cambiarles el nombre del encabezado, agrégalas así:
                # "src_port": "Puerto Origen"
            }
        )
    else: 
        st.info("✅ Sin alertas de intrusión detectadas.")

# ==========================================
# PESTAÑA 3: RED (Mejorada Visualmente)
# ==========================================
with tab_net:
    # 1. Filtramos datos de Zeek (Tráfico general, excluyendo lo que es puramente IEC104/SCADA si se prefiere)
    # Usamos .copy() para evitar advertencias de pandas
    df_net = df[(df['source'] == 'zeek') & (df.get('protocol') != 'iec104')].copy()

    if not df_net.empty:
        # 2. DEFINIR COLUMNAS (Mismo estilo que IDS)
        # Agregamos 'service' que es común en Zeek/Network logs
        lista_ordenada_red = [
            '@timestamp',
            'source',
            'src_ip', 
            'src_port',
            'dst_ip', 
            'dst_port',
            'protocol',
            'service',    # Zeek suele traer el servicio (dns, http, ssh)
            'message',    # Información general del paquete
            'raw_log'
        ]
        
        # 3. Validar que las columnas existan en los datos
        columnas_finales_red = [c for c in lista_ordenada_red if c in df_net.columns]
        
        # 4. Renderizar Tabla con Formato (Igual que IDS)
        st.dataframe(
            df_net[columnas_finales_red], 
            use_container_width=True,
            hide_index=True,
            column_config={
                "@timestamp": st.column_config.DatetimeColumn("Fecha/Hora", format="DD/MM/YYYY HH:mm:ss"),
                "source": "Fuente",
                "src_ip": "Origen",
                "src_port": "Pto. Org",
                "dst_ip": "Destino",
                "dst_port": "Pto. Dst",
                "protocol": "Protocolo",
                "service": "Servicio",
                "message": "Info",
                "raw_log": "Log Crudo"
            }
        )
    else:
        st.info("✅ Sin tráfico de red general registrado.")
# ==========================================
# PESTAÑA 4: SCADA (Sin Cambios)
# ==========================================
with tab_ot:
    if not df.empty:
        mask = (df.get('protocol') == 'iec104') | (df.get('sub_source') == 'zeek_iec104')
        st.dataframe(df[mask], use_container_width=True)

# ==========================================
# PESTAÑA 5: VULNERABILIDADES (Lógica existente)
# ==========================================
with tab_vuln:
    st.header("🛡️ Gestión de Vulnerabilidades")
    c1, c2 = st.columns([1,2])
    
    with c1:
        st.subheader("Inventario")
        if os.path.exists(INVENTORY_FILE):
            with open(INVENTORY_FILE) as f: st.json(json.load(f))
        
        new_dev = st.text_input("Agregar Activo OT:")
        if st.button("➕ Añadir"):
            try:
                with open(INVENTORY_FILE, 'r+') as f:
                    d = json.load(f); d['devices'].append({"name": new_dev})
                    f.seek(0); json.dump(d, f, indent=4)
                st.success("Añadido")
            except: pass

    with c2:
        st.subheader("Reporte CVEs")
        if st.button("🔄 Escanear Ahora"):
            subprocess.run(["python3", SCANNER_SCRIPT])
            st.success("Escaneo completado")
        
        if os.path.exists(REPORT_FILE):
            df_cve = pd.read_csv(REPORT_FILE)
            st.dataframe(df_cve, use_container_width=True)

# ==========================================
# PESTAÑA 6: LOGS RAW
# ==========================================
with tab_raw:
    st.write("Datos crudos directos de Elasticsearch:")
    st.dataframe(df, use_container_width=True)
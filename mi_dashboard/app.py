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
            # --- CORRECCIÓN CRÍTICA: RELLENAR COLUMNAS FALTANTES ---
            # Esto evita el KeyError si hay datos sucios en Elastic
            cols_necesarias = ['protocol', 'src_port', 'dst_port', 'risk_total_score', 'risk_label', 'mitre_msg', 'source', 'sub_source']
            for col in cols_necesarias:
                if col not in df.columns:
                    df[col] = "0" # Valor por defecto seguro
            # -----------------------------------------------------

            df['@timestamp'] = pd.to_datetime(df['@timestamp'])
            if df['@timestamp'].dt.tz is None:
                df['@timestamp'] = df['@timestamp'].dt.tz_localize('UTC')
            
            df['@timestamp'] = df['@timestamp'].dt.tz_convert('America/Santiago')
            
            # Asegurar columnas nuevas existan
            cols_req = ['risk_total_score', 'risk_label', 'mitre_msg', 'risk_probability', 'risk_impact', 'ai_score']
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
        # --- FUNCIÓN DE AYUDA VISUAL ---
        def formatear_anomalia(valor_raw):
            """Convierte el score negativo (-1 a 1) en porcentaje (0% a 100%)"""
            if valor_raw > 0:
                return 0 # Es normal
            else:
                # Convertimos -0.65 en 65
                return int(abs(valor_raw) * 100)

        # KPIs Superiores
        k1, k2, k3, k4 = st.columns(4)
        
        max_score = df['risk_total_score'].max()
        criticos = len(df[df['risk_total_score'] >= 17])
        
        # CÁLCULO PROMEDIO DE ANOMALÍA PARA EL KPI
        promedio_ia_raw = df['ai_score'].mean()
        promedio_ia_perc = formatear_anomalia(promedio_ia_raw)
        
        k1.metric("Riesgo Máximo Actual", f"{max_score}/25")
        k2.metric("Incidentes Críticos", criticos)
        
        # AQUI EL CAMBIO: Mostramos porcentaje, y ponemos una flecha si es alto
        k3.metric(
            "Nivel de Anomalía IA", 
            f"{promedio_ia_perc}%", 
            delta="Alto" if promedio_ia_perc > 50 else "Normal",
            delta_color="inverse" # Rojo si sube, verde si baja
        )
        
        k4.metric("Activos Afectados", df['dst_ip'].nunique())

        st.divider()

        # MATRIZ VISUAL DE RIESGO
        col_incidents = st.columns(1)[0]
        
        with col_incidents:
            st.subheader("Últimos Incidentes Detectados")
            df_risk = df[df['risk_total_score'] >= 8].drop_duplicates(subset=['src_ip', 'mitre_msg']).head(5)
            
            if df_risk.empty:
                st.success("✅ Sistema estable. No hay incidentes de riesgo Medio/Alto.")
            
            for index, row in df_risk.iterrows():
                css_class = "risk-card-critical" if row['risk_total_score'] >= 17 else "risk-card-medium"
                icon = "🚨" if row['risk_total_score'] >= 17 else "⚠️"
                
                # Calculamos el % individual para esta tarjeta
                anomalia_pct = formatear_anomalia(row['ai_score'])
                
                html_content = f"""
                <div class="{css_class}">
                    <h4>{icon} {row['risk_label']} ({row['risk_total_score']}/25) - {row['src_ip']} ➡️ {row['dst_ip']}</h4>
                    <p><b>Diagnóstico:</b> {row['mitre_msg']}</p>
                    <p>
                        <span class="mitre-badge">🤖 IA: {anomalia_pct}% Anomalía</span>
                        <span class="mitre-badge">📚 MITRE: {row['mitre_tactics']}</span>
                        <span class="mitre-badge">🏭 Impacto: {row['risk_impact']}/5</span>
                    </p>
                </div>
                """
                st.markdown(html_content, unsafe_allow_html=True)

        st.divider()
        
        # (El resto del código de la Matriz de calor sigue igual...)
        col_viz = st.columns(1)[0]
        with col_viz:
            st.subheader("Matriz de Calor")
            if not df.empty:
                # ... (código del gráfico sin cambios) ...
                fig = px.density_heatmap(
                    df, x="risk_impact", y="risk_probability", 
                    nbinsx=5, nbinsy=5, 
                    title="Amenaza (Y) vs Impacto (X)",
                    range_x=[0.5, 5.5], range_y=[0.5, 5.5],
                    color_continuous_scale="Reds"
                )
                fig.update_layout(xaxis_title="Vulnerabilidad Activo (CVE)", yaxis_title="Probabilidad Amenaza (MITRE/IA)")
                st.plotly_chart(fig, use_container_width=True)
## ==========================================
# PESTAÑA 2: SNORT (IDS + ARREGLO MENSAJE)
# ==========================================
with tab_snort:
    if not df.empty and 'source' in df.columns:
        df_snort = df[df['source'] == 'snort'].copy()
        
        if not df_snort.empty:
            
            # --- FUNCIÓN MEJORADA ---
            def extraer_mensaje_real(row):
                raw = str(row.get('raw_log', ''))
                # Busca el patrón [1:100:1] y toma lo que sigue a la derecha
                import re
                match = re.search(r'\[\d+:\d+:\d+\]\s+(.*)', raw)
                if match:
                    msg = match.group(1).strip()
                    # Quitamos basura final si existe
                    return msg.replace('[**]', '').strip()
                return "Alerta Snort (Ver Detalle)"
            # ------------------------

            # Aplicamos la función
            df_snort['mensaje_limpio'] = df_snort.apply(extraer_mensaje_real, axis=1)

            cols_to_show = [
                '@timestamp', 'mensaje_limpio', 'risk_label', 
                'risk_total_score', 'mitre_tactics', 'mitre_techniques',
                'src_ip', 'dst_ip', 'raw_log'
            ]
            
            # Filtro de columnas existentes
            available_cols = [c for c in cols_to_show if c in df_snort.columns]
            view_df = df_snort[available_cols].copy()

            st.dataframe(
                view_df,
                use_container_width=True,
                hide_index=True,
                column_config={
                    "@timestamp": st.column_config.DatetimeColumn("📅 Fecha/Hora", format="DD/MM/YYYY HH:mm:ss", width="medium"),
                    "mensaje_limpio": st.column_config.TextColumn("📢 Descripción del Ataque", width="large"),
                    "risk_label": st.column_config.TextColumn("Nivel", width="small"),
                    "risk_total_score": st.column_config.ProgressColumn("Score", format="%d", min_value=0, max_value=25, width="small"),
                    "mitre_tactics": st.column_config.TextColumn("📚 Táctica", width="medium"),
                    "mitre_techniques": st.column_config.TextColumn("🛠️ ID", width="small"),
                    "src_ip": "Origen",
                    "dst_ip": "Destino",
                    "raw_log": st.column_config.TextColumn("📝 Log Crudo", width="large")
                }
            )
            st.caption(f"Total de alertas mostradas: {len(df_snort)}")
        else:
            st.info("✅ No hay alertas de Snort en este periodo.")
    else: 
        st.info("✅ Sin alertas de intrusión detectadas.")
# ==========================================
# PESTAÑA 3: RED 
# ==========================================
with tab_net:
    if not df.empty:
        # Usamos .get() o rellenamos antes para evitar crash
        mask = (df['source'] == 'zeek') & (df['protocol'] != 'iec104')
        df_net = df[mask].copy()
        st.dataframe(df_net, use_container_width=True)
    else:
        st.info("✅ Sin tráfico de red general registrado.")

# ==========================================
# PESTAÑA 4: SCADA
# ==========================================
with tab_ot:
    if not df.empty:
        # FILTRO PROTEGIDO
        mask = (df['protocol'] == 'iec104') | (df.get('sub_source') == 'zeek_iec104')
        st.dataframe(df[mask], use_container_width=True)

# ==========================================
# PESTAÑA 5: VULNERABILIDADES
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
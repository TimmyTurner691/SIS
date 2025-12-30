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
import re

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

# ==========================================
# LÓGICA DE NEGOCIO (HELPER FUNCTIONS)
# ==========================================

def get_data(minutes=60, start=None, end=None, limit=5000):
    if not es: return pd.DataFrame()
    
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
            cols_necesarias = ['protocol', 'src_port', 'dst_port', 'risk_total_score', 'risk_label', 'mitre_msg', 'source', 'sub_source']
            for col in cols_necesarias:
                if col not in df.columns:
                    df[col] = "0"

            df['@timestamp'] = pd.to_datetime(df['@timestamp'])
            if df['@timestamp'].dt.tz is None:
                df['@timestamp'] = df['@timestamp'].dt.tz_localize('UTC')
            df['@timestamp'] = df['@timestamp'].dt.tz_convert('America/Santiago')
            
            cols_req = ['risk_total_score', 'risk_label', 'mitre_msg', 'risk_probability', 'risk_impact', 'ai_score']
            for c in cols_req:
                if c not in df.columns: df[c] = 0 if 'score' in c or 'risk' in c else "N/A"
            
            if 'mitre_tactics' in df.columns:
                df['mitre_tactics'] = df['mitre_tactics'].apply(lambda x: ", ".join(x) if isinstance(x, list) else str(x))
            
            return df
        return pd.DataFrame()
    except: return pd.DataFrame()

def lógica_interpretar_scada(row):
    """Traduce comandos técnicos a lenguaje humano, incluyendo formatos cortos I/S/U"""
    # 1. Obtenemos datos y normalizamos
    # Agregamos espacios al texto para buscar palabras completas y evitar falsos positivos
    texto_raw = (str(row.get('raw_log', '')) + " " + str(row.get('message', ''))).upper()
    texto = f" {texto_raw} " 
    
    dst_port = str(row.get('dst_port'))
    state = str(row.get('conn_state', '')).upper()
    proto = str(row.get('protocol', '')).lower()

    # 2. PRIORIDAD ALTA: Comandos IEC-104 Explícitos
    if 'STARTDT' in texto: return "🟢 Inicio Conexión (STARTDT)"
    if 'STOPDT' in texto:  return "🔴 Fin Conexión (STOPDT)"
    if 'TESTFR' in texto:  return "💓 Latido / Test (TESTFR)"
    if 'C_IC' in texto or 'INTERROGATION' in texto: return "❓ Interrogación General"
    if 'C_CS' in texto or 'CLOCK' in texto: return "⏰ Sincronización Reloj"
    if 'M_SP' in texto: return "📡 Info Punto Simple (Monitor)"
    if 'M_DP' in texto: return "📡 Info Punto Doble (Monitor)"
    if 'C_SC' in texto: return "⚙️ Comando Control (Switch)"

    # 3. PRIORIDAD MEDIA: Formatos Genéricos IEC-104 (Tu caso de la "U")
    # Buscamos la letra rodeada de espacios o tabulaciones para no confundir con otras palabras
    if ' U ' in texto or '\tU\t' in texto: return "⚙️ Gestión de Conexión (Formato U)"
    if ' S ' in texto or '\tS\t' in texto: return "🛡️ Supervisión / ACK (Formato S)"
    if ' I ' in texto or '\tI\t' in texto: return "📦 Datos de Proceso (Formato I)"
    
    # 4. PRIORIDAD: Modbus
    if 'MODBUS' in texto or dst_port == '502':
        if 'EXCEPTION' in texto: return "⚠️ Excepción/Error Modbus"
        if 'func 5' in texto.lower() or 'write' in texto.lower(): return "📝 Escritura (Write)"
        if 'func' in texto.lower(): return "👁️ Lectura Modbus"

    # 5. PRIORIDAD BAJA: Estados de Conexión de Red
    if state == 'REJ': return "⛔ Conexión Rechazada (Puerto Cerrado)"
    if state == 'S0':  return "⚠️ Intento de Conexión (Sin Respuesta)"
    if state == 'SF' and (proto == 'iec104' or dst_port == '2404'): 
        return "🔌 Canal Abierto (Esperando Tráfico)"

    return "📦 Tráfico Industrial Genérico"

def lógica_calcular_anomalia_pct(valor):
    """Convierte score -1 a 1 en porcentaje 0-100%"""
    try:
        val = float(valor)
        return int(abs(val) * 100) if val < 0 else 0
    except:
        return 0

def lógica_limpiar_snort_msg(row):
    """Limpia mensajes de Snort eliminando SIDs"""
    raw = str(row.get('raw_log', ''))
    match = re.search(r'\[\d+:\d+:\d+\]\s+(.*)', raw)
    if match:
        msg = match.group(1).strip()
        if msg == "[TEST]": return "⚠️ Alerta de Prueba (TEST)"
        return msg.replace('[**]', '').strip()
    return raw.replace('[**]', '').split('] ')[-1]

# ==========================================
# INTERFAZ DE USUARIO (SIDEBAR & TABS)
# ==========================================

st.sidebar.title("🎛️ Centro de Comando")
modo = st.sidebar.radio("Vista", ["En Vivo", "Histórico"])
df = pd.DataFrame()

if modo == "En Vivo":
    mins = st.sidebar.slider("Minutos", 5, 1440, 60)
    if st.sidebar.button("🔄 Actualizar", type="primary") or True:
        st.cache_data.clear()
        df = get_data(minutes=mins)
        st.title("🛡️ SIS - SIEM Dashboard (En Vivo)")
else:
    d1 = st.sidebar.date_input("Inicio"); d2 = st.sidebar.date_input("Fin")
    if st.sidebar.button("Buscar"):
        df = get_data(start=d1, end=d2)

# Pestañas
tab_risk, tab_snort, tab_net, tab_ot, tab_vuln, tab_raw = st.tabs([
    "🚨 Fusión de Riesgos", "🛡️ IDS", "🌐 Red", "🏭 SCADA", "⚠️ Vulnerabilidades", "📝 Logs Raw"
])

# ---------------- PESTAÑA 1: RIESGOS ----------------
with tab_risk:
    if df.empty:
        st.info("Sin datos recientes.")
    else:
        k1, k2, k3, k4 = st.columns(4)
        max_score = df['risk_total_score'].max()
        criticos = len(df[df['risk_total_score'] >= 17])
        
        # Calculamos promedio IA para KPI
        promedio_ia_raw = df['ai_score'].mean()
        promedio_ia_perc = lógica_calcular_anomalia_pct(promedio_ia_raw)
        
        k1.metric("Riesgo Máximo", f"{max_score}/25")
        k2.metric("Incidentes Críticos", criticos)
        k3.metric("Nivel Anomalía IA", f"{promedio_ia_perc}%", delta="Alto" if promedio_ia_perc > 50 else "Normal", delta_color="inverse")
        k4.metric("Activos Afectados", df['dst_ip'].nunique())

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
                anomalia_pct = lógica_calcular_anomalia_pct(row['ai_score'])
                
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
        col_viz = st.columns(1)[0]
        with col_viz:
            st.subheader("Matriz de Calor")
            if not df.empty:
                fig = px.density_heatmap(
                    df, x="risk_impact", y="risk_probability", nbinsx=5, nbinsy=5, 
                    title="Amenaza (Y) vs Impacto (X)", range_x=[0.5, 5.5], range_y=[0.5, 5.5], color_continuous_scale="Reds"
                )
                st.plotly_chart(fig, use_container_width=True)

# ---------------- PESTAÑA 2: SNORT ----------------
with tab_snort:
    if not df.empty and 'source' in df.columns:
        df_snort = df[df['source'] == 'snort'].copy()
        if not df_snort.empty:
            # Aplicar limpieza de mensaje
            df_snort['mensaje_limpio'] = df_snort.apply(lógica_limpiar_snort_msg, axis=1)

            cols_to_show = ['@timestamp', 'mensaje_limpio', 'risk_label', 'risk_total_score', 'mitre_tactics', 'mitre_techniques', 'src_ip', 'dst_ip', 'raw_log']
            view_df = df_snort[[c for c in cols_to_show if c in df_snort.columns]].copy()

            st.dataframe(view_df, use_container_width=True, hide_index=True, column_config={
                "@timestamp": st.column_config.DatetimeColumn("📅 Fecha/Hora", format="DD/MM/YYYY HH:mm:ss", width="medium"),
                "mensaje_limpio": st.column_config.TextColumn("📢 Descripción del Ataque", width="large"),
                "risk_label": st.column_config.TextColumn("Nivel", width="small"),
                "risk_total_score": st.column_config.ProgressColumn("Score", format="%d", min_value=0, max_value=25, width="small"),
                "mitre_tactics": st.column_config.TextColumn("📚 Táctica", width="medium"),
                "mitre_techniques": st.column_config.TextColumn("🛠️ ID", width="small"),
                "raw_log": st.column_config.TextColumn("📝 Log Crudo", width="large")
            })
        else: st.info("✅ No hay alertas de Snort.")
    else: st.info("✅ Sin alertas.")

# ---------------- PESTAÑA 3: RED ----------------
with tab_net:
    if not df.empty:
        mask_net = (df['source'] == 'zeek') & (df['protocol'] != 'iec104')
        df_net = df[mask_net].copy()
    else: df_net = pd.DataFrame()

    if not df_net.empty:
        cols_prioridad = ['@timestamp', 'protocol', 'service', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'conn_state', 'duration', 'orig_bytes', 'resp_bytes']
        cols_existentes = df_net.columns.tolist()
        vip_reales = [c for c in cols_prioridad if c in cols_existentes]
        orden_final = vip_reales + [c for c in cols_existentes if c not in vip_reales]
        
        st.dataframe(df_net[orden_final], use_container_width=True, hide_index=True, column_config={
            "@timestamp": st.column_config.DatetimeColumn("📅 Fecha/Hora", format="DD/MM/YYYY HH:mm:ss", width="medium"),
            "protocol": st.column_config.TextColumn("Proto", width="small"),
            "conn_state": st.column_config.TextColumn("Estado", help="SF: Normal, S0: Intento, REJ: Rechazado", width="small"),
            "duration": st.column_config.NumberColumn("Duración (s)", format="%.4f")
        })
        st.caption(f"Visualizando {len(df_net)} conexiones.")
    else: st.info("✅ Sin tráfico de red general.")

# ---------------- PESTAÑA 4: SCADA ----------------
with tab_ot:
    mask_ot = ((df['protocol'] == 'iec104') | (df['dst_port'].astype(str).isin(['2404', '502', '102', '20000'])) | (df.get('sub_source') == 'zeek_iec104'))
    df_ot = df[mask_ot].copy()

    if not df_ot.empty:
        # Aplicar lógica SCADA
        df_ot['comando_humano'] = df_ot.apply(lógica_interpretar_scada, axis=1)
        df_ot['ia_pct'] = df_ot['ai_score'].apply(lógica_calcular_anomalia_pct)

        cols_ot = ['@timestamp', 'comando_humano', 'src_ip', 'dst_ip', 'dst_port', 'protocol', 'risk_total_score', 'ia_pct', 'mitre_tactics', 'raw_log']
        view_ot = df_ot[[c for c in cols_ot if c in df_ot.columns]].copy()

        st.dataframe(view_ot, use_container_width=True, hide_index=True, column_config={
            "@timestamp": st.column_config.DatetimeColumn("📅 Fecha/Hora", format="DD/MM/YYYY HH:mm:ss", width="medium"),
            "comando_humano": st.column_config.TextColumn("🏭 Acción / Comando", width="large"),
            "risk_total_score": st.column_config.ProgressColumn("Riesgo", min_value=0, max_value=25, format="%d", width="small"),
            "ia_pct": st.column_config.NumberColumn("IA %", format="%d%%", help="Probabilidad de Anomalía"),
            "raw_log": st.column_config.TextColumn("📝 Payload Técnico", width="large")
        })
        st.caption("🔍 Leyenda: STARTDT (Inicio) | STOPDT (Parada) | TESTFR (Heartbeat) | C_IC (Interrogación) | C_SC (Comando de Mando)")
    else:
        st.info("🏭 Esperando tráfico de protocolos industriales (IEC-104, Modbus, DNP3)...")

# ---------------- PESTAÑA 5: VULNERABILIDADES ----------------
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
            st.dataframe(pd.read_csv(REPORT_FILE), use_container_width=True)

# ---------------- PESTAÑA 6: RAW ----------------
with tab_raw:
    st.write("Datos crudos de Elasticsearch:")
    st.dataframe(df, use_container_width=True)
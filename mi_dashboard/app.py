import streamlit as st
import pandas as pd
from elasticsearch import Elasticsearch
import plotly.express as px
import datetime
import os
import json
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

# Conexión a Elasticsearch
try: 
    es = Elasticsearch("http://elasticsearch:9200")
except: 
    es = None

# ==========================================
# LÓGICA DE NEGOCIO (HELPER FUNCTIONS)
# ==========================================

def get_data(minutes=60, start=None, end=None, limit=5000):
    if not es: return pd.DataFrame()
    
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
            return pd.DataFrame()
            
        df = pd.DataFrame(hits)
        
        # --- 🛡️ ZONA DE BLINDAJE (AQUÍ ESTÁ LA CORRECCIÓN) ---
        # Lista de columnas que EL DASHBOARD NECESITA SÍ O SÍ para no romperse.
        # Si no vienen de la BD, las creamos vacías.
        cols_blindadas = [
            'protocol', 'src_port', 'dst_port', 'src_ip', 'dst_ip', 'conn_state',
            'risk_total_score', 'risk_label', 'mitre_msg', 'source', 'sub_source', 
            'ai_score', 'raw_log', 'mitre_tactics', 'mitre_techniques'
        ]
        
        for col in cols_blindadas:
            if col not in df.columns:
                df[col] = "N/A" # Relleno por defecto para evitar KeyError
                
        # Aseguramos que los scores sean numéricos (para que no fallen las gráficas)
        df['risk_total_score'] = pd.to_numeric(df['risk_total_score'], errors='coerce').fillna(0)
        df['ai_score'] = pd.to_numeric(df['ai_score'], errors='coerce').fillna(0.5)
        # -----------------------------------------------------

        # Procesamiento de Fechas
        df['@timestamp'] = pd.to_datetime(df['@timestamp'])
        if df['@timestamp'].dt.tz is None:
            df['@timestamp'] = df['@timestamp'].dt.tz_localize('UTC')
        df['@timestamp'] = df['@timestamp'].dt.tz_convert('America/Santiago')
        
        # Limpieza visual de listas (para que no se vean corchetes feos)
        if 'mitre_tactics' in df.columns:
            df['mitre_tactics'] = df['mitre_tactics'].apply(lambda x: ", ".join(x) if isinstance(x, list) else str(x))
        
        return df

    except Exception as e:
        print(f"Error recuperando datos: {e}")
        return pd.DataFrame()

def lógica_interpretar_scada(row):
    """Traduce comandos técnicos a lenguaje humano"""
    texto_raw = (str(row.get('raw_log', '')) + " " + str(row.get('message', ''))).upper()
    texto = f" {texto_raw} " 
    dst_port = str(row.get('dst_port'))
    state = str(row.get('conn_state', '')).upper()
    proto = str(row.get('protocol', '')).lower()

    if 'STARTDT' in texto: return "🟢 Inicio Conexión (STARTDT)"
    if 'STOPDT' in texto:  return "🔴 Fin Conexión (STOPDT)"
    if 'TESTFR' in texto:  return "💓 Latido / Test (TESTFR)"
    if 'C_IC' in texto or 'INTERROGATION' in texto: return "❓ Interrogación General"
    if 'C_CS' in texto or 'CLOCK' in texto: return "⏰ Sincronización Reloj"
    if 'M_SP' in texto: return "📡 Info Punto Simple"
    if 'M_DP' in texto: return "📡 Info Punto Doble"
    if 'C_SC' in texto: return "⚙️ Comando Control (Switch)"
    
    # Formatos cortos
    if ' U ' in texto or '\tU\t' in texto: return "⚙️ Gestión (Formato U)"
    if ' S ' in texto or '\tS\t' in texto: return "🛡️ Supervisión (Formato S)"
    if ' I ' in texto or '\tI\t' in texto: return "📦 Datos Proceso (Formato I)"
    
    if 'MODBUS' in texto or dst_port == '502':
        if 'EXCEPTION' in texto: return "⚠️ Error Modbus"
        if 'func 5' in texto.lower() or 'write' in texto.lower(): return "📝 Escritura (Write)"
        return "👁️ Lectura Modbus"

    if state == 'REJ': return "⛔ Rechazada"
    if state == 'S0':  return "⚠️ Intento Sin Respuesta"
    
    return "📦 Tráfico Industrial Genérico"

def lógica_calcular_anomalia_pct(valor):
    """Convierte score negativo (-1.0) a porcentaje positivo (100%)"""
    try:
        val = float(valor)
        # Si es negativo (anomalía), convertimos a porcentaje positivo.
        # Si es positivo (normal), es 0% anomalía.
        return int(abs(val) * 100) if val < 0 else 0
    except:
        return 0

def lógica_limpiar_snort_msg(row):
    """Limpia mensajes de Snort"""
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
        
        # 1. Riesgo Máximo
        max_score = df['risk_total_score'].max()
        
        # 2. Conteo Críticos
        criticos = len(df[df['risk_total_score'] >= 17])
        
        # 3. KPI ANOMALÍA IA CORREGIDO
        # Buscamos el valor MÍNIMO de ai_score (el más negativo = mayor anomalía)
        if 'ai_score' in df.columns:
            peor_score_ia = df['ai_score'].min()
            nivel_anomalia_kpi = lógica_calcular_anomalia_pct(peor_score_ia)
        else:
            nivel_anomalia_kpi = 0
            
        # 4. Activos
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
            # Filtramos incidentes relevantes
            df_risk = df[df['risk_total_score'] >= 8].drop_duplicates(subset=['src_ip', 'mitre_msg']).head(5)
            
            if df_risk.empty:
                st.success("✅ Sistema estable. No hay incidentes de riesgo Medio/Alto.")
            
            for index, row in df_risk.iterrows():
                css_class = "risk-card-critical" if row['risk_total_score'] >= 17 else "risk-card-medium"
                icon = "🚨" if row['risk_total_score'] >= 17 else "⚠️"
                
                # Calculamos % específico para esta tarjeta
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

# ---------------- PESTAÑA 2: SNORT ----------------
with tab_snort:
    if not df.empty and 'source' in df.columns:
        df_snort = df[df['source'] == 'snort'].copy()
        if not df_snort.empty:
            df_snort['mensaje_limpio'] = df_snort.apply(lógica_limpiar_snort_msg, axis=1)

            st.dataframe(df_snort[['@timestamp', 'mensaje_limpio', 'risk_label', 'risk_total_score', 'src_ip', 'dst_ip']], 
                         use_container_width=True, hide_index=True)
        else: st.info("✅ No hay alertas de Snort.")
    else: st.info("✅ Sin alertas.")

# ---------------- PESTAÑA 3: RED ----------------
with tab_net:
    if not df.empty:
        mask_net = (df['source'] == 'zeek') & (df['protocol'] != 'iec104')
        df_net = df[mask_net].copy()
        if not df_net.empty:
            st.dataframe(df_net[['@timestamp', 'protocol', 'src_ip', 'dst_ip', 'dst_port', 'conn_state']], 
                         use_container_width=True, hide_index=True)
        else: st.info("✅ Sin tráfico de red general.")

# ---------------- PESTAÑA 4: SCADA ----------------
with tab_ot:
    mask_ot = ((df['protocol'] == 'iec104') | (df['dst_port'].astype(str).isin(['2404', '502', '102'])) | (df.get('sub_source') == 'zeek_iec104'))
    df_ot = df[mask_ot].copy()

    if not df_ot.empty:
        df_ot['comando_humano'] = df_ot.apply(lógica_interpretar_scada, axis=1)
        df_ot['ia_pct'] = df_ot['ai_score'].apply(lógica_calcular_anomalia_pct)

        st.dataframe(df_ot[['@timestamp', 'comando_humano', 'src_ip', 'dst_ip', 'risk_total_score', 'ia_pct']], 
                     use_container_width=True, hide_index=True)
    else:
        st.info("🏭 Esperando tráfico industrial...")

# ---------------- PESTAÑA 5: VULNERABILIDADES (MEJORADA) ----------------
with tab_vuln:
    st.header("🛡️ Gestión de Vulnerabilidades")
    
    # Dividimos la pantalla: Izquierda (Gestión Inventario), Derecha (Reporte CVEs)
    c1, c2 = st.columns([1, 2])
    
    # --- COLUMNA IZQUIERDA: GESTIÓN DE INVENTARIO ---
    with c1:
        st.subheader("📦 Inventario Operativo")
        
        # 1. FORMULARIO DE ALTA (Usamos st.form para agrupar los inputs)
        with st.form("form_add_asset", clear_on_submit=True):
            st.markdown("#### ➕ Agregar Nuevo Activo")
            
            # Campos de entrada correspondientes a tu estructura JSON
            new_ip = st.text_input("Dirección IP", placeholder="Ej: 192.168.1.50")
            new_name = st.text_input("Nombre del Dispositivo", placeholder="Ej: PLC_Hornos")
            new_crit = st.selectbox("Nivel de Criticidad", ["LOW", "MEDIUM", "HIGH", "CRITICAL"])
            
            # Botón de envío dentro del form
            submitted = st.form_submit_button("💾 Guardar Activo")
            
            if submitted:
                if new_ip and new_name:
                    try:
                        # A. Leer datos existentes
                        current_data = []
                        if os.path.exists(INVENTORY_FILE):
                            with open(INVENTORY_FILE, 'r') as f:
                                try:
                                    content = f.read()
                                    if content: # Si no está vacío
                                        current_data = json.loads(content)
                                except json.JSONDecodeError:
                                    current_data = [] # Si el archivo está corrupto, empezamos de cero

                        # B. Crear el nuevo objeto con TU estructura exacta
                        new_entry = {
                            "ip": new_ip.strip(),
                            "name": new_name.strip(),
                            "criticality": new_crit
                        }
                        
                        # C. Validar duplicados (Opcional: chequear si la IP ya existe)
                        # Filtramos si ya existía esa IP para actualizarla, o simplemente agregamos
                        current_data = [x for x in current_data if x.get('ip') != new_entry['ip']]
                        current_data.append(new_entry)
                        
                        # D. Guardar en disco
                        with open(INVENTORY_FILE, 'w') as f:
                            json.dump(current_data, f, indent=4)
                            
                        st.success(f"✅ Guardado: {new_name} ({new_ip})")
                        
                    except Exception as e:
                        st.error(f"❌ Error al guardar: {e}")
                else:
                    st.warning("⚠️ Debes ingresar al menos IP y Nombre.")

        # 2. VISUALIZACIÓN DEL INVENTARIO ACTUAL
        st.divider()
        st.markdown("#### 📋 Activos Registrados")
        if os.path.exists(INVENTORY_FILE):
            try:
                with open(INVENTORY_FILE, 'r') as f:
                    inventory_data = json.load(f)
                
                if inventory_data:
                    # Mostramos como tabla pequeña
                    df_inv = pd.DataFrame(inventory_data)
                    st.dataframe(
                        df_inv, 
                        column_config={
                            "ip": "IP",
                            "name": "Nombre",
                            "criticality": st.column_config.SelectboxColumn(
                                "Criticidad",
                                options=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                                disabled=True # Solo lectura aquí
                            )
                        },
                        use_container_width=True,
                        hide_index=True
                    )
                else:
                    st.info("El inventario está vacío.")
            except:
                st.warning("No se pudo leer el archivo de inventario.")

    # --- COLUMNA DERECHA: REPORTE DE VULNERABILIDADES (CVEs) ---
    with c2:
        st.subheader("🔍 Escáner de Vulnerabilidades (CVEs)")
        
        col_btn, col_info = st.columns([1, 3])
        
        # Variable de estado para saber si acabamos de escanear
        scan_done = False

        with col_btn:
            if st.button("🚀 Iniciar Escaneo", type="primary"):
                with st.spinner("Escaneando activos contra base de datos CVE..."):
                    try:
                        # 1. Ejecutar el script
                        # check=True lanza una excepción si el script falla
                        result = subprocess.run(["python3", SCANNER_SCRIPT], capture_output=True, text=True, check=False)
                        
                        if result.returncode == 0:
                            st.success("Escaneo finalizado.")
                            scan_done = True # Marcamos éxito
                            
                            # TRUCO: Limpiamos la caché de Streamlit para obligar a releer el CSV nuevo
                            st.cache_data.clear()
                        else:
                            st.error(f"El escáner reportó un error:\n{result.stderr}")
                            
                    except Exception as e:
                        st.error(f"Fallo crítico al ejecutar script: {e}")
        
        # --- LÓGICA DE VISUALIZACIÓN DE LA TABLA (BLINDADA) ---
        if os.path.exists(REPORT_FILE):
            try:
                # 2. Leemos el CSV
                # on_bad_lines='skip' evita que el sistema explote si hay una línea mal escrita
                df_cve = pd.read_csv(REPORT_FILE, on_bad_lines='skip')
                
                if not df_cve.empty:
                    # 3. NORMALIZACIÓN DE COLUMNAS (La solución al "choque de formatos")
                    # Convertimos todo a minúsculas y quitamos espacios: " Severity " -> "severity"
                    df_cve.columns = [c.lower().strip() for c in df_cve.columns]
                    
                    # Verificamos si tenemos las columnas necesarias, si no, las creamos vacías
                    required_cols = ['ip', 'cve_id', 'severity', 'description']
                    for col in required_cols:
                        if col not in df_cve.columns:
                            df_cve[col] = "N/A"

                    # 4. Mostrar Tabla
                    st.dataframe(
                        df_cve, 
                        use_container_width=True,
                        column_config={
                            "ip": "Activo IP",
                            "severity": st.column_config.TextColumn(
                                "Severidad",
                                help="Nivel de riesgo CVSS",
                                validate="^.*$" # Acepta cualquier texto
                            ),
                            "cve_id": "ID CVE",
                            "description": "Descripción Técnica"
                        }
                    )
                    
                    # Mostrar contador simple
                    st.caption(f"Total vulnerabilidades detectadas: {len(df_cve)}")
                    
                else:
                    st.info("✅ El reporte está vacío. No se encontraron vulnerabilidades o el escaneo no trajo resultados.")
                    
            except pd.errors.EmptyDataError:
                st.warning("⚠️ El archivo de reporte existe pero está vacío. Ejecuta un escaneo.")
            except Exception as e:
                st.error(f"❌ Error leyendo reporte CSV: {e}")
        else:
            st.info("ℹ️ No hay reporte generado aún. Presiona 'Iniciar Escaneo'.")

# ---------------- PESTAÑA 6: RAW ----------------
with tab_raw:
    st.write("Datos crudos:")
    st.dataframe(df, use_container_width=True)
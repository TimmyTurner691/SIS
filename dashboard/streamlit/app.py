import streamlit as st
import pandas as pd
from elasticsearch import Elasticsearch
import plotly.express as px
import plotly.graph_objects as go
import numpy as np
import datetime
import ipaddress
import os
import json
import subprocess
import re
import time
import redis  # <--- NUEVO: Necesario para enviar comandos
from pathlib import Path

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
DISCOVERED_ASSETS_INDEX = os.getenv("SIS_DASHBOARD_DISCOVERED_ASSETS_INDEX", "sis-discovered-assets-v3")
SENSOR_HEALTH_DIR = os.getenv("SIS_SENSOR_HEALTH_DIR", "/sensor-health")
RFC1918_NETWORKS = tuple(ipaddress.ip_network(cidr) for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))

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



def is_private_ipv4_address(value):
    try:
        ip = ipaddress.ip_address(str(value))
    except ValueError:
        return False
    if ip.version != 4 or not any(ip in network for network in RFC1918_NETWORKS):
        return False
    last_octet = int(str(ip).split(".")[-1])
    return last_octet not in {0, 255}


def network_for_private_ipv4_address(value, prefix=24):
    if not is_private_ipv4_address(value):
        return None
    try:
        prefix = min(max(int(prefix), 24), 30)
        return str(ipaddress.ip_network(f"{value}/{prefix}", strict=False))
    except ValueError:
        return None


def _sensor_status(sensor_name):
    file_path = Path(SENSOR_HEALTH_DIR) / f"{sensor_name}.json"
    if not file_path.exists():
        return "🔴 Caído", "Sin heartbeat"

    try:
        payload = json.loads(file_path.read_text())
        ts_raw = payload.get("timestamp")
        ts = pd.to_datetime(ts_raw, utc=True, errors="coerce")
        age_sec = (pd.Timestamp.utcnow() - ts).total_seconds() if pd.notna(ts) else 999999

        if age_sec <= 30:
            state = "🟢 Escuchando"
        elif age_sec <= 120:
            state = "🟡 Degradado"
        else:
            state = "🔴 Caído"

        info = f"if={payload.get('interface', 'N/A')} | promisc={payload.get('promiscuous', 'N/A')} | modo={payload.get('mode', 'N/A')}"
        return state, info
    except Exception:
        return "🔴 Error", "Heartbeat inválido"


def render_sensor_health_sidebar():
    st.sidebar.markdown("### Estado Sensores")
    for sensor in ["zeek", "snort"]:
        state, info = _sensor_status(sensor)
        st.sidebar.write(f"**{sensor.upper()}**: {state}")
        st.sidebar.caption(info)

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



def get_discovered_assets(limit=2000):
    cols = [
        "ip", "mac", "hostname", "vendor_oui", "protocolos_vistos",
        "puertos_observados", "primera_vez_visto", "ultima_vez_visto",
        "criticidad_sugerida", "so_estimado", "fuentes", "event_count", "asset_id"
    ]
    if not es:
        return pd.DataFrame(columns=cols)

    query = {
        "query": {"match_all": {}},
        "sort": [{"ultima_vez_visto": "desc"}],
        "size": limit,
    }

    try:
        res = es.search(index=DISCOVERED_ASSETS_INDEX, body=query, ignore_unavailable=True)
        hits = [h.get("_source", {}) for h in res.get("hits", {}).get("hits", [])]
        if not hits:
            return pd.DataFrame(columns=cols)
        df_assets = pd.DataFrame(hits)
        if "ip" in df_assets.columns:
            df_assets = df_assets[df_assets["ip"].apply(is_private_ipv4_address)]
        if df_assets.empty:
            return pd.DataFrame(columns=cols)
        for col in cols:
            if col not in df_assets.columns:
                df_assets[col] = "N/A"

        for col in ["protocolos_vistos", "puertos_observados", "fuentes"]:
            df_assets[col] = df_assets[col].apply(lambda x: ", ".join(map(str, x)) if isinstance(x, list) else str(x))

        for col in ["primera_vez_visto", "ultima_vez_visto"]:
            df_assets[col] = pd.to_datetime(df_assets[col], errors="coerce", utc=True)
            df_assets[col] = df_assets[col].dt.tz_convert("America/Santiago")

        df_assets["event_count"] = pd.to_numeric(df_assets["event_count"], errors="coerce").fillna(0).astype(int)
        return df_assets[cols]
    except Exception as e:
        print(f"Error recuperando activos descubiertos: {e}")
        return pd.DataFrame(columns=cols)




def ensure_discovered_asset_selection_state():
    if "selected_discovered_asset_ids" not in st.session_state:
        st.session_state["selected_discovered_asset_ids"] = set()
    elif not isinstance(st.session_state["selected_discovered_asset_ids"], set):
        st.session_state["selected_discovered_asset_ids"] = set(st.session_state["selected_discovered_asset_ids"])


def sync_discovered_asset_selection_from_editor():
    ensure_discovered_asset_selection_state()
    editor_state = st.session_state.get("discovered_assets_selection_editor", {})
    visible_ids = st.session_state.get("discovered_assets_visible_ids", [])
    selected = set(st.session_state["selected_discovered_asset_ids"])

    for row_idx, changes in editor_state.get("edited_rows", {}).items():
        try:
            asset_id = visible_ids[int(row_idx)]
        except (ValueError, IndexError):
            continue
        if "seleccionar" not in changes:
            continue
        if changes["seleccionar"]:
            selected.add(asset_id)
        else:
            selected.discard(asset_id)

    st.session_state["selected_discovered_asset_ids"] = selected

def delete_discovered_assets(asset_ids):
    if not es:
        return False, "No hay conexión con Elasticsearch."
    clean_ids = sorted({str(asset_id) for asset_id in asset_ids if str(asset_id) not in ("", "N/A", "nan")})
    if not clean_ids:
        return False, "No hay activos seleccionados para eliminar."

    deleted = 0
    for asset_id in clean_ids:
        try:
            es.delete(index=DISCOVERED_ASSETS_INDEX, id=asset_id, ignore=[404], refresh=True)
            deleted += 1
        except Exception as e:
            return False, f"Error eliminando activo {asset_id}: {e}"
    return True, f"Activos eliminados: {deleted}."


def clear_discovered_assets():
    if not es:
        return False, "No hay conexión con Elasticsearch."
    try:
        es.delete_by_query(
            index=DISCOVERED_ASSETS_INDEX,
            body={"query": {"match_all": {}}},
            conflicts="proceed",
            refresh=True,
            ignore_unavailable=True,
        )
        return True, "Todos los activos descubiertos fueron eliminados."
    except Exception as e:
        return False, f"Error vaciando activos descubiertos: {e}"

def load_inventory_data():
    if not os.path.exists(INVENTORY_FILE):
        return []
    try:
        with open(INVENTORY_FILE, "r") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except Exception:
        return []


def save_inventory_data(data):
    with open(INVENTORY_FILE, "w") as f:
        json.dump(data, f, indent=4)


def promote_discovered_asset(asset):
    inventory_data = load_inventory_data()
    ip = str(asset.get("ip", "")).strip()
    if not is_private_ipv4_address(ip):
        return False, "Solo se pueden promover activos con IPv4 privada."

    default_name = asset.get("hostname") if asset.get("hostname") not in (None, "", "N/A") else f"Descubierto_{ip}"
    promoted = {
        "ip": ip,
        "name": default_name,
        "criticality": asset.get("criticidad_sugerida", "LOW"),
        "source": "discovered_assets",
        "mac": asset.get("mac", "N/A"),
        "vendor": asset.get("vendor_oui", "Desconocido"),
        "os_estimate": asset.get("so_estimado", "Sin evidencia suficiente"),
    }

    replaced = False
    for idx, item in enumerate(inventory_data):
        if item.get("ip") == ip:
            inventory_data[idx] = {**item, **promoted}
            replaced = True
            break
    if not replaced:
        inventory_data.append(promoted)

    save_inventory_data(inventory_data)
    return True, "Activo actualizado en inventario." if replaced else "Activo promovido al inventario."

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

render_sensor_health_sidebar()
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
tab_risk, tab_snort, tab_net, tab_ot, tab_assets, tab_vuln, tab_raw = st.tabs([
    "🚨 Fusión de Riesgos", "🛡️ IDS", "🌐 Red", "🏭 SCADA", "🧭 Equipos Descubiertos", "⚠️ Vulnerabilidades", "📝 Logs Raw"
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


# Pestaña Equipos Descubiertos
with tab_assets:
    st.header("🧭 Equipos Descubiertos")
    st.caption("Activos consolidados automáticamente desde tráfico Zeek, alertas IDS y otras fuentes observadas.")

    df_assets = get_discovered_assets()
    redes_descubiertas = sorted({
        network
        for ip in df_assets.get("ip", pd.Series(dtype=str)).astype(str)
        if (network := network_for_private_ipv4_address(ip))
    })

    action_col, info_col = st.columns([1, 3])
    with action_col:
        if st.button("🔁 Re-escanear redes locales", type="secondary"):
            if r:
                try:
                    r.set("cmd_rescan_discovered_networks", "true")
                    st.success("Orden enviada: el sensor re-escaneará sus redes locales y cualquier red descubierta con nmap ping+ARP sweep.")
                except Exception as e:
                    st.error(f"Error Redis: {e}")
            else:
                st.error("No hay conexión con Redis para enviar la orden de re-escaneo.")
    with info_col:
        st.caption(
            "Redes detectadas en la tabla (el sensor también usará sus redes locales): "
            + (", ".join(redes_descubiertas) if redes_descubiertas else "ninguna todavía")
        )

    if df_assets.empty:
        st.info("Aún no hay equipos descubiertos. Se poblarán automáticamente cuando llegue tráfico nuevo.")
    else:
        c1, c2, c3 = st.columns([2, 1, 1])
        with c1:
            filtro_texto = st.text_input("Filtrar por IP, hostname, MAC, fabricante o SO", key="asset_filter_text")
        with c2:
            criticidades = sorted([x for x in df_assets["criticidad_sugerida"].dropna().unique().tolist() if x != "N/A"])
            filtro_crit = st.multiselect("Criticidad sugerida", criticidades, default=criticidades, key="asset_filter_crit")
        with c3:
            protocolos = sorted({p.strip() for value in df_assets["protocolos_vistos"].dropna() for p in str(value).split(",") if p.strip()})
            filtro_proto = st.multiselect("Protocolos", protocolos, key="asset_filter_proto")

        filtrado = df_assets.copy()
        if filtro_texto:
            needle = filtro_texto.lower().strip()
            mask = filtrado.apply(lambda row: needle in " ".join(map(str, row.values)).lower(), axis=1)
            filtrado = filtrado[mask]
        if filtro_crit:
            filtrado = filtrado[filtrado["criticidad_sugerida"].isin(filtro_crit)]
        if filtro_proto:
            filtrado = filtrado[filtrado["protocolos_vistos"].apply(lambda value: any(proto in str(value) for proto in filtro_proto))]

        k1, k2, k3, k4 = st.columns(4)
        k1.metric("Equipos", len(filtrado))
        k2.metric("Críticos sugeridos", len(filtrado[filtrado["criticidad_sugerida"] == "CRITICAL"]))
        k3.metric("Con MAC", len(filtrado[filtrado["mac"].astype(str) != "N/A"]))
        k4.metric("Con hostname", len(filtrado[filtrado["hostname"].astype(str) != "N/A"]))

        if filtrado.empty:
            st.warning("No hay equipos descubiertos que coincidan con los filtros actuales.")
        else:
            ensure_discovered_asset_selection_state()
            visible_asset_ids = filtrado["asset_id"].dropna().astype(str).tolist()
            visible_asset_id_set = set(visible_asset_ids)
            st.session_state["discovered_assets_visible_ids"] = visible_asset_ids

            select_all_assets = st.checkbox("Seleccionar todos los activos filtrados", key="select_all_discovered_assets")
            previous_select_all = st.session_state.get("_previous_select_all_discovered_assets", False)
            if select_all_assets != previous_select_all:
                selected_state = set(st.session_state["selected_discovered_asset_ids"])
                if select_all_assets:
                    selected_state.update(visible_asset_id_set)
                else:
                    selected_state.difference_update(visible_asset_id_set)
                st.session_state["selected_discovered_asset_ids"] = selected_state
                st.session_state["_previous_select_all_discovered_assets"] = select_all_assets

            table_columns = [
                "seleccionar", "ip", "hostname", "mac", "vendor_oui", "protocolos_vistos",
                "puertos_observados", "primera_vez_visto", "ultima_vez_visto",
                "criticidad_sugerida", "so_estimado", "fuentes", "event_count", "asset_id"
            ]
            table_df = filtrado.copy()
            selected_state = set(st.session_state["selected_discovered_asset_ids"])
            table_df.insert(0, "seleccionar", table_df["asset_id"].astype(str).isin(selected_state))

            edited_assets = st.data_editor(
                table_df[table_columns],
                use_container_width=True,
                hide_index=True,
                disabled=[col for col in table_columns if col != "seleccionar"],
                column_config={
                    "seleccionar": st.column_config.CheckboxColumn("Seleccionar", default=False),
                    "asset_id": None,
                },
                key="discovered_assets_selection_editor",
                on_change=sync_discovered_asset_selection_from_editor,
            )

            returned_selected_ids = set(edited_assets.loc[edited_assets["seleccionar"], "asset_id"].dropna().astype(str).tolist())
            selected_state = set(st.session_state["selected_discovered_asset_ids"])
            selected_state.difference_update(visible_asset_id_set)
            selected_state.update(returned_selected_ids)
            st.session_state["selected_discovered_asset_ids"] = selected_state
            selected_asset_ids = sorted(selected_state)
            bulk_col1, bulk_col2, bulk_col3 = st.columns([1, 1, 3])
            with bulk_col1:
                if st.button("🗑️ Eliminar seleccionados", disabled=not selected_asset_ids):
                    ok, msg = delete_discovered_assets(selected_asset_ids)
                    if ok:
                        st.session_state["selected_discovered_asset_ids"].difference_update(selected_asset_ids)
                        st.success(msg)
                        st.rerun()
                    else:
                        st.error(msg)
            with bulk_col2:
                confirm_clear = st.checkbox("Confirmar vaciado", key="confirm_clear_discovered_assets")
                if st.button("🧹 Vaciar todo", disabled=not confirm_clear):
                    ok, msg = clear_discovered_assets()
                    if ok:
                        st.session_state["selected_discovered_asset_ids"] = set()
                        st.success(msg)
                        st.rerun()
                    else:
                        st.error(msg)
            with bulk_col3:
                st.caption(f"Seleccionados: {len(selected_asset_ids)}. El vaciado total permite probar el descubrimiento desde cero.")

            st.subheader("Promover a inventario operativo")
            selected_ip = st.selectbox("Equipo descubierto", filtrado["ip"].tolist(), key="promote_asset_ip")
            selected_asset = filtrado[filtrado["ip"] == selected_ip].iloc[0].to_dict()
            st.caption(f"Se copiará como activo gestionado con nombre '{selected_asset.get('hostname') if selected_asset.get('hostname') != 'N/A' else 'Descubierto_' + selected_ip}' y criticidad {selected_asset.get('criticidad_sugerida', 'LOW')}.")
            if st.button("➕ Promover al inventario", type="primary"):
                try:
                    ok, msg = promote_discovered_asset(selected_asset)
                    if ok:
                        st.success(msg)
                    else:
                        st.error(msg)
                except Exception as e:
                    st.error(f"No se pudo promover el activo: {e}")

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

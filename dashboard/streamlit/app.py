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
import re
import time
import redis  # <--- NUEVO: Necesario para enviar comandos
from pathlib import Path

from signature_manager import SignatureError, SignatureManager

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
ES_HOST = os.getenv("SIS_DASHBOARD_ELASTIC_HOST", "elasticsearch")
ES_PORT = os.getenv("SIS_DASHBOARD_ELASTIC_PORT", "9200")
REDIS_HOST = os.getenv("SIS_DASHBOARD_REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("SIS_DASHBOARD_REDIS_PORT", "6379"))
INDEX_NAME = os.getenv("SIS_DASHBOARD_INDEX", "sis-logs-v1")
DISCOVERED_ASSETS_INDEX = os.getenv("SIS_DASHBOARD_DISCOVERED_ASSETS_INDEX", "sis-discovered-assets-v3")
SENSOR_HEALTH_DIR = os.getenv("SIS_SENSOR_HEALTH_DIR", "/sensor-health")
SIGNATURES_DIR = os.getenv("SIS_SIGNATURES_DIR", "/signatures")
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


def registered_assets_dataframe(inventory_data):
    rows = []
    for inventory_index, asset in enumerate(inventory_data):
        rows.append({
            "inventory_id": str(inventory_index),
            "ip": asset.get("ip", "N/A"),
            "name": asset.get("name", "N/A"),
            "type": asset.get("type", "N/A"),
            "mac": asset.get("mac", "N/A"),
            "vendor": asset.get("vendor", asset.get("vendor_oui", "Desconocido")),
            "criticidad": asset.get("criticality", asset.get("criticidad", "LOW")),
        })
    return pd.DataFrame(rows, columns=["inventory_id", "ip", "name", "type", "mac", "vendor", "criticidad"])


def ensure_registered_asset_selection_state():
    if "selected_registered_asset_ids" not in st.session_state:
        st.session_state["selected_registered_asset_ids"] = set()
    elif not isinstance(st.session_state["selected_registered_asset_ids"], set):
        st.session_state["selected_registered_asset_ids"] = set(st.session_state["selected_registered_asset_ids"])


def sync_registered_asset_selection_from_editor():
    ensure_registered_asset_selection_state()
    editor_state = st.session_state.get("registered_assets_selection_editor", {})
    visible_ids = st.session_state.get("registered_assets_visible_ids", [])
    selected = set(st.session_state["selected_registered_asset_ids"])

    for row_idx, changes in editor_state.get("edited_rows", {}).items():
        try:
            inventory_id = visible_ids[int(row_idx)]
        except (ValueError, IndexError):
            continue
        if "seleccionar" not in changes:
            continue
        if changes["seleccionar"]:
            selected.add(inventory_id)
        else:
            selected.discard(inventory_id)

    st.session_state["selected_registered_asset_ids"] = selected


def delete_registered_assets(inventory_ids):
    inventory_data = load_inventory_data()
    selected_indices = {
        int(inventory_id)
        for inventory_id in inventory_ids
        if str(inventory_id).isdigit() and int(inventory_id) < len(inventory_data)
    }
    if not selected_indices:
        return False, "No hay activos registrados seleccionados para eliminar."

    remaining_assets = [
        asset
        for inventory_index, asset in enumerate(inventory_data)
        if inventory_index not in selected_indices
    ]
    try:
        save_inventory_data(remaining_assets)
    except Exception as e:
        return False, f"No se pudieron eliminar los activos registrados: {e}"
    return True, f"Activos registrados eliminados: {len(selected_indices)}."


def _promote_asset_in_inventory(inventory_data, asset):
    ip = str(asset.get("ip", "")).strip()
    if not is_private_ipv4_address(ip):
        return False, False

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

    for idx, item in enumerate(inventory_data):
        if item.get("ip") == ip:
            inventory_data[idx] = {**item, **promoted}
            return True, True

    inventory_data.append(promoted)
    return True, False


def promote_discovered_asset(asset):
    inventory_data = load_inventory_data()
    promoted, replaced = _promote_asset_in_inventory(inventory_data, asset)
    if not promoted:
        return False, "Solo se pueden promover activos con IPv4 privada."

    save_inventory_data(inventory_data)
    return True, "Activo actualizado en inventario." if replaced else "Activo promovido al inventario."


def promote_discovered_assets(assets):
    inventory_data = load_inventory_data()
    promoted_count = 0
    updated_count = 0
    skipped_count = 0

    for asset in assets:
        promoted, replaced = _promote_asset_in_inventory(inventory_data, asset)
        if not promoted:
            skipped_count += 1
            continue
        promoted_count += 1
        updated_count += int(replaced)

    if not promoted_count:
        return False, "No se pudo promover ningún activo seleccionado con IPv4 privada."

    save_inventory_data(inventory_data)
    created_count = promoted_count - updated_count
    message = f"Activos promovidos: {promoted_count} ({created_count} nuevos, {updated_count} actualizados)."
    if skipped_count:
        message += f" Omitidos por IP inválida o no privada: {skipped_count}."
    return True, message


@st.dialog("Confirmar vaciado")
def confirm_clear_discovered_assets_dialog():
    st.write("¿Quieres eliminar todos los equipos descubiertos?")
    confirm_col, cancel_col = st.columns(2)
    with confirm_col:
        if st.button("Sí", type="primary", use_container_width=True):
            ok, msg = clear_discovered_assets()
            if ok:
                st.session_state["selected_discovered_asset_ids"] = set()
                st.session_state["discovered_assets_notice"] = ("success", msg)
                st.rerun()
            else:
                st.error(msg)
    with cancel_col:
        if st.button("Cancelar", use_container_width=True):
            st.rerun()

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
refresh_rate = 60

if modo == "En Vivo":
    st.sidebar.markdown("### ⏱️ Control de Tiempo")
    mins = st.sidebar.slider("Ventana de Datos (Min)", 5, 1440, 60)
    
    c_auto, c_sec = st.sidebar.columns([1, 1])
    with c_auto:
        auto_refresh = st.toggle("Auto-Refresh", value=True) 
    with c_sec:
        refresh_rate = st.number_input("Segundos", min_value=1, max_value=60, value=60)

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
tab_risk, tab_snort, tab_net, tab_ot, tab_assets, tab_registered_assets, tab_signatures, tab_raw = st.tabs([
    "🚨 Fusión de Riesgos", "🛡️ IDS", "🌐 Red", "🏭 SCADA", "🧭 Equipos Descubiertos", "📋 Activos Registrados", "✍️ Firmas / Reglas", "📝 Logs Raw"
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

    notice = st.session_state.pop("discovered_assets_notice", None)
    if notice:
        notice_type, notice_message = notice
        getattr(st, notice_type)(notice_message)

    df_assets = get_discovered_assets()
    if st.button("🔁 Re-escanear redes locales", type="secondary"):
        if r:
            try:
                r.set("cmd_rescan_discovered_networks", "true")
                st.success("escaneando...")
            except Exception as e:
                st.error(f"Error Redis: {e}")
        else:
            st.error("No hay conexión con Redis para enviar la orden de re-escaneo.")

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
            selected_assets = df_assets[df_assets["asset_id"].astype(str).isin(selected_asset_ids)].to_dict("records")
            bulk_col1, bulk_col2, bulk_col3 = st.columns(3)
            with bulk_col1:
                if st.button("🗑️ Eliminar seleccionados", disabled=not selected_asset_ids, use_container_width=True):
                    ok, msg = delete_discovered_assets(selected_asset_ids)
                    if ok:
                        st.session_state["selected_discovered_asset_ids"].difference_update(selected_asset_ids)
                        st.session_state["discovered_assets_notice"] = ("success", msg)
                        st.rerun()
                    else:
                        st.error(msg)
            with bulk_col2:
                if st.button("🧹 Vaciar todo", use_container_width=True):
                    confirm_clear_discovered_assets_dialog()
            with bulk_col3:
                if st.button("Promover equipo", disabled=not selected_assets, type="primary", use_container_width=True):
                    try:
                        ok, msg = promote_discovered_assets(selected_assets)
                        if ok:
                            st.session_state["discovered_assets_notice"] = ("success", msg)
                            st.rerun()
                        else:
                            st.error(msg)
                    except Exception as e:
                        st.error(f"No se pudieron promover los activos: {e}")

# Pestaña Activos Registrados
with tab_registered_assets:
    st.header("📋 Activos Registrados")

    notice = st.session_state.pop("registered_assets_notice", None)
    if notice:
        notice_type, notice_message = notice
        getattr(st, notice_type)(notice_message)

    inventory_data = load_inventory_data()
    registered_assets = registered_assets_dataframe(inventory_data)
    if registered_assets.empty:
        st.info("No hay activos registrados.")
    else:
        registered_filter = st.text_input(
            "Filtrar por IP, nombre, tipo, MAC, fabricante o criticidad",
            key="registered_asset_filter_text",
        )
        filtered_registered_assets = registered_assets.copy()
        if registered_filter:
            needle = registered_filter.lower().strip()
            searchable_columns = ["ip", "name", "type", "mac", "vendor", "criticidad"]
            mask = filtered_registered_assets[searchable_columns].apply(
                lambda row: needle in " ".join(map(str, row.values)).lower(),
                axis=1,
            )
            filtered_registered_assets = filtered_registered_assets[mask]

        if filtered_registered_assets.empty:
            st.warning("No hay activos registrados que coincidan con el filtro actual.")
        else:
            ensure_registered_asset_selection_state()
            all_registered_ids = set(registered_assets["inventory_id"].astype(str))
            selected_state = set(st.session_state["selected_registered_asset_ids"])
            selected_state.intersection_update(all_registered_ids)
            st.session_state["selected_registered_asset_ids"] = selected_state

            visible_registered_ids = filtered_registered_assets["inventory_id"].astype(str).tolist()
            visible_registered_id_set = set(visible_registered_ids)
            st.session_state["registered_assets_visible_ids"] = visible_registered_ids

            if st.session_state.pop("_reset_registered_select_all", False):
                st.session_state["select_all_registered_assets"] = False
                st.session_state["_previous_select_all_registered_assets"] = False

            select_all_registered = st.checkbox(
                "Seleccionar todos los activos registrados filtrados",
                key="select_all_registered_assets",
            )
            previous_select_all = st.session_state.get("_previous_select_all_registered_assets", False)
            if select_all_registered != previous_select_all:
                selected_state = set(st.session_state["selected_registered_asset_ids"])
                if select_all_registered:
                    selected_state.update(visible_registered_id_set)
                else:
                    selected_state.difference_update(visible_registered_id_set)
                st.session_state["selected_registered_asset_ids"] = selected_state
                st.session_state["_previous_select_all_registered_assets"] = select_all_registered

            table_df = filtered_registered_assets.copy()
            selected_state = set(st.session_state["selected_registered_asset_ids"])
            table_df.insert(0, "seleccionar", table_df["inventory_id"].astype(str).isin(selected_state))
            table_columns = ["seleccionar", "ip", "name", "type", "mac", "vendor", "criticidad", "inventory_id"]

            edited_registered_assets = st.data_editor(
                table_df[table_columns],
                width="stretch",
                hide_index=True,
                disabled=[column for column in table_columns if column != "seleccionar"],
                column_config={
                    "seleccionar": st.column_config.CheckboxColumn("Seleccionar", default=False),
                    "inventory_id": None,
                },
                key="registered_assets_selection_editor",
                on_change=sync_registered_asset_selection_from_editor,
            )

            returned_selected_ids = set(
                edited_registered_assets.loc[
                    edited_registered_assets["seleccionar"], "inventory_id"
                ].astype(str)
            )
            selected_state = set(st.session_state["selected_registered_asset_ids"])
            selected_state.difference_update(visible_registered_id_set)
            selected_state.update(returned_selected_ids)
            st.session_state["selected_registered_asset_ids"] = selected_state
            selected_registered_ids = sorted(selected_state)

            if st.button(
                "🗑️ Eliminar seleccionados",
                disabled=not selected_registered_ids,
                key="delete_selected_registered_assets",
            ):
                ok, msg = delete_registered_assets(selected_registered_ids)
                if ok:
                    st.session_state["selected_registered_asset_ids"] = set()
                    st.session_state["_reset_registered_select_all"] = True
                    st.session_state["registered_assets_notice"] = ("success", msg)
                    st.rerun()
                else:
                    st.error(msg)

# Pestaña Firmas / Reglas
with tab_signatures:
    st.header("✍️ Firmas / Reglas")
    st.caption("Administre familias de detección y aplique cambios sin reiniciar el stack completo.")

    try:
        signature_manager = SignatureManager(SIGNATURES_DIR)
        package_rows = signature_manager.package_rows()
        signature_state = signature_manager.load_state()
        profiles = signature_manager.profiles()

        status_col, rules_col, profile_col = st.columns(3)
        status_col.metric("Paquetes activos", sum(row["enabled"] for row in package_rows))
        rules_col.metric("Reglas efectivas", signature_state.get("effective_rule_count", sum(row["rule_count"] for row in package_rows if row["enabled"])))
        active_profile = signature_state.get("profile")
        profile_names = {profile["id"]: profile["name"] for profile in profiles}
        profile_col.metric("Perfil base", profile_names.get(active_profile, "Personalizado"))

        sensor_reload = signature_manager.status()["sensor"]
        if sensor_reload:
            reload_state = sensor_reload.get("status", "desconocido")
            reload_message = sensor_reload.get("message", "Sin detalle")
            if reload_state == "applied":
                st.success(f"Última recarga aplicada: {reload_message}")
            elif reload_state == "rejected":
                st.error(f"Última recarga rechazada; el sensor conserva las reglas anteriores: {reload_message}")
            else:
                st.info(f"Estado de recarga: {reload_state} — {reload_message}")
        else:
            st.info("El sensor todavía no informó el estado de una recarga.")

        st.subheader("Perfiles de detección")
        profile_labels = {profile["name"]: profile for profile in profiles}
        profile_options = list(profile_labels)
        current_profile_name = profile_names.get(active_profile)
        selected_profile_name = st.selectbox(
            "Partir desde un perfil prearmado",
            profile_options,
            index=profile_options.index(current_profile_name) if current_profile_name in profile_options else 0,
            help="El perfil habilita una base que luego puede ajustar por paquete.",
        )
        selected_profile = profile_labels[selected_profile_name]
        st.caption(selected_profile.get("description", ""))
        if st.button("Aplicar perfil", type="primary", key="apply_signature_profile"):
            signature_manager.apply_profile(selected_profile["id"])
            for row in package_rows:
                st.session_state.pop(f"signature_installed_{row['id']}", None)
                st.session_state.pop(f"signature_enabled_{row['id']}", None)
            st.session_state["signature_notice"] = f"Perfil {selected_profile_name} solicitado al sensor."
            st.rerun()

        notice = st.session_state.pop("signature_notice", None)
        if notice:
            st.success(notice)

        st.divider()
        st.subheader("Catálogo de paquetes")
        with st.form("signature_packages_form"):
            header = st.columns([2, 4, 1, 1, 1])
            for column, label in zip(header, ["Paquete", "Cobertura", "Reglas", "Instalado", "Activo"]):
                column.markdown(f"**{label}**")

            installed_ids = []
            enabled_ids = []
            for row in package_rows:
                columns = st.columns([2, 4, 1, 1, 1])
                columns[0].write(row["name"])
                columns[1].caption(row.get("description", ""))
                columns[2].write(str(row["rule_count"]))
                installed = columns[3].checkbox(
                    f"Instalar {row['name']}",
                    value=row["installed"],
                    key=f"signature_installed_{row['id']}",
                    label_visibility="collapsed",
                )
                enabled = columns[4].checkbox(
                    f"Activar {row['name']}",
                    value=row["enabled"],
                    key=f"signature_enabled_{row['id']}",
                    label_visibility="collapsed",
                )
                if installed:
                    installed_ids.append(row["id"])
                if installed and enabled:
                    enabled_ids.append(row["id"])

            apply_packages = st.form_submit_button("Validar y aplicar selección", type="primary")
            if apply_packages:
                signature_manager.set_packages(installed_ids, enabled_ids)
                st.session_state["signature_notice"] = "Selección validada y recarga segura solicitada."
                st.rerun()

    except SignatureError as exc:
        st.error(f"Configuración de firmas inválida: {exc}")
    except OSError as exc:
        st.error(f"No se pudo acceder al almacenamiento de firmas: {exc}")

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

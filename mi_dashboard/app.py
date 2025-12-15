import streamlit as st
import redis
import json
import pandas as pd
import time
from elasticsearch import Elasticsearch

# Configuración
st.set_page_config(page_title="SIEM OT - Matriz de Riesgo", layout="wide")
st.title("🛡️ SIEM Industrial - Matriz de Riesgos Dinámica")

# Conexiones
r = redis.Redis(host='redis', port=6379, db=0)
es = Elasticsearch("http://elasticsearch:9200")

# Columnas principales
col1, col2 = st.columns([1, 2])

with col1:
    st.subheader("📡 Estado en Vivo")
    metric_ph = st.empty()
    alert_ph = st.empty()

with col2:
    st.subheader("📜 Historial de Eventos (Elasticsearch)")
    hist_ph = st.empty()

# Lógica de actualización (Simulada para Streamlit)
# En producción usaríamos st.connection o callbacks, aquí loop simple
p = r.pubsub()
p.subscribe('alertas_siem')

logs_recientes = []

while True:
    message = p.get_message()
    if message and message['type'] == 'message':
        data = json.loads(message['data'])
        logs_recientes.insert(0, data)
        if len(logs_recientes) > 10: logs_recientes.pop()
        
        # Actualizar Métrica
        riesgo = data['riesgo_total']
        delta_color = "normal"
        if riesgo >= 20: delta_color = "inverse"
        
        metric_ph.metric(label="Último Nivel de Riesgo", value=f"{riesgo}/25", delta=data['mensaje'], delta_color=delta_color)
        
        # Mostrar Alerta Grande si es Roja
        if data['color'] == "ROJO_CRITICO":
            alert_ph.error(f"🚨 ALERTA CRÍTICA: {data['mensaje']} - Origen: {data['origen']}")
        elif data['color'] == "AMARILLO":
            alert_ph.warning(f"⚠️ ALERTA: {data['mensaje']} - Origen: {data['origen']}")
        else:
            alert_ph.success("Sistema Estable")

    # Actualizar Tabla Histórica desde Elastic
    try:
        res = es.search(index="siem-logs", body={"query": {"match_all": {}}, "size": 20, "sort": [{"timestamp": "desc"}]})
        docs = [hit['_source'] for hit in res['hits']['hits']]
        if docs:
            df = pd.DataFrame(docs)
            hist_ph.dataframe(df[['timestamp', 'origen', 'riesgo_total', 'mensaje']])
    except:
        hist_ph.info("Esperando datos en Elastic...")

    time.sleep(1)

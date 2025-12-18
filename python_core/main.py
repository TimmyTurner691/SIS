import time
import json
import os
import redis
from elasticsearch import Elasticsearch

# --- CONFIGURACIÓN ---
REDIS_HOST = "redis"
REDIS_QUEUE = "sis_queue"  # La cola donde Filebeat deja los logs
ELASTIC_HOST = "elasticsearch"

# --- MEMORIA DE CORTO PLAZO (5 MINUTOS) ---
memoria_ataques = {}
VENTANA_TIEMPO = 300 

# --- CONEXIONES ---
print("🔌 Conectando a servicios...", flush=True)
try:
    # Conexión a Redis
    r = redis.Redis(host=REDIS_HOST, port=6379, db=0, decode_responses=False) # False para leer bytes raw
    # Conexión a Elastic
    es = Elasticsearch(f"http://{ELASTIC_HOST}:9200")
    print("✅ Conectado a Redis y Elastic", flush=True)
except Exception as e:
    print(f"⚠️ Error fatal de conexión: {e}", flush=True)
    exit(1)

# --- MATRIZ DE RIESGO (Lógica Original) ---
def calcular_riesgo(origen, tipo_ataque):
    global memoria_ataques
    tiempo_actual = time.time()

    # 1. Limpiar memoria vieja
    memoria_ataques = {k:v for k,v in memoria_ataques.items() if (tiempo_actual - v) < VENTANA_TIEMPO}
    
    # 2. Registrar el ataque actual
    memoria_ataques[origen] = tiempo_actual

    # 3. Lógica Base
    probabilidad = 2
    impacto = 2
    mensaje = "Evento Aislado"

    if "STOPDT" in tipo_ataque or "DoS" in tipo_ataque:
        probabilidad = 3
        impacto = 4

    # 4. CORRELACIÓN
    activos_afectados = len(memoria_ataques)
    if activos_afectados >= 2:
        print(f"🚨 ALERTA COORDINADA: {activos_afectados} Activos bajo fuego simultáneo!", flush=True)
        probabilidad = 5
        impacto = 5
        mensaje = f"ATAQUE COORDINADO. Activos: {list(memoria_ataques.keys())}"

    riesgo_total = probabilidad * impacto
    color = "VERDE"
    if riesgo_total >= 20: color = "ROJO_CRITICO"
    elif riesgo_total >= 10: color = "AMARILLO"

    return {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "origen": origen,
        "tipo": tipo_ataque,
        "probabilidad": probabilidad,
        "impacto": impacto,
        "riesgo_total": riesgo_total,
        "color": color,
        "mensaje": mensaje
    }

# --- PROCESADOR DE LOGS (Adaptado para Filebeat JSON) ---
def procesar_evento(datos):
    try:
        # Filebeat envía JSON. Lo convertimos a dict.
        log_json = json.loads(datos)
        
        # Extraemos el mensaje de texto original y el tipo de fuente
        linea = log_json.get('message', '')
        # Filebeat pone los campos custom bajo 'fields' o 'json'
        campos = log_json.get('fields', {})
        origen_log = campos.get('source_type', 'unknown') 
        
        # Si no viene en fields, intentamos inferirlo o buscar en tags
        if origen_log == 'unknown':
            path = log_json.get('log', {}).get('file', {}).get('path', '')
            if 'zeek' in path: origen_log = 'zeek'
            elif 'snort' in path: origen_log = 'snort'

        alerta = None

        # --- LÓGICA DE DETECCIÓN ---
        if origen_log == "zeek":
            if "STOPDT" in linea:
                alerta = calcular_riesgo("PLC_VIRTUAL", "Comando STOPDT (DoS)")
            elif "45" in linea: # Ejemplo IEC104 type 45
                alerta = calcular_riesgo("RTU_VIRTUAL", "Manipulación Actuador")
        
        elif origen_log == "snort":
            if "Priority: 1" in linea or "ICMP" in linea:
                alerta = calcular_riesgo("RED_GENERAL", "Firma Snort Detectada")

        # --- ACCIONES SI HAY ALERTA ---
        if alerta:
            print(f"🔥 {alerta['color']} - Riesgo {alerta['riesgo_total']}: {alerta['mensaje']}", flush=True)
            
            # 1. Enviar Alerta al Dashboard (Redis Pub/Sub)
            r.publish('alertas_siem', json.dumps(alerta))
            
            # 2. Guardar en Elastic (Persistencia)
            try: 
                es.index(index="siem-logs", document=alerta)
            except Exception as ex: 
                print(f"Error guardando en Elastic: {ex}", flush=True)

    except json.JSONDecodeError:
        print("⚠️ Error decodificando JSON de Filebeat", flush=True)
    except Exception as e:
        print(f"⚠️ Error procesando evento: {e}", flush=True)

# --- BUCLE PRINCIPAL (Consumidor de Cola) ---
if __name__ == "__main__":
    print("🚀 CEREBRO SIEM INICIADO (Modo: Consumidor Redis v4)", flush=True)
    print(f"👀 Esperando logs en la cola '{REDIS_QUEUE}'...", flush=True)

    contador = 0
    while True:
        # BLPOP espera hasta que llegue algo (timeout 5s para no bloquear eternamente)
        # Retorna una tupla (nombre_cola, datos)
        item = r.blpop(REDIS_QUEUE, timeout=5)
        
        if item:
            # item[1] contiene el payload
            procesar_evento(item[1])
            
            # Un pequeño contador visual para saber que está vivo procesando el backlog
            contador += 1
            if contador % 1000 == 0:
                print(f"📊 Procesados {contador} eventos...", flush=True)

import time
import json
import os
import redis
import threading
from elasticsearch import Elasticsearch

# --- CONFIGURACIÓN ---
LOG_ZEEK = "/app/logs_zeek/iec104.log"  # O conn.log según tu zeek
LOG_SNORT = "/app/logs_snort/alert"
REDIS_HOST = "redis"
ELASTIC_HOST = "elasticsearch"

# --- MEMORIA DE CORTO PLAZO (5 MINUTOS) ---
# Aquí guardamos qué equipos han sido atacados recientemente
memoria_ataques = {} 
VENTANA_TIEMPO = 300 # 300 segundos = 5 minutos

# --- CONEXIONES ---
try:
    r = redis.Redis(host=REDIS_HOST, port=6379, db=0)
    es = Elasticsearch(f"http://{ELASTIC_HOST}:9200")
    print("✅ Conectado a Redis y Elastic")
except Exception as e:
    print(f"⚠️ Error de conexión: {e}")

# --- MATRIZ DE RIESGO ---
def calcular_riesgo(origen, tipo_ataque):
    global memoria_ataques
    tiempo_actual = time.time()
    
    # 1. Limpiar memoria vieja (ataques de hace más de 5 min)
    memoria_ataques = {k:v for k,v in memoria_ataques.items() if (tiempo_actual - v) < VENTANA_TIEMPO}
    
    # 2. Registrar el ataque actual
    memoria_ataques[origen] = tiempo_actual
    
    # 3. Lógica de Matriz Base
    probabilidad = 2 # Baja por defecto
    impacto = 2      # Bajo por defecto
    mensaje = "Evento Aislado"
    
    if "STOPDT" in tipo_ataque or "DoS" in tipo_ataque:
        probabilidad = 3
        impacto = 4 # Alto
    
    # 4. LÓGICA DE CORRELACIÓN 
    # Si hay más de 1 activo diferente atacado en la ventana de tiempo
    activos_afectados = len(memoria_ataques)
    
    if activos_afectados >= 2:
        print(f"🚨 ALERTA COORDINADA: {activos_afectados} Activos bajo fuego simultáneo!")
        probabilidad = 5 # Muy Alta
        impacto = 5      # Catastrófico
        mensaje = f"ATAQUE COORDINADO (PLC + RTU/Otros). Activos: {list(memoria_ataques.keys())}"
        
    riesgo_total = probabilidad * impacto
    
    # Definir color
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

# --- PROCESADORES DE LOGS ---
def procesar_linea(origen_log, linea):
    alerta = None
    
    # Simulación de parsing (Ajustar según formato real de log)
    if origen_log == "ZEEK":
        if "STOPDT" in linea:
            alerta = calcular_riesgo("PLC_VIRTUAL", "Comando STOPDT (DoS)")
        elif "45" in linea: # Comando de control
            alerta = calcular_riesgo("RTU_VIRTUAL", "Manipulación Actuador")
            
    elif origen_log == "SNORT":
        if "Priority: 1" in linea or "ICMP" in linea: # Ejemplo
             alerta = calcular_riesgo("RED_GENERAL", "Firma Snort Detectada")

    # Si se generó una alerta, enviarla
    if alerta:
        print(f"🔥 {alerta['color']} - Riesgo {alerta['riesgo_total']}: {alerta['mensaje']}")
        # 1. Enviar a Redis (Para ver en vivo en Dashboard)
        if r: r.publish('alertas_siem', json.dumps(alerta))
        # 2. Guardar en Elastic (Para historial)
        if es: 
            try: es.index(index="siem-logs", body=alerta)
            except: pass

# --- VIGILANTE DE ARCHIVOS (TAIL -F) ---
def vigilar(ruta, tipo):
    print(f"👀 Vigilando {ruta}...")
    f = open(ruta, 'r')
    f.seek(0, 2) # Ir al final
    while True:
        linea = f.readline()
        if not linea:
            time.sleep(0.1)
            continue
        procesar_linea(tipo, linea)

if __name__ == "__main__":
    print("🚀 CEREBRO SIEM INICIADO (Modo Matriz de Riesgo)", flush=True)
    t1 = threading.Thread(target=vigilar, args=(LOG_ZEEK, "ZEEK"))
    t2 = threading.Thread(target=vigilar, args=(LOG_SNORT, "SNORT"))
    t1.start()
    t2.start()

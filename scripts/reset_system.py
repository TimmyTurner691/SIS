import os
import redis
from elasticsearch import Elasticsearch

# === CONFIGURACIÓN ===
ELASTIC_HOST = 'http://elasticsearch:9200'
INDEX_NAME = 'sis-logs-v1'
REDIS_HOST = 'redis'

# Archivos a vaciar (Trunca a 0 bytes sin borrar el archivo)
FILES_TO_CLEAN = [
    '/var/log/snort/alert',
    '/var/log/zeek/conn.log',
    '/var/log/zeek/iec104.log',
    '/app/cve_report.csv',    # Borramos el reporte de vulnerabilidades antiguo
    '/app/ot_inventory.json'  # Opcional: si quieres borrar el inventario
]

def clean_elastic():
    print("🗑️ Conectando a Elasticsearch...")
    try:
        es = Elasticsearch([ELASTIC_HOST])
        if es.indices.exists(index=INDEX_NAME):
            es.indices.delete(index=INDEX_NAME)
            print(f"   ✅ Índice '{INDEX_NAME}' eliminado.")
        else:
            print(f"   ℹ️ El índice '{INDEX_NAME}' no existía.")
    except Exception as e:
        print(f"   ❌ Error en Elastic: {e}")

def clean_redis():
    print("🧹 Limpiando Redis...")
    try:
        r = redis.Redis(host=REDIS_HOST, port=6379)
        r.flushall()
        print("   ✅ Redis vaciado.")
    except:
        print("   ⚠️ No se pudo conectar a Redis (quizás no esté activo).")

def clean_logs():
    print("asd📄 Vaciando archivos de log...")
    for file_path in FILES_TO_CLEAN:
        if os.path.exists(file_path):
            try:
                # Abrir en modo 'w' borra el contenido
                with open(file_path, 'w') as f:
                    pass 
                print(f"   ✅ Vaciado: {file_path}")
            except Exception as e:
                print(f"   ❌ Error vaciando {file_path}: {e}")
        else:
            print(f"   ⚠️ Archivo no encontrado: {file_path}")

def main():
    print("===================================")
    print("   SISTEMA DE LIMPIEZA TOTAL SIS   ")
    print("===================================")
    clean_elastic()
    clean_redis()
    clean_logs()
    print("\n✨ Sistema como nuevo. Reinicia 'main.py' para empezar limpio.")

if __name__ == "__main__":
    main()
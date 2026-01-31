import socket
import time
import threading
import sys

# --- CONFIGURACIÓN ---
TARGET_IP = "10.10.10.10"
TARGET_PORT = 2404

# Queremos llegar a ~80 EPS en total.
# Si usamos 4 hilos, cada uno debe aportar 20 EPS.
THREAD_COUNT = 4
DELAY_PER_THREAD = 0.05 # 1 seg / 0.05 = 20 peticiones por hilo

def atacar(thread_id):
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.1)
            s.connect((TARGET_IP, TARGET_PORT))
            
            # Payload IEC-104 (Test Frame)
            payload = b'\x68\x04\x43\x00\x00\x00'
            s.send(payload)
            s.close()
            
            # Imprimir solo el hilo 1 para no ensuciar la consola
            if thread_id == 0:
                print(f"⚡ [Thread-{thread_id}] Enviando paquete...", end="\r")
            
            time.sleep(DELAY_PER_THREAD)

        except Exception as e:
            # Si falla la conexión, espera un poco y reintenta
            time.sleep(1)

def main():
    print(f"\n🕵️ INICIANDO ESCANEO SUTIL MULTI-HILO")
    print(f"🎯 Objetivo: {TARGET_IP}:{TARGET_PORT}")
    print(f"🧵 Hilos: {THREAD_COUNT} | Ritmo Estimado Total: ~{int(1/DELAY_PER_THREAD * THREAD_COUNT)} EPS")
    print("-------------------------------------------------------------")

    threads = []
    for i in range(THREAD_COUNT):
        t = threading.Thread(target=atacar, args=(i,))
        t.daemon = True # Para que se cierren al matar el script principal
        t.start()
        threads.append(t)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n🛑 Ataque detenido.")

if __name__ == "__main__":
    main()  
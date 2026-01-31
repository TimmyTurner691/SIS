import socket
import struct
import time
import random
import select 

# --- CONFIGURACIÓN ---
HOST = '10.10.10.10' 
PORT = 2404
# ---------------------

def build_measure_packet(seq_send, value_float):
    # Construye paquete de medida
    start = 0x68
    length = 17 
    cf1, cf2, cf3, cf4 = (seq_send << 1) & 0xFF, 0, 0, 0
    type_id = 13    # M_ME_NC_1
    sq_num = 1; cot = 3; org = 0; common_addr = 1; ioa = 200
    
    val_bytes = struct.pack('<f', value_float) 
    qds = 0
    
    # CORRECCIÓN AQUÍ: Se agregó una 'B' extra al inicio del string de formato.
    # Antes: '<BBBBBBBBBBH' (10 bytes + 1 short) -> ERROR
    # Ahora: '<BBBBBBBBBBBH' (11 bytes + 1 short) -> CORRECTO para los 12 argumentos
    header = struct.pack('<BBBBBBBBBBBH', start, length, cf1, cf2, cf3, cf4, type_id, sq_num, cot, org, common_addr, ioa)
    
    return header + val_bytes + struct.pack('B', qds)

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server.bind((HOST, PORT))
    except PermissionError:
        print("❌ ERROR: Necesitas 'sudo' para usar el puerto 2404")
        return

    server.listen(1)
    print(f"🏭 RTU CORREGIDA Y LISTA EN PUERTO {PORT}")
    print("⏳ Esperando conexión del SCADA...")

    while True:
        try:
            conn, addr = server.accept()
            print(f"✅ SCADA CONECTADO: {addr}")
            conn.setblocking(0) # Modo No Bloqueante

            seq = 0
            last_sent_time = time.time()
            
            while True:
                # Usamos select para esperar eventos y evitar bloqueos
                ready_to_read, _, _ = select.select([conn], [], [], 1.0)

                # --- A. SI RECIBIMOS ALGO DEL CLIENTE ---
                if ready_to_read:
                    try:
                        data = conn.recv(1024)
                        if not data:
                            print("⚠️ SCADA se desconectó.")
                            break
                        
                        hex_data = data.hex().upper()
                        # Detección simple de comandos para el log
                        if "640106000100F40101" in hex_data: 
                            print(f"⚡ RECIBIDO COMANDO: ENCENDER (ON) | Raw: {hex_data}")
                        elif "640106000100F40100" in hex_data:
                            print(f"⛔ RECIBIDO COMANDO: APAGAR (OFF) | Raw: {hex_data}")
                        elif "640106000100000014" in hex_data:
                            print(f"❓ RECIBIDO: INTERROGACIÓN | Raw: {hex_data}")
                        else:
                            print(f"📥 Recibido (Otro): {hex_data}")
                    except ConnectionResetError:
                        print("❌ Conexión reseteada por el cliente.")
                        break

                # --- B. ENVIAR DATOS PERIODICOS (VOLTAJE) ---
                if time.time() - last_sent_time > 3:
                    voltaje = 220.0 + random.uniform(-5.0, 5.0)
                    if random.random() < 0.1: voltaje = 1000.0 # Pico simulado

                    pkt = build_measure_packet(seq, voltaje)
                    
                    try:
                        conn.sendall(pkt)
                        print(f"📤 Enviado: Voltaje {voltaje:.2f}V")
                        seq = (seq + 1) % 127
                        last_sent_time = time.time()
                    except (BrokenPipeError, ConnectionResetError):
                        print("❌ Error al enviar: Cliente desconectado.")
                        break

        except Exception as e:
            print(f"❌ Error general en loop: {e}")
        finally:
            if 'conn' in locals(): conn.close()
            print("🔄 Reiniciando espera de cliente...\n")

if __name__ == "__main__":
    start_server()
import socket
import struct
import time
import random

# --- CONFIGURA ESTO ---
IP_DESTINO = "192.168.131.5" # <--- ¡PON LA IP DE TU RTU (SERVER)!
PUERTO = 2404
# ----------------------

def build_command_packet(type_cmd):
    # Construye paquetes de COMANDO
    start = 0x68
    length = 14
    cf1, cf2, cf3, cf4 = 0, 0, 0, 0 # Secuencias dummy
    
    # Header común
    common_addr = 1
    org = 0
    
    # NOTA TÉCNICA:
    # La estructura correcta para pasar 13 argumentos (11 bytes, 1 short, 1 byte) es:
    # '<BBBBBBBBBBBHB' (11 Bs, 1 H, 1 B)
    
    if type_cmd == "CMD_ON":
        # C_SC_NA_1 (Single Command) - Tipo 45
        type_id = 45
        cot = 6     # Activation (Act)
        ioa = 500   # Dirección del Breaker
        val = 1     # ON
        # Corregido: Agregada una 'B' extra en el string de formato
        return struct.pack('<BBBBBBBBBBBHB', start, length, cf1, cf2, cf3, cf4, type_id, 1, cot, org, common_addr, ioa, val)

    elif type_cmd == "CMD_OFF":
        # C_SC_NA_1 (Single Command) - Tipo 45
        type_id = 45
        cot = 6     # Activation
        ioa = 500
        val = 0     # OFF
        # Corregido: Agregada una 'B' extra en el string de formato
        return struct.pack('<BBBBBBBBBBBHB', start, length, cf1, cf2, cf3, cf4, type_id, 1, cot, org, common_addr, ioa, val)

    elif type_cmd == "INTERROGATION":
        # C_IC_NA_1 (Interrogation) - Tipo 100
        type_id = 100
        cot = 6     # Activation
        ioa = 0
        qoi = 20    # Station Interrogation
        # Corregido: Agregada una 'B' extra en el string de formato
        return struct.pack('<BBBBBBBBBBBHB', start, length, cf1, cf2, cf3, cf4, type_id, 1, cot, org, common_addr, ioa, qoi)

def start_scada():
    print(f"💻 INICIANDO SCADA HACIA {IP_DESTINO}...")
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((IP_DESTINO, PUERTO))
        
        # Enviar STARTDT inicial
        client.sendall(bytes.fromhex("680407000000"))
        time.sleep(1)
        
        while True:
            # Seleccionar una acción aleatoria
            accion = random.choice(["CMD_ON", "CMD_OFF", "INTERROGATION", "WAIT"])
            
            if accion == "CMD_ON":
                print("⚡ ENVIANDO COMANDO: ENCENDER BREAKER (Type 45)")
                client.sendall(build_command_packet("CMD_ON"))
            
            elif accion == "CMD_OFF":
                print("⛔ ENVIANDO COMANDO: APAGAR BREAKER (Type 45)")
                client.sendall(build_command_packet("CMD_OFF"))
            
            elif accion == "INTERROGATION":
                print("❓ ENVIANDO: INTERROGACIÓN GENERAL (Type 100)")
                client.sendall(build_command_packet("INTERROGATION"))
            
            else:
                print("💤 Operador en espera...")
            
            time.sleep(5) # Acción cada 5 segundos

    except ConnectionRefusedError:
        print("❌ No hay conexión. ¿Corriste el rtu_sensor.py?")
    except KeyboardInterrupt:
        client.close()

if __name__ == "__main__":
    start_scada()
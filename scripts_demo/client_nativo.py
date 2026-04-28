import socket
import time
import struct

# --- CONFIGURACIÓN ---
IP_DESTINO = "192.168.1.20"  # <--- CAMBIA ESTO SI ZEEK NO VE NADA (Pon tu IP de LAN)
PUERTO = 2404
# ---------------------

def create_iec104_packet(seq_send, seq_recv):
    # Construcción manual de un paquete IEC-104 (ASDU)
    # Tipo 1 (M_SP_NA_1 - Single Point), 1 objeto, Espontáneo (03)
    
    # Cabecera APCI
    start = 0x68
    length = 14     # Longitud del resto
    
    # Control Fields (Secuencias) - Shift left 1 bit
    cf1 = (seq_send << 1) & 0xFF
    cf2 = (seq_send >> 7) & 0xFF
    cf3 = (seq_recv << 1) & 0xFF
    cf4 = (seq_recv >> 7) & 0xFF

    # ASDU Header
    type_id = 1     # Single Point
    sq_num = 1      # 1 Objeto
    cot = 3         # Spontaneous (Causa)
    org = 0         # Originador
    common_addr = 1 # Dirección común

    # Objeto de Información (IOA 100, Valor ON)
    ioa = 100
    value = 1       # ON (Status)

    # Empaquetamos todo en binario
    # B=1byte, H=2bytes (unsigned short)
    # Estructura: 68 Len CF1 CF2 CF3 CF4 Typ SQ COT Org CA_L CA_H IOA_L IOA_M IOA_H Val
    packet = struct.pack('<BBBBBBBBBBHHB', 
                         start, length, 
                         cf1, cf2, cf3, cf4, 
                         type_id, sq_num, cot, org, common_addr, 
                         ioa, value)
    return packet

def start_client():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    print(f"🔌 Conectando a {IP_DESTINO}:{PUERTO}...")
    try:
        client.connect((IP_DESTINO, PUERTO))
    except ConnectionRefusedError:
        print("❌ No se puede conectar. ¿Corriste el servidor primero?")
        return

    # 1. Enviar STARTDT ACT (Solicitud de inicio)
    print("📤 Enviando STARTDT...")
    client.sendall(bytes.fromhex("680407000000"))
    time.sleep(1)

    seq = 0
    try:
        while True:
            # Enviar paquete de DATOS (Esto es lo que Zeek quiere ver)
            packet = create_iec104_packet(seq, 0)
            client.sendall(packet)
            
            print(f"🔥 [Spam] Enviado paquete de datos IEC-104 (Seq: {seq})")
            
            seq += 1
            if seq > 30000: seq = 0 # Reiniciar contador si es muy alto
            
            time.sleep(2) # Enviar cada 2 segundos

    except KeyboardInterrupt:
        print("\n🛑 Deteniendo...")
        client.close()

if __name__ == "__main__":
    start_client()
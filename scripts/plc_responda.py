import socket

# Configuración
HOST = '0.0.0.0' # TU IP (La misma que usaste antes)
PORT = 2404

def iniciar_plc():
    print(f"🏭 PLC Listo en {HOST}:{PORT}")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, PORT))
    s.listen(1)
    
    conn, addr = s.accept()
    print(f"🔗 Conexión de {addr}")
    
    while True:
        data = conn.recv(1024)
        if not data: break
        
        # Si recibimos STARTDT (68 04 07...), respondemos STARTDT_ACK
        if len(data) > 0 and data[0] == 0x68:
            print(f"📥 Recibido comando Hex: {data.hex()}")
            
            # Respondemos con un paquete "STARTDT Confirm" genérico
            # Hex: 68 04 0B 00 00 00
            respuesta = b'\x68\x04\x0B\x00\x00\x00'
            conn.send(respuesta)
            print("📤 Respondido: STARTDT Confirm")
            
    conn.close()

if __name__ == "__main__":
    iniciar_plc()

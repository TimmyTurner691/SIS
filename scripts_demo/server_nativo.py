import socket
import struct
import time

def start_server():
    # Escuchar en TODAS las interfaces (importante para Docker)
    HOST = '0.0.0.0'  
    PORT = 2404

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind((HOST, PORT))
    except PermissionError:
        print("❌ ERROR: Necesitas permisos de root para el puerto 2404.")
        print("   Ejecuta: sudo python3 server_nativo.py")
        return

    server_socket.listen(1)
    print(f"📡 SERVIDOR IEC-104 ESCUCHANDO EN {HOST}:{PORT}")
    print("⏳ Esperando víctima (cliente)...")

    conn, addr = server_socket.accept()
    print(f"✅ CONECTADO CON: {addr}")

    try:
        while True:
            data = conn.recv(1024)
            if not data:
                break
            
            # Si recibimos STARTDT (68 04 07...), respondemos STARTDT CON (68 04 0B...)
            if len(data) >= 2 and data[0] == 0x68:
                print(f"📥 Recibido: {data.hex()}")
                
                # Respuesta automática genérica para mantener vivo el enlace
                # Si es un STARTDT ACT (07), respondemos STARTDT CON (0B)
                if data[2] == 0x07:
                    response = bytes.fromhex("68040B000000")
                    conn.sendall(response)
                    print("📤 Enviado: STARTDT CONFIRM")
                
                # Si es un I-Frame (Datos), enviamos un ACK S-Frame simple
                # (Esto es un hack, siempre confirmamos secuencia 0 para no complicar)
                elif data[2] & 0x01 == 0: 
                    # S-Frame ACK
                    response = bytes.fromhex("680401000200") 
                    conn.sendall(response)

    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()
        server_socket.close()

if __name__ == "__main__":
    start_server()
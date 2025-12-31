import json
import os

# Ruta absoluta para Docker
INVENTORY_FILE = "/app/ot_inventory.json"

DEFAULT_INVENTORY = [
    {"ip": "192.168.1.50", "name": "PLC_Siemens_S7", "criticality": "CRITICAL"},
    {"ip": "192.168.1.100", "name": "Workstation_Win10", "criticality": "MEDIUM"}
]

def load_inventory():
    """Carga la lista de dispositivos."""
    if not os.path.exists(INVENTORY_FILE):
        save_inventory(DEFAULT_INVENTORY)
        return DEFAULT_INVENTORY
    
    try:
        with open(INVENTORY_FILE, 'r') as f:
            return json.load(f) # Retorna la lista directa
    except Exception as e:
        print(f"⚠️ Error leyendo inventario: {e}")
        return []

def save_inventory(data_list):
    """Guarda la lista completa en JSON."""
    try:
        with open(INVENTORY_FILE, 'w') as f:
            json.dump(data_list, f, indent=4)
    except Exception as e:
        print(f"❌ Error guardando inventario: {e}")

def add_device(ip, name, criticality="LOW"):
    """Agrega un dispositivo nuevo."""
    current = load_inventory()
    
    # Verificar si ya existe la IP
    if any(d['ip'] == ip for d in current):
        return False
        
    current.append({
        "ip": ip,
        "name": name,
        "criticality": criticality
    })
    save_inventory(current)
    return True

if __name__ == "__main__":
    # Inicialización rápida si se ejecuta directo
    if not os.path.exists(INVENTORY_FILE):
        print("⚙️ Inicializando inventario por defecto...")
        save_inventory(DEFAULT_INVENTORY)
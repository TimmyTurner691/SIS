import json
import os

# Buscamos el archivo un nivel arriba de esta carpeta (en la raíz del proyecto)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INVENTORY_FILE = os.path.join(BASE_DIR, "ot_inventory.json")

# Lista por defecto
DEFAULT_INVENTORY = [
    "Siemens S7-1200",
    "Schneider Electric Modicon",
    "Rockwell Automation",
    "Moxa",
    "Hirschmann"
]

def load_inventory():
    """Carga la lista de dispositivos desde el JSON compartido."""
    if not os.path.exists(INVENTORY_FILE):
        save_inventory(DEFAULT_INVENTORY)
        return DEFAULT_INVENTORY
    
    try:
        with open(INVENTORY_FILE, 'r') as f:
            data = json.load(f)
            return data.get("devices", [])
    except Exception as e:
        print(f"⚠️ Error leyendo inventario: {e}")
        return []

def save_inventory(device_list):
    """Guarda la lista en el JSON."""
    try:
        with open(INVENTORY_FILE, 'w') as f:
            json.dump({"devices": list(set(device_list))}, f, indent=4)
    except Exception as e:
        print(f"❌ Error guardando inventario en {INVENTORY_FILE}: {e}")

def add_detected_device(device_name):
    """Agrega un dispositivo si no existe ya."""
    current_list = load_inventory()
    clean_name = device_name.strip()
    
    if not any(clean_name.lower() == d.lower() for d in current_list):
        print(f"🆕 ¡Nuevo equipo detectado!: {clean_name}")
        current_list.append(clean_name)
        save_inventory(current_list)
        return True
    return False
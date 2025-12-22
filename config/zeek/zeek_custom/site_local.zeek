# --- INICIALIZACIÓN BASE ---
@load base/init-default.zeek

# --- FRAMEWORKS ESENCIALES ---
@load base/frameworks/logging
@load base/frameworks/notice
@load base/frameworks/files
@load base/frameworks/intel

# --- PROTOCOLOS ESTÁNDAR (Faltaban estos) ---
# Sin esto, no tendrás conn.log (Vital para tu Dashboard)
@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/http
@load base/protocols/ssl

# --- INDUSTRIAL ---
@load packages/zeek-iec104

# --- CONFIGURACIÓN DE LOGS (JSON) ---
# Recomendación: Usar JSON facilita la vida a tu script de Python (main.py)
# Si tu main.py soporta JSON, descomenta la siguiente línea:
# @load policy/tuning/json-logs.zeek

# Ignorar checksums (Importante para Docker/Virtualización)
redef ignore_checksums = T;

event zeek_init()
{
    print "🚀 SIS-ZEEK: Configuración cargada. Protocolos IT + OT (IEC104) activos.";
}
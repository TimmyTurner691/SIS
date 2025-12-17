# zeek_custom/site_local.zeek
# Configuración mínima y moderna compatible con Zeek 5-8.x
# Carga del script local estándar
@load base/init-default.zeek

# Carga de frameworks necesarios para la detección de protocolos
@load base/frameworks/detection-protocols
# Carga del protocolo TCP para que pueda aplicar las firmas DPD
@load base/protocols/tcp

# Carga del plugin IEC 104 (instalado en /usr/local/zeek/share/zeek/site/packages/zeek-iec104/)
# Zeek automáticamente detecta '__load__.zeek' dentro del plugin
# Este script (__load__.zeek) a su vez carga main.zeek, que define el analizador y el log iec104.log
@load packages/zeek-iec104

print "Site local.zeek cargado correctamente. Plugin IEC104 habilitado y DPD activado.";

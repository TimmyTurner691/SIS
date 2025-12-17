# zeek_custom/site_local.zeek
# Configuración mínima y moderna compatible con Zeek 5-8.x

# Carga del script local estándar
@load base/init-default.zeek

# Frameworks usuales compatibles con Zeek moderno (opcional, según necesidad)
# @load base/frameworks/files
# @load base/frameworks/notice
# @load base/frameworks/software
# @load base/frameworks/sumstats
# @load base/frameworks/packet-filter

# Carga del plugin IEC 104 (instalado en /usr/local/zeek)
# Zeek automáticamente detecta '__load__.zeek' dentro del plugin
@load packages/zeek-iec104

print "Site local.zeek cargado correctamente. Plugin IEC104 habilitado.";

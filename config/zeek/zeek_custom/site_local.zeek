# zeek_custom/site_local.zeek
# Configuración base correcta para Zeek moderno

# Inicialización base
@load base/init-default.zeek

# Frameworks FUNDAMENTALES para logs
@load base/frameworks/logging
@load base/frameworks/notice
@load base/frameworks/files

# Cargar plugin IEC-104
@load packages/zeek-iec104

event zeek_init()
{
    print "Site local.zeek cargado correctamente. Plugin IEC104 habilitado.";
}

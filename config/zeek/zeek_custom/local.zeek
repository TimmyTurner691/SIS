##! CONFIGURACIÓN MAESTRA SIS-ZEEK

@load base/init-default
@load base/frameworks/logging
@load base/frameworks/notice
@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/http
@load base/protocols/ssl

# Carga del plugin (Si usas el Dockerfile de arriba con CERT-LV):
@load spicy-iec104

@load policy/tuning/json-logs
redef ignore_checksums = T;
redef Log::default_rotation_interval = 0sec;

event zeek_init()
{
    # Forzar escucha en puerto 2404 (CRÍTICO PARA QUE NO SE QUEDE SORDO)
    Analyzer::register_for_ports(Analyzer::ANALYZER_SPICY_IEC104, set(2404/tcp));
    print "🚀 SIS-ZEEK: Configuración Maestra cargada correctamente.";
}
# ./zeek_custom/local.zeek

# @load base/frameworks/notice
# @load base/frameworks/files
# @load base/frameworks/communication
# @load base/frameworks/input
# @load base/frameworks/output
# @load base/frameworks/packet-filter
# @load base/frameworks/reporter
# @load base/frameworks/tunnels
# @load base/frameworks/dpd
# @load base/frameworks/conn
# @load base/frameworks/file-analysis
# @load base/frameworks/netcontrol
# @load base/frameworks/supervisor
# @load base/frameworks/sumstats
# @load base/frameworks/packet-analyzer
# @load base/bif/plugins
# @load base/utils
# @load base/init-default.zeek
# @load base/policy/tuning/json-logs.zeek
# @load base/policy/tuning/defaults.zeek

# Cargar el plugin de IEC 104
@load /opt/zeek/lib/zeek/plugins/packages/zeek-iec104/scripts/main.zeek

# Asegúrate de que se estén cargando los scripts locales
redef Log::default_rotation_interval = 1day;

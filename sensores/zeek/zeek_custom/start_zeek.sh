#!/bin/bash
set -e

echo "🛡️ Iniciando Zeek (Modo Sensor)..."

BASE_DIR="/pcap"
LOGS_BASE="$BASE_DIR/logs"
LIVE_LOGDIR="$LOGS_BASE/live"
SITE_LOCAL_FILE="/opt/site_local.zeek"
HEALTH_DIR="/sensor-health"
HEALTH_FILE="$HEALTH_DIR/zeek.json"

INTERFACE="${INTERFACE:-eth0}"
SENSOR_MODE="${SIS_SENSOR_MODE:-demo}"
SENSOR_PROMISCUOUS="${SIS_SENSOR_PROMISCUOUS:-true}"

mkdir -p "$LOGS_BASE" "$LIVE_LOGDIR" "$HEALTH_DIR"

if [ -f "$SITE_LOCAL_FILE" ]; then
    sed -i '/redef Pcap::promisc/d' "$SITE_LOCAL_FILE"
    if [ "$SENSOR_PROMISCUOUS" = "false" ]; then
        echo 'redef Pcap::promisc = F;' >> "$SITE_LOCAL_FILE"
    fi
fi

write_health() {
  local status="$1"
  cat > "$HEALTH_FILE" <<JSON
{"sensor":"zeek","status":"$status","interface":"$INTERFACE","promiscuous":"$SENSOR_PROMISCUOUS","mode":"$SENSOR_MODE","timestamp":"$(date -Iseconds)"}
JSON
}

write_health "starting"
(
  while true; do
    write_health "running"
    sleep 10
  done
) &
HEALTH_PID=$!

trap 'write_health "stopped"; kill $HEALTH_PID 2>/dev/null || true' EXIT INT TERM

echo "📡 Escuchando en: $INTERFACE"
echo "📄 Cargando scripts: local + $SITE_LOCAL_FILE"

exec zeek -i "$INTERFACE" -C local "$SITE_LOCAL_FILE" Log::default_logdir="$LIVE_LOGDIR"

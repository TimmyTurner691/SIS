#!/bin/sh
set -eu

INTERFACE="${SIS_CAPTURE_INTERFACE:-lo}"
PROMISCUOUS="${SIS_SENSOR_PROMISCUOUS:-true}"
SENSOR_MODE="${SIS_SENSOR_MODE:-demo}"
HEALTH_DIR="/sensor-health"
HEALTH_FILE="$HEALTH_DIR/snort.json"

mkdir -p "$HEALTH_DIR"

PROMISC_FLAG=""
if [ "$PROMISCUOUS" = "false" ]; then
  PROMISC_FLAG="-p"
fi

write_health() {
  STATUS="$1"
  cat > "$HEALTH_FILE" <<JSON
{"sensor":"snort","status":"$STATUS","interface":"$INTERFACE","promiscuous":"$PROMISCUOUS","mode":"$SENSOR_MODE","timestamp":"$(date -Iseconds)"}
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

snort -q -i "$INTERFACE" -c /etc/snort/snort.conf -l /var/log/snort -A fast -k none $PROMISC_FLAG

#!/bin/sh
set -eu

INTERFACE="${SIS_CAPTURE_INTERFACE:-lo}"
PROMISCUOUS="${SIS_SENSOR_PROMISCUOUS:-true}"
SENSOR_MODE="${SIS_SENSOR_MODE:-demo}"
HEALTH_DIR="/sensor-health"
HEALTH_FILE="$HEALTH_DIR/snort.json"
PID_FILE="$HEALTH_DIR/snort.pid"
RULES_FILE="${SIS_SIGNATURE_ACTIVE_RULES_PATH:-/etc/snort/rules/active.rules}"
RELOAD_FILE="${SIS_SIGNATURE_RELOAD_PATH:-/etc/snort/reload_request.json}"
SNORT_CONF="/etc/snort/snort.conf"
SNORT_PID=""
LAST_RULES_MTIME=""
LAST_RELOAD_MTIME=""

mkdir -p "$HEALTH_DIR" /var/log/snort

PROMISC_FLAG=""
if [ "$PROMISCUOUS" = "false" ]; then
  PROMISC_FLAG="-p"
fi

write_health() {
  STATUS="$1"
  MESSAGE="${2:-}"
  cat > "$HEALTH_FILE" <<JSON
{"sensor":"snort","status":"$STATUS","interface":"$INTERFACE","promiscuous":"$PROMISCUOUS","mode":"$SENSOR_MODE","active_rules":"$RULES_FILE","message":"$MESSAGE","timestamp":"$(date -Iseconds)"}
JSON
}

mtime_of() {
  if [ -f "$1" ]; then
    stat -c %Y "$1" 2>/dev/null || stat -f %m "$1"
  else
    echo "0"
  fi
}

validate_rules() {
  if [ ! -s "$RULES_FILE" ]; then
    write_health "invalid_rules" "active.rules no existe o está vacío"
    return 1
  fi
  snort -T -q -c "$SNORT_CONF" -i "$INTERFACE" -k none $PROMISC_FLAG >/tmp/snort-test.log 2>&1
}

start_snort() {
  if validate_rules; then
    snort -q -i "$INTERFACE" -c "$SNORT_CONF" -l /var/log/snort -A fast -k none $PROMISC_FLAG &
    SNORT_PID=$!
    echo "$SNORT_PID" > "$PID_FILE"
    write_health "running" "sensor iniciado con reglas validadas"
  else
    write_health "invalid_rules" "validación Snort -T falló; ver /tmp/snort-test.log"
    return 1
  fi
}

stop_snort() {
  if [ -n "${SNORT_PID:-}" ] && kill -0 "$SNORT_PID" 2>/dev/null; then
    kill "$SNORT_PID" 2>/dev/null || true
    wait "$SNORT_PID" 2>/dev/null || true
  fi
  SNORT_PID=""
  rm -f "$PID_FILE"
}

reload_snort_safely() {
  if validate_rules; then
    write_health "reloading" "reglas validadas; reiniciando sensor"
    stop_snort
    start_snort
  else
    write_health "invalid_rules" "recarga rechazada; se conservan reglas anteriores en proceso"
    return 1
  fi
}

cleanup() {
  write_health "stopped" "sensor detenido"
  stop_snort
}

trap cleanup EXIT INT TERM
trap reload_snort_safely HUP

write_health "starting" "inicializando sensor"
start_snort || true
LAST_RULES_MTIME="$(mtime_of "$RULES_FILE")"
LAST_RELOAD_MTIME="$(mtime_of "$RELOAD_FILE")"

while true; do
  if [ -n "${SNORT_PID:-}" ] && ! kill -0 "$SNORT_PID" 2>/dev/null; then
    write_health "crashed" "proceso Snort no está vivo; reintentando"
    start_snort || true
  fi

  CURRENT_RULES_MTIME="$(mtime_of "$RULES_FILE")"
  CURRENT_RELOAD_MTIME="$(mtime_of "$RELOAD_FILE")"
  if [ "$CURRENT_RULES_MTIME" != "$LAST_RULES_MTIME" ] || [ "$CURRENT_RELOAD_MTIME" != "$LAST_RELOAD_MTIME" ]; then
    reload_snort_safely || true
    LAST_RULES_MTIME="$CURRENT_RULES_MTIME"
    LAST_RELOAD_MTIME="$CURRENT_RELOAD_MTIME"
  else
    write_health "running" "sensor activo"
  fi

  sleep 10
done

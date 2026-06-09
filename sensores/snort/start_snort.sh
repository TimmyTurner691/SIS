#!/bin/sh
set -eu

INTERFACE="${SIS_CAPTURE_INTERFACE:-lo}"
PROMISCUOUS="${SIS_SENSOR_PROMISCUOUS:-true}"
SENSOR_MODE="${SIS_SENSOR_MODE:-demo}"
HEALTH_DIR="/sensor-health"
HEALTH_FILE="$HEALTH_DIR/snort.json"
SIGNATURES_DIR="${SIS_SIGNATURES_DIR:-/signatures}"
CONTROL_DIR="$SIGNATURES_DIR/control"
CANDIDATE_RULES="$CONTROL_DIR/effective.rules"
ACTIVE_RULES="/etc/snort/rules/active.rules"
DEFAULT_RULES="/etc/snort/rules/default.rules"
RELOAD_REQUEST="$CONTROL_DIR/reload.request"
RELOAD_STATUS="$CONTROL_DIR/reload.status.json"
LAST_REQUEST=""
SNORT_PID=""

mkdir -p "$HEALTH_DIR" "$CONTROL_DIR"

PROMISC_FLAG=""
if [ "$PROMISCUOUS" = "false" ]; then
  PROMISC_FLAG="-p"
fi

write_health() {
  STATUS="$1"
  cat > "$HEALTH_FILE.tmp" <<JSON
{"sensor":"snort","status":"$STATUS","interface":"$INTERFACE","promiscuous":"$PROMISCUOUS","mode":"$SENSOR_MODE","timestamp":"$(date -Iseconds)"}
JSON
  mv "$HEALTH_FILE.tmp" "$HEALTH_FILE"
}

write_reload_status() {
  STATUS="$1"
  MESSAGE="$2"
  cat > "$RELOAD_STATUS.tmp" <<JSON
{"status":"$STATUS","message":"$MESSAGE","timestamp":"$(date -Iseconds)"}
JSON
  mv "$RELOAD_STATUS.tmp" "$RELOAD_STATUS"
}

start_snort() {
  snort -q -i "$INTERFACE" -c /etc/snort/snort.conf -l /var/log/snort -A fast -k none $PROMISC_FLAG &
  SNORT_PID=$!
}

validate_and_reload() {
  [ -s "$CANDIDATE_RULES" ] || {
    write_reload_status "rejected" "El set efectivo está vacío o no existe"
    return
  }

  VALIDATION_RULES="/etc/snort/rules/.candidate.rules"
  VALIDATION_CONF="/etc/snort/snort.validation.conf"
  cp "$CANDIDATE_RULES" "$VALIDATION_RULES"
  sed 's@include rules/active.rules@include rules/.candidate.rules@' /etc/snort/snort.conf > "$VALIDATION_CONF"

  if snort -T -q -c "$VALIDATION_CONF" -i "$INTERFACE" >/tmp/snort-validation.log 2>&1; then
    cp "$CANDIDATE_RULES" "$ACTIVE_RULES.tmp"
    mv "$ACTIVE_RULES.tmp" "$ACTIVE_RULES"
    kill "$SNORT_PID" 2>/dev/null || true
    wait "$SNORT_PID" 2>/dev/null || true
    start_snort
    RULE_COUNT=$(grep -Ec '^[[:space:]]*(alert|log|pass|drop|reject|sdrop)[[:space:]]' "$ACTIVE_RULES" || true)
    write_reload_status "applied" "$RULE_COUNT reglas validadas y activadas"
  else
    ERROR=$(tail -n 1 /tmp/snort-validation.log | sed 's/"/\\"/g')
    write_reload_status "rejected" "Validación Snort fallida: $ERROR"
  fi
  rm -f "$VALIDATION_RULES" "$VALIDATION_CONF"
}

cleanup() {
  write_health "stopped"
  [ -n "$SNORT_PID" ] && kill "$SNORT_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# Prepara un set de arranque conocido antes de validar cualquier candidato pendiente.
if [ ! -f "$ACTIVE_RULES" ]; then
  cp "$DEFAULT_RULES" "$ACTIVE_RULES"
fi

# Valida el set inicial antes de arrancar; si falla conserva active.rules.
if [ -s "$CANDIDATE_RULES" ]; then
  cp "$CANDIDATE_RULES" /etc/snort/rules/.candidate.rules
  sed 's@include rules/active.rules@include rules/.candidate.rules@' /etc/snort/snort.conf > /etc/snort/snort.validation.conf
  if snort -T -q -c /etc/snort/snort.validation.conf -i "$INTERFACE" >/tmp/snort-validation.log 2>&1; then
    cp "$CANDIDATE_RULES" "$ACTIVE_RULES.tmp"
    mv "$ACTIVE_RULES.tmp" "$ACTIVE_RULES"
  fi
  rm -f /etc/snort/rules/.candidate.rules /etc/snort/snort.validation.conf
fi

write_health "starting"
start_snort

while kill -0 "$SNORT_PID" 2>/dev/null; do
  write_health "running"
  if [ -f "$RELOAD_REQUEST" ]; then
    CURRENT_REQUEST=$(cksum "$RELOAD_REQUEST" | awk '{print $1 ":" $2}')
    if [ "$CURRENT_REQUEST" != "$LAST_REQUEST" ]; then
      LAST_REQUEST="$CURRENT_REQUEST"
      validate_and_reload
    fi
  fi
  sleep 5
done

wait "$SNORT_PID"

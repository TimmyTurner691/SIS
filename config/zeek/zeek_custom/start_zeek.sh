#!/bin/bash
set -e

echo "Iniciando script de Zeek..."

BASE_DIR="/pcap"
LOGS_BASE="$BASE_DIR/logs"
SITE_LOCAL_FILE="/opt/site_local.zeek"
INTERFACE="${INTERFACE:-eth0}"

# Crear carpeta base de logs si no existe
mkdir -p "$LOGS_BASE"

# Validaciones
if [ ! -f "$SITE_LOCAL_FILE" ]; then
  echo "Error: No se encontró $SITE_LOCAL_FILE"
  exit 1
fi

# -------------------------------
# MODO PCAP
# -------------------------------
if [ -n "$1" ]; then
  PCAP_FILE="$1"
  PCAP_PATH="$BASE_DIR/$PCAP_FILE"

  if [ ! -f "$PCAP_PATH" ]; then
    echo "Error: No se encontró el PCAP $PCAP_PATH"
    exit 1
  fi

  # Nombre limpio del PCAP (sin extensión)
  PCAP_NAME="$(basename "$PCAP_FILE" .pcap)"

  # Carpeta final de logs
  FINAL_LOGDIR="$LOGS_BASE/$PCAP_NAME"
  mkdir -p "$FINAL_LOGDIR"

  echo "Analizando PCAP: $PCAP_FILE"
  echo "Logs se guardarán en: $FINAL_LOGDIR"

  exec zeek -r "$PCAP_PATH" \
    -C "$SITE_LOCAL_FILE" \
    Log::default_logdir="$FINAL_LOGDIR"
fi

# -------------------------------
# MODO LIVE
# -------------------------------
LIVE_LOGDIR="$LOGS_BASE/live"
mkdir -p "$LIVE_LOGDIR"

echo "Iniciando captura en interfaz $INTERFACE"
echo "Logs se guardarán en: $LIVE_LOGDIR"

exec zeek -i "$INTERFACE" \
  -C "$SITE_LOCAL_FILE" \
  Log::default_logdir="$LIVE_LOGDIR"

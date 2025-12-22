#!/bin/bash
set -e

echo "🛡️ Iniciando lanzador de Zeek para SIS..."

BASE_DIR="/pcap"
# Ajusta esto si tu volumen de logs en docker-compose apunta a otro lado
LOGS_BASE="$BASE_DIR/logs" 
SITE_LOCAL_FILE="/opt/site_local.zeek"
INTERFACE="${INTERFACE:-eth0}"

# Crear carpeta base si no existe
mkdir -p "$LOGS_BASE"

# Validaciones
if [ ! -f "$SITE_LOCAL_FILE" ]; then
  echo "❌ Error Crítico: No se encontró $SITE_LOCAL_FILE"
  exit 1
fi

# -------------------------------
# MODO 1: ANÁLISIS DE ARCHIVO PCAP
# -------------------------------
if [ -n "$1" ]; then
  PCAP_FILE="$1"
  PCAP_PATH="$BASE_DIR/$PCAP_FILE"

  if [ ! -f "$PCAP_PATH" ]; then
    echo "❌ Error: No se encontró el archivo $PCAP_PATH"
    exit 1
  fi

  # Nombre limpio para la carpeta
  PCAP_NAME="$(basename "$PCAP_FILE" .pcap)"
  FINAL_LOGDIR="$LOGS_BASE/$PCAP_NAME"
  
  # Limpiamos análisis previo del mismo pcap si existe
  rm -rf "$FINAL_LOGDIR"
  mkdir -p "$FINAL_LOGDIR"

  echo "📂 Analizando PCAP: $PCAP_FILE"
  echo "📂 Destino de Logs: $FINAL_LOGDIR"

  exec zeek -r "$PCAP_PATH" \
    -C "$SITE_LOCAL_FILE" \
    Log::default_logdir="$FINAL_LOGDIR"
fi

# -------------------------------
# MODO 2: MONITOREO EN VIVO (LIVE)
# -------------------------------
# Usamos una carpeta específica para live
LIVE_LOGDIR="$LOGS_BASE/live"
mkdir -p "$LIVE_LOGDIR"

echo "📡 Iniciando captura EN VIVO en interfaz: $INTERFACE"
echo "📂 Los logs se generarán en: $LIVE_LOGDIR"

# Importante: Zeek en modo cluster/live gestiona sus propios logs, 
# pero aquí lo corremos en modo standalone.
exec zeek -i "$INTERFACE" \
  -C "$SITE_LOCAL_FILE" \
  Log::default_logdir="$LIVE_LOGDIR"
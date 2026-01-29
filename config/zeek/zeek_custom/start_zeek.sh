#!/bin/bash
set -e

echo "🛡️ Iniciando Zeek (Estructura Limpia)..."

# Variables
BASE_DIR="/pcap"
LOGS_BASE="$BASE_DIR/logs"
LIVE_LOGDIR="$LOGS_BASE/live"
# OJO: Aquí apuntamos al destino que definimos en el Dockerfile
SITE_LOCAL_FILE="/opt/site_local.zeek" 
INTERFACE="${INTERFACE:-eth0}"

# Carpetas
mkdir -p "$LOGS_BASE" "$LIVE_LOGDIR"

echo "📡 Escuchando en: $INTERFACE"
echo "📄 Usando config: $SITE_LOCAL_FILE"

# Ejecución
exec zeek -i "$INTERFACE" -C "$SITE_LOCAL_FILE" Log::default_logdir="$LIVE_LOGDIR"
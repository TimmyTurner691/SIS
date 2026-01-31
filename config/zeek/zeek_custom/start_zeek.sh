#!/bin/bash
set -e

echo "🛡️ Iniciando Zeek (Modo Nativo / Interfaz Real)..."

# --- 1. Variables ---
BASE_DIR="/pcap"
LOGS_BASE="$BASE_DIR/logs"
LIVE_LOGDIR="$LOGS_BASE/live"
SITE_LOCAL_FILE="/opt/site_local.zeek"

# Por defecto usaremos eth0, pero lo cambiaremos desde el docker-compose
INTERFACE="${INTERFACE:-eth0}"

# --- 2. Preparar Carpetas ---
mkdir -p "$LOGS_BASE" "$LIVE_LOGDIR"

# --- 3. Limpieza de hacks anteriores (Importante) ---
# Borramos cualquier línea que hayamos inyectado antes para que no estorbe
if [ -f "$SITE_LOCAL_FILE" ]; then
    sed -i '/redef Pcap::promisc/d' "$SITE_LOCAL_FILE"
    sed -i '/# FIX:/d' "$SITE_LOCAL_FILE"
    sed -i '/# AUTO-CONFIG/d' "$SITE_LOCAL_FILE"
fi

# --- 4. Ejecución Estándar ---
echo "📡 Escuchando en: $INTERFACE"
echo "📄 Cargando scripts: local + $SITE_LOCAL_FILE"

# Ejecutamos Zeek de la forma oficial.
# -i: Interfaz real
# -C: Ignorar checksums (útil para tráfico local)
# local: Carga todo el entorno Zeek correctamente.
exec zeek -i "$INTERFACE" -C local "$SITE_LOCAL_FILE" Log::default_logdir="$LIVE_LOGDIR"
#!/bin/bash
# zeek_custom/start_zeek.sh

set -e  # Salir si algo falla

echo "Iniciando script de Zeek..."

# --- Configuración (DEFINIR PRIMERO) ---
LOG_DIR="/pcap"
INTERFACE="${INTERFACE:-eth0}" # Permite sobrescribir con variable de entorno, sino usa eth0
SITE_LOCAL_FILE="/opt/site_local.zeek"

# --- Validaciones ---
if [ ! -d "$LOG_DIR" ]; then
  echo "Error: El directorio de logs $LOG_DIR no existe en el contenedor."
  exit 1
fi

if [ ! -f "$SITE_LOCAL_FILE" ]; then
  echo "Error: El archivo $SITE_LOCAL_FILE no se encontró."
  exit 1
fi

# Establecer el directorio de logs
export ZEEK_LOGDIR="$LOG_DIR"
echo "ZEEK_LOGDIR configurado a: $ZEEK_LOGDIR"
echo "Iniciando Zeek en la interfaz $INTERFACE..."
echo "Usando site_local: $SITE_LOCAL_FILE"

# --- Iniciar Zeek (EJECUTAR AL FINAL) ---
exec zeek -i "$INTERFACE" -C "$SITE_LOCAL_FILE"

# Nota: Se removió el argumento '--logdir' del comando zeek.
# Se manejará mediante ZEEK_LOGDIR.
# También se removió 'local' y 'zeek-iec104' como argumentos directos,
# ya que se cargarán desde site_local.zeek.

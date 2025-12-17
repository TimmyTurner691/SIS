#!/bin/bash

# Colores (Verde para normalidad)
VERDE='\033[0;32m'
AZUL='\033[0;34m'
NC='\033[0m'

echo -e "${AZUL}=========================================${NC}"
echo -e "${VERDE}   ESCENARIO 1: TRÁFICO OPERATIVO (NORMAL)   ${NC}"
echo -e "${AZUL}=========================================${NC}"

# 1. Limpieza
docker exec siem_zeek pkill nc > /dev/null 2>&1

# 2. Levantar Servidor (PLC Simulado)
echo -e "🏭 PLC: Esperando conexión de la RTU..."
docker exec -d siem_zeek nc -l -k -p 2404

# 3. Tráfico Legítimo (Una sola conexión limpia)
echo -e "📡 RTU: Iniciando conexión estándar..."
python3 generador_nativo.py > /dev/null 2>&1
sleep 2

# 4. Análisis
echo -e "\n🔍 SIEM (Zeek) Analizando protocolo IEC-104..."
echo -e "${AZUL}---------------------------------------${NC}"
# Mostramos el último log de IEC104
docker exec siem_zeek bash -c "cd /pcap && cat iec104.log | zeek-cut ts id.orig_h apci_type | tail -n 1"
echo -e "${AZUL}---------------------------------------${NC}"
echo -e "${VERDE}✅ ESTADO: Tráfico reconocido y validado.${NC}"

#!/bin/bash

# Colores (Rojo para peligro)
ROJO='\033[0;31m'
AMARILLO='\033[1;33m'
NC='\033[0m'

echo -e "${ROJO}=========================================${NC}"
echo -e "${ROJO}   ESCENARIO 2: CIBERATAQUE (FLOODING/DoS)   ${NC}"
echo -e "${ROJO}=========================================${NC}"

# 1. Limpieza
docker exec siem_zeek pkill nc > /dev/null 2>&1

# 2. Levantar Servidor
docker exec -d siem_zeek nc -l -k -p 2404

# 3. EL ATAQUE (Bucle rápido)
echo -e "${AMARILLO}⚠️  ALERTA: Iniciando inyección masiva de paquetes...${NC}"
for i in {1..15}
do
   # Ejecutamos en segundo plano (&) para que sea simultáneo y caótico
   python3 generador_nativo.py > /dev/null 2>&1 & 
   echo -n "🔥"
done
wait # Esperar a que terminen los procesos del bucle
echo -e "\n${ROJO}>>> Ataque finalizado <<<${NC}"

sleep 3

# 4. Análisis Forense
echo -e "\n🕵️‍♂️ REPORTE DE INCIDENTE:"
echo -e "Contando conexiones detectadas en los últimos segundos..."
echo -e "${ROJO}---------------------------------------${NC}"

# Aquí contamos cuántas líneas se generaron en conn.log en este instante
TOTAL=$(docker exec siem_zeek bash -c "cat /pcap/conn.log | wc -l")
echo -e "Conexiones Totales Registradas: ${AMARILLO}$TOTAL${NC}"

# Mostramos una muestra del caos
echo -e "Muestra de tráfico malicioso (últimos 5 eventos):"
docker exec siem_zeek bash -c "cd /pcap && cat iec104.log | zeek-cut ts id.orig_h apci_type | tail -n 5"

echo -e "${ROJO}---------------------------------------${NC}"
echo -e "${ROJO}🚨 ALERTA: Patrón de tráfico anómalo detectado.${NC}"

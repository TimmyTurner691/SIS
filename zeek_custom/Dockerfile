# zeek_custom/Dockerfile
# Usa la imagen recomendada por el autor del plugin
FROM zeek/zeek:8.0.0

# 1. Instalar dependencias para compilar plugins Spicy
RUN apt-get update && apt-get install -y \
    cmake \
    g++ \
    libpcap-dev \
    python3 \
    python3-pip \
    wget \
    nano \
    git \
    && rm -rf /var/lib/apt/lists/*

# 2. Crear directorio para logs internos del contenedor
RUN mkdir -p /pcap

# 3. Copiar el código fuente del plugin IEC 104
COPY zeek-iec104 /tmp/zeek-iec104

# 4. Compilar e instalar el plugin desde el directorio build
WORKDIR /tmp/zeek-iec104
RUN mkdir build && cd build && \
    cmake .. && \
    make && \
    make install

# 5. COPIAR manualmente los scripts .zeek a la ubicación donde Zeek los espera
# Creamos la estructura de directorios destino
RUN mkdir -p /usr/local/zeek/share/zeek/site/packages/zeek-iec104/
# Copiamos los archivos .zeek desde el directorio original del plugin al destino
COPY zeek-iec104/scripts/ /usr/local/zeek/share/zeek/site/packages/zeek-iec104/

# 6. Limpiar directorio temporal del plugin (después de copiar los scripts)
RUN rm -rf /tmp/zeek-iec104

# 7. Verificar la instalación Y explorar la estructura de archivos
# Mostramos explícitamente la salida de zeek -NN y el resultado del find.
RUN echo "--- Verificando Zeek -NN (debería mostrar el plugin ahora) ---" && \
    zeek -NN | grep -i iec104 && \
    echo "--- Buscando archivos del plugin instalado ---" && \
    find /usr/local -name "*iec104*" -type f -o -name "*iec104*" -type d 2>/dev/null

# 8. Copiar script de inicio
COPY start_zeek.sh /opt/start_zeek.sh
RUN chmod +x /opt/start_zeek.sh

# 9. Copiar site_local
COPY site_local.zeek /opt/site_local.zeek

# 10. Comando de inicio
CMD ["/opt/start_zeek.sh"]

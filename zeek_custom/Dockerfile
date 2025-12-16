# ~/proyectos/SIS/zeek_custom/Dockerfile
# Usa la imagen recomendada por el autor del plugin
FROM zeek/zeek:8.0.0

# 1. Instalar dependencias para compilar plugins Spicy
RUN apt-get update && apt-get install -y \
    cmake \
    g++ \
    libpcap-dev \
    python3 \
    python3-pip \
    git \
    wget \
    nano \
    && rm -rf /var/lib/apt/lists/*

# 2. Crear directorio para logs internos del contenedor
RUN mkdir -p /pcap

# 3. Clonar el código fuente del plugin IEC 104 DENTRO del contenedor
RUN git clone https://github.com/georgemakrakis/zeek-iec104.git /tmp/zeek-iec104

# 4. Compilar e instalar el plugin desde el directorio build
WORKDIR /tmp/zeek-iec104
# Creamos el directorio build y lo usamos como directorio de trabajo para la compilación
RUN mkdir -p build
WORKDIR /tmp/zeek-iec104/build
# Ejecutamos cmake apuntando al directorio padre (donde está CMakeLists.txt)
RUN cmake .. && \
    make && \
    make install
# Volvemos al directorio original para los siguientes pasos
WORKDIR /tmp/zeek-iec104

# 5. COPIAR manualmente los scripts .zeek a la ubicación donde Zeek los espera
# Creamos la estructura de directorios destino
RUN mkdir -p /usr/local/zeek/share/zeek/site/packages/zeek-iec104/
# Copiamos los archivos .zeek desde la ubicación donde están en el contenedor (/tmp/zeek-iec104/scripts/) al destino
RUN cp -r scripts/* /usr/local/zeek/share/zeek/site/packages/zeek-iec104/

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

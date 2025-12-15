FROM ubuntu:22.04

# Evitar preguntas molestas al instalar
ENV DEBIAN_FRONTEND=noninteractive

# 1. Instalar Zeek y herramientas de red básicas
RUN apt-get update && \
    apt-get install -y zeek iproute2 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# 2. Agregar los binarios de Zeek al sistema (Ubuntu los guarda en /opt)
ENV PATH="/opt/zeek/bin:${PATH}"

# 3. Crear la carpeta donde se guardarán los logs
RUN mkdir -p /pcap

# 4. COMANDO DE ARRANQUE "A PRUEBA DE FALLOS"
# Ejecuta zeek escuchando en cualquier interfaz (-i any)
# Ignora checksums (-C)
# Guarda en /pcap (-l /pcap)
# Carga los scripts locales (local)
CMD ["zeek", "-i", "any", "-C", "-l", "/pcap", "local"]

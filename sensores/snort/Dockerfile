FROM ubuntu:22.04

# Evitar que la instalación nos haga preguntas de configuración
ENV DEBIAN_FRONTEND=noninteractive

# Actualizar e instalar Snort + herramientas de red
RUN apt-get update && \
    apt-get install -y snort iproute2 net-tools && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Crear estructura de carpetas básica para que no falle
RUN mkdir -p /var/log/snort && \
    touch /etc/snort/rules/local.rules && \
    touch /etc/snort/snort.conf

# El comando por defecto (se sobreescribe en el compose, pero por seguridad)

COPY start_snort.sh /opt/start_snort.sh
RUN chmod +x /opt/start_snort.sh

CMD ["/opt/start_snort.sh"]

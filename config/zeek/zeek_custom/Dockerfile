FROM zeek/zeek:latest

USER root
RUN apt-get update && apt-get install -y cmake make gcc g++ git bison flex libssl-dev python3-pip && rm -rf /var/lib/apt/lists/*

# Instalamos el plugin SPICY (CERT-LV) que acordamos probar
RUN zkg autoconfig --force && zkg install --force --skiptests https://github.com/cert-lv/spicy-iec104

COPY start_zeek.sh /opt/start_zeek.sh
RUN chmod +x /opt/start_zeek.sh

# --- AQUÍ ESTÁ EL CAMBIO IMPORTANTE ---
# Copiamos TU 'local.zeek' y lo renombramos a 'site_local.zeek' dentro del contenedor
# para mantener la compatibilidad con el script de arranque.
COPY local.zeek /opt/site_local.zeek

ENTRYPOINT ["/opt/start_zeek.sh"]

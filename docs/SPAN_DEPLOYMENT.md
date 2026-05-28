# SIS — Despliegue con interfaz física y puerto SPAN

## Objetivo
Conectar SIS a tráfico real usando una interfaz dedicada de captura conectada a un puerto espejo (SPAN) del switch.

---

## 1) Topología recomendada

- **NIC de gestión (Management):** acceso SSH, Docker, administración.
- **NIC de captura (SPAN):** recibe copia de tráfico desde el switch.

Ejemplo:

- `eth0` = gestión (IP de servidor).
- `eth1` = captura (sin IP o IP mínima, no usada para administración).

---

## 2) Configuración en SIS (.env)

```env
SIS_MANAGEMENT_INTERFACE=eth0
SIS_CAPTURE_INTERFACE=eth1
SIS_SENSOR_MODE=span
SIS_SENSOR_PROMISCUOUS=true
SIS_SENSOR_HEALTH_PATH=./logs/sensor_health
```

Con esto, Zeek/Snort escucharán en la interfaz física (`eth1`) en vez de `lo`.

---

## 3) Requisitos de interfaz de captura

En host Linux:

```bash
ip link show eth1
sudo ip link set eth1 up
sudo ip link set eth1 promisc on
```

> Nota: SIS ya corre sensores con privilegios y `NET_ADMIN/NET_RAW`, pero esta verificación ayuda en troubleshooting.

---

## 4) Ejemplo SPAN en switch (referencial)

### Cisco-like (referencial)

```text
monitor session 1 source interface Gi1/0/10 both
monitor session 1 destination interface Gi1/0/24
```

- `Gi1/0/10`: puerto origen a espejar.
- `Gi1/0/24`: puerto conectado a `eth1` del servidor SIS.

### MikroTik (conceptual)

- Definir puerto origen.
- Definir puerto destino espejo.
- Activar mirror de Rx/Tx según necesidad.

La sintaxis exacta depende del modelo/firmware del switch.

---

## 5) Levantar SIS en modo SPAN

```bash
cp .env.sis .env
# editar .env (interfaz captura = eth1, modo=span)
docker compose up -d --build
```

Opcional con proxy:

```bash
docker compose --profile proxy up -d --build
```

---

## 6) Verificación operativa

### Ver heartbeat de sensores

```bash
cat logs/sensor_health/zeek.json
cat logs/sensor_health/snort.json
```

Estados esperados: `running` con `interface=eth1`.

### Ver logs de sensores

```bash
docker compose logs -f zeek
docker compose logs -f snort
```

### GUI: estado sensores

En el dashboard, revisar la sección lateral **Estado Sensores**:

- 🟢 Escuchando
- 🟡 Degradado
- 🔴 Caído / Error

---

## 7) Buenas prácticas

- No mezclar captura y gestión en la misma NIC en producción.
- Restringir acceso a puertos de Elasticsearch/Redis en firewall.
- Controlar capacidad de disco para logs y volúmenes persistentes.
- Validar reloj del servidor (NTP) para correlación temporal correcta.


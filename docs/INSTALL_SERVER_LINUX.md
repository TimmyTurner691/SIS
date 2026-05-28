# SIS — Guía de instalación en servidor Linux (LAN)

Esta guía cubre dos modos de despliegue:

1. **Modo simple (directo):** acceso a GUI por `http://IP_SERVIDOR:8501`.
2. **Modo proxy (opcional):** acceso por Nginx en `http://IP_SERVIDOR:8080`.

---

## 1) Requisitos del servidor

- Linux (Ubuntu 22.04+ recomendado).
- Docker Engine + Docker Compose plugin.
- Usuario con permisos para ejecutar Docker.
- Acceso de red LAN entre cliente y servidor.

### Instalar Docker (Ubuntu)

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

### Habilitar Docker al reiniciar

```bash
sudo systemctl enable docker
sudo systemctl start docker
```

---

## 2) Clonar y configurar SIS

```bash
git clone https://github.com/TimmyTurner691/SIS.git
cd SIS
cp .env.sis .env
```

Edita `.env` y ajusta como mínimo:

- `SIS_CAPTURE_INTERFACE` (ej. `eth0` o interfaz de laboratorio).
- `SIS_DASHBOARD_PORT` (puerto externo GUI directa).
- `SIS_DASHBOARD_LISTEN_ADDRESS=0.0.0.0` (acceso LAN).
- `SIS_ELASTIC_PORT`, `SIS_REDIS_PORT` si necesitas custom.

---

## 3) Puertos requeridos (firewall)

- `8501/tcp` → GUI directa (modo simple).
- `8080/tcp` → GUI vía Nginx (modo proxy).
- `9200/tcp` → Elasticsearch (solo si necesitas acceso externo).
- `6379/tcp` → Redis (recomendado restringir a red interna).

Ejemplo con UFW:

```bash
sudo ufw allow 8501/tcp
sudo ufw allow 8080/tcp
sudo ufw allow 9200/tcp
sudo ufw status
```

---

## 4) Levantar servicios

### Modo simple (sin proxy)

```bash
docker compose up -d --build
```

Acceso GUI desde otro equipo LAN:

```text
http://IP_SERVIDOR:8501
```

### Modo proxy (Nginx opcional)

```bash
docker compose --profile proxy up -d --build
```

Acceso GUI desde otro equipo LAN:

```text
http://IP_SERVIDOR:8080
```

---

## 5) Persistencia y reinicio de servidor

El despliegue usa:

- `restart: unless-stopped` en servicios críticos.
- Volumen `elastic_data` para histórico de Elasticsearch.
- Volumen `redis_data` (AOF activado) para cola Redis.
- Volumen `filebeat_data` para estado/registro de Filebeat.

Validación tras reinicio del servidor:

```bash
sudo reboot
# luego reconectar
cd SIS
docker compose ps
docker volume ls | grep -E 'elastic_data|redis_data|filebeat_data'
```

---

## 6) Volúmenes y permisos

Rutas montadas desde host (por defecto):

- `./logs/logs_zeek`
- `./logs/logs_snort`
- `./core/cerebro`
- `./dashboard/streamlit`

Si ejecutas con usuario no-root en host, asegura permisos de lectura/escritura en `logs/`.

---

## 7) Operación básica y diagnóstico

```bash
docker compose ps
docker compose logs -f dashboard
docker compose logs -f cerebro
docker compose logs -f filebeat
```

Parar stack:

```bash
docker compose down
```

Parar stack + borrar volúmenes persistentes (destructivo):

```bash
docker compose down -v
```



## 8) Captura real por SPAN

Para despliegue con interfaz física dedicada y puerto espejo, revisa: `docs/SPAN_DEPLOYMENT.md`.



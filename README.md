[README.md](https://github.com/user-attachments/files/25816625/README.md)
# SIS – MVP de SIEM para Entornos OT/ICS

## Descripción general

**SIS** es un prototipo funcional (MVP) de una plataforma tipo **SIEM** orientada a la **detección, correlación, priorización y visualización de eventos de ciberseguridad** en entornos de red y, especialmente, en escenarios **OT/ICS** (Operational Technology / Industrial Control Systems).

El proyecto combina **captura de tráfico**, **detección por firmas**, **procesamiento y enriquecimiento de eventos**, **almacenamiento histórico** y **visualización web** en una arquitectura basada en contenedores Docker.

A nivel conceptual, el flujo principal es el siguiente:

1. **Zeek** y **Snort** observan el tráfico de red.
2. **Filebeat** recoge los logs generados y los envía a **Redis**.
3. El **núcleo Python** consume esos eventos, los normaliza, clasifica, enriquece y calcula riesgo.
4. Los eventos procesados se almacenan en **Elasticsearch**.
5. Un **dashboard en Streamlit** permite visualizar eventos en tiempo real e históricos.

---

## Objetivo del proyecto

El objetivo de SIS es demostrar la viabilidad de una solución capaz de:

- detectar eventos de seguridad en red mediante reglas y firmas;
- interpretar tráfico de interés para entornos industriales;
- correlacionar y priorizar alertas;
- incorporar una capa básica de análisis anómalo;
- entregar visibilidad operativa a través de un dashboard web.

Se trata de un **MVP orientado a demostración y validación técnica**, no de una plataforma SIEM empresarial terminada.

---

## Arquitectura de la solución

### Componentes principales

#### 1. Sensores de red

**Zeek**
- Captura y analiza tráfico de red.
- Está preparado para observar tráfico relacionado con **IEC-104** en el puerto **2404**.
- Genera logs de actividad de red y eventos OT/ICS para su posterior procesamiento.

**Snort**
- Ejecuta detección basada en firmas.
- Utiliza reglas locales para generar alertas frente a patrones definidos.
- Aporta la capa principal de **detección signature-based** del MVP.

#### 2. Transporte de eventos

**Filebeat**
- Lee los logs generados por Zeek y Snort.
- Unifica el envío de eventos hacia la cola de procesamiento.

**Redis**
- Funciona como cola de mensajes/eventos en tiempo real.
- Permite desacoplar la captura del procesamiento central.

#### 3. Núcleo de análisis

**Python Core (Cerebro)**
- Consume eventos desde Redis.
- Normaliza distintos formatos de logs.
- Identifica origen, IPs, puertos, protocolo y tipo de evento.
- Traduce ciertos comandos o eventos OT a etiquetas más comprensibles.
- Aplica lógica de correlación y clasificación.
- Calcula puntuaciones de riesgo.
- Puede activar alertas por correo en ciertos escenarios.
- Almacena los resultados procesados en Elasticsearch.

#### 4. Persistencia histórica

**Elasticsearch**
- Guarda los eventos enriquecidos y procesados.
- Permite consultas históricas y análisis desde el dashboard.

#### 5. Capa de visualización

**Dashboard Streamlit**
- Presenta eventos en tiempo real.
- Permite revisar históricos.
- Muestra secciones diferenciadas para IDS, red, SCADA/OT, riesgo y logs crudos.
- Permite operar funciones auxiliares del sistema desde la interfaz.

---

## Flujo lógico del sistema

### Flujo resumido

```text
Tráfico de red / eventos simulados
        ↓
   Zeek + Snort
        ↓
     Filebeat
        ↓
       Redis
        ↓
   Python Core
  (normaliza, correlaciona,
   enriquece y puntúa)
        ↓
  Elasticsearch
        ↓
 Dashboard Streamlit
```

### Flujo funcional detallado

1. El sistema observa tráfico o recibe eventos simulados.
2. Zeek y Snort generan registros y alertas.
3. Filebeat toma esos archivos de log y los empuja a Redis.
4. El núcleo Python consume los eventos desde la cola.
5. Los eventos se transforman a un formato común.
6. Se identifican patrones relevantes, reglas disparadas y contexto OT.
7. Se calcula una priorización basada en criticidad y comportamiento observado.
8. Los resultados se almacenan en Elasticsearch.
9. El dashboard muestra información en vivo e histórica al operador.

---

## Funcionalidades del MVP

### 1. Detección por firmas

El sistema integra Snort para detectar eventos de red a partir de reglas definidas. Esto permite:

- generar alertas frente a patrones conocidos;
- demostrar una base de detección tradicional tipo IDS;
- alimentar el pipeline de priorización y visualización.

### 2. Monitoreo de tráfico OT/ICS

El proyecto está orientado a tráfico industrial, especialmente al protocolo **IEC-104**, lo que permite:

- identificar actividad relevante en puerto 2404;
- distinguir tráfico OT del tráfico de red general;
- presentar eventos SCADA/ICS de forma diferenciada.

### 3. Normalización de eventos

El núcleo Python toma eventos provenientes de diferentes fuentes y los transforma en un esquema común. Esto ayuda a:

- correlacionar múltiples orígenes;
- facilitar búsquedas en Elasticsearch;
- mostrar datos homogéneos en el dashboard.

### 4. Enriquecimiento de eventos

Los eventos pueden complementarse con información adicional, como:

- tipo de origen;
- criticidad del activo;
- interpretación de evento OT;
- contexto de riesgo.

### 5. Análisis básico de anomalías

Además de la detección por firmas, el proyecto incorpora una capa simple de análisis anómalo orientada a:

- identificar comportamientos fuera de lo esperado;
- reforzar el valor del MVP más allá del enfoque puramente estático;
- apoyar el cálculo de riesgo.

### 6. Matriz o fusión de riesgo

Uno de los elementos más interesantes del proyecto es la construcción de una **priorización de alertas** basada en:

- severidad del evento;
- contexto del activo;
- comportamiento anómalo;
- impacto y probabilidad.

Esto permite pasar de “alerta detectada” a “alerta priorizada”, lo que es mucho más útil para operación y toma de decisiones.

### 7. Almacenamiento histórico

Elasticsearch permite:

- conservar eventos procesados;
- consultar actividad histórica;
- apoyar análisis posteriores y visualización retrospectiva.

### 8. Dashboard web interactivo

La interfaz desarrollada en Streamlit ofrece:

- vista en tiempo real;
- vista histórica;
- paneles separados por tipo de dato;
- visualización de alertas y eventos;
- exploración de logs crudos.

### 9. Inventario de activos OT

El proyecto incluye un inventario de activos que puede servir para:

- asignar criticidad a dispositivos;
- contextualizar eventos;
- enriquecer la evaluación de riesgo.

### 10. Componente de vulnerabilidades

El MVP incluye una funcionalidad de apoyo para asociar vulnerabilidades o contexto CVE a activos, con foco demostrativo.

### 11. Simulación de ataques o eventos

El repositorio incluye scripts auxiliares orientados a pruebas y demostraciones, útiles para:

- poblar el sistema con eventos de ejemplo;
- verificar el pipeline extremo a extremo;
- preparar una presentación o demo funcional.

### 12. Alertas por correo

El núcleo contempla el envío de correos en determinados escenarios críticos, como mecanismo de notificación adicional.

---

## Estructura general del proyecto

Una vista simplificada del repositorio es la siguiente:

```text
SIS/
├── sensores/              # Sensores (Zeek + Snort)
├── core/                  # Núcleo de análisis (Cerebro)
├── dashboard/             # Dashboard Streamlit
├── reglas_firmas/         # Reglas IDS / firmas
├── configuracion/         # Configuración de Filebeat/Snort
├── scripts_demo/          # Scripts de simulación y demo
├── logs/                  # Logs generados por sensores
├── docker-compose.yml     # Orquestación principal
├── ot_inventory.json      # Inventario OT
├── cve_report.csv         # Reporte o dataset de vulnerabilidades
├── lanzar_ataque_total.py # Script de simulación/demostración
└── lanzar_ataque_total_inun.py
```

---

## Requisitos para ejecutar el proyecto

### Requisitos mínimos

- **Docker** instalado
- **Docker Compose** habilitado
- Sistema operativo compatible con Docker
- Permisos suficientes para levantar contenedores con capacidades de red

### Requisitos recomendados

- Entorno Linux o laboratorio controlado
- Acceso con privilegios para interfaces de captura
- Recursos suficientes para ejecutar Elasticsearch con estabilidad

---

## Cómo ejecutar SIS

## Guía de instalación en servidor Linux

Para despliegue en servidor con acceso remoto LAN y modo proxy opcional, revisa: `docs/INSTALL_SERVER_LINUX.md`.

Para captura real desde interfaz física/puerto espejo (SPAN), revisa: `docs/SPAN_DEPLOYMENT.md`.


### 1. Clonar el repositorio

```bash
git clone https://github.com/TimmyTurner691/SIS.git
cd SIS
```

### 2. Configurar variables de entorno

```bash
cp .env.sis .env
# Edita .env según tu entorno
```

### 3. Levantar los contenedores

```bash
docker compose up --build
```

Esto construirá y levantará los servicios definidos en `docker-compose.yml`.

> Acceso remoto LAN (modo simple): `http://IP_SERVIDOR:${SIS_DASHBOARD_PORT}`.
>
> Modo proxy opcional (Nginx):
> ```bash
> docker compose --profile proxy up -d --build
> ```
> Acceso: `http://IP_SERVIDOR:${SIS_PROXY_PORT}`.

### 4. Verificar que los servicios estén arriba

```bash
docker ps
```

Deberían aparecer contenedores equivalentes a:

- Zeek
- Snort
- Filebeat
- Redis
- Elasticsearch
- Cerebro (Python Core)
- Dashboard

### 5. Acceder al dashboard

Una vez iniciado el stack, el dashboard debería quedar disponible en:

```text
http://localhost:8501
```

### 6. Verificar Elasticsearch

```text
http://localhost:9200
```

### 7. Verificar Redis

Redis quedará expuesto típicamente en:

```text
localhost:6379
```

---

## Consideraciones importantes de ejecución

### 1. Proyecto orientado a laboratorio / demo

La configuración del MVP está pensada principalmente para **pruebas, demostración y validación funcional**. No debe considerarse directamente lista para producción sin endurecimiento adicional.

### 2. Captura sobre interfaz local

La configuración actual apunta a una interfaz de captura local, por lo que el comportamiento observado puede estar orientado a tráfico simulado o generado dentro del mismo entorno de prueba.

### 3. Interfaz de gestión vs captura

En despliegue real se recomienda separar:

- **Interfaz de gestión** (`SIS_MANAGEMENT_INTERFACE` / `SIS_MANAGEMENT_BIND_IP`) para acceso GUI/SSH.
- **Interfaz de captura** (`SIS_CAPTURE_INTERFACE`) para tráfico SPAN.

### 3. Dependencia de logs y volumenes

El correcto funcionamiento depende de que:

- los volúmenes montados existan;
- las rutas de logs sean válidas;
- Filebeat pueda leer esos archivos;
- Redis y Elasticsearch estén disponibles cuando el núcleo Python comience a procesar.

### 4. Inicio completo del stack

Algunos componentes pueden tardar más en quedar listos, especialmente Elasticsearch. Si el dashboard no refleja datos de inmediato, conviene esperar a que todos los servicios terminen de inicializar.

---

## Cómo probar el sistema

### Opción 1: Generar eventos desde scripts incluidos

El repositorio incorpora scripts de simulación, por lo que una forma práctica de probar el pipeline es ejecutarlos una vez que el stack esté arriba.

Ejemplo:

```bash
python3 lanzar_ataque_total.py
```

Según el entorno, también puede usarse:

```bash
python3 lanzar_ataque_total_inun.py
```

### Opción 2: Revisar logs en tiempo real

Puedes observar actividad de contenedores con:

```bash
docker compose logs -f
```

O revisar un servicio puntual:

```bash
docker compose logs -f dashboard
docker compose logs -f cerebro
docker compose logs -f filebeat
```

## Configuración y secretos

- Todas las variables de entorno del stack están documentadas en `.env.sis`.
- **No** se incluyen credenciales SMTP en el repositorio.
- Para habilitar alertas por correo, define en `.env`: `SIS_SMTP_SERVER`, `SIS_SMTP_PORT`, `SIS_SMTP_SENDER_EMAIL`, `SIS_SMTP_SENDER_PASSWORD`, `SIS_SMTP_RECEIVER_EMAIL`.
- Si esos valores quedan vacíos, el core omite el envío de correos sin fallar.

### Opción 3: Confirmar ingestión en Elasticsearch

Si el pipeline está funcionando, el índice histórico debería comenzar a poblarse y el dashboard debería reflejar eventos.

---

## Operación básica del dashboard

Dependiendo de la versión exacta del código, el dashboard contempla secciones orientadas a:

- **Riesgo / Fusión de riesgo**
- **Alertas IDS**
- **Tráfico de red**
- **Eventos SCADA / OT**
- **Vulnerabilidades**
- **Logs crudos**
- **Vista en tiempo real**
- **Vista histórica**

La lógica de la interfaz está diseñada para que un operador pueda revisar eventos priorizados y navegar distintas capas de información desde un solo punto.

Además, el sidebar muestra **Estado Sensores** (Zeek/Snort) en tiempo real usando heartbeat de salud (`Escuchando`, `Degradado`, `Caído`).

---

## Casos de uso que este MVP demuestra

SIS puede presentarse como una demostración técnica de los siguientes casos de uso:

- detección temprana de eventos sospechosos en red;
- visibilidad sobre tráfico OT/ICS;
- priorización de alertas en base a criticidad;
- consolidación de múltiples fuentes en una sola consola;
- analítica básica sobre comportamiento y riesgo;
- soporte a pruebas de concepto para monitoreo industrial.

---

## Limitaciones actuales del MVP

Para una presentación seria, conviene explicar estas limitaciones con honestidad técnica. Eso da más credibilidad que vender humo cósmico.

### Limitaciones esperables

- No es un SIEM empresarial completo.
- La capa de análisis anómalo es básica.
- La cobertura MITRE/ICS no necesariamente es extensa.
- La lógica de correlación está orientada a MVP y demostración.
- La captura y reglas deben ajustarse para cada entorno real.
- Requiere endurecimiento de seguridad antes de uso productivo.
- La integración con fuentes externas aún puede ampliarse.

---

## Mejoras futuras sugeridas

Líneas naturales de evolución del proyecto:

- ampliar reglas y cobertura de detección;
- soportar más protocolos OT/ICS;
- robustecer la correlación multi-evento;
- mejorar el modelo de anomalías;
- incorporar autenticación y control de acceso al dashboard;
- separar configuración sensible en variables de entorno o secretos;
- agregar métricas, reportes y exportación ejecutiva;
- incorporar más fuentes de inteligencia o vulnerabilidades;
- diseñar despliegue más cercano a producción.

---

## Valor para presentación ante inversionistas

Desde una perspectiva de negocio y producto, SIS demuestra varios elementos atractivos:

- un problema real: visibilidad y detección en entornos OT/ICS;
- una arquitectura modular y escalable por componentes;
- integración de detección, analítica y visualización;
- una propuesta híbrida entre monitoreo industrial y priorización de riesgo;
- capacidad de evolucionar desde MVP hacia producto especializado.

En términos de pitch, SIS puede posicionarse como una **plataforma de monitoreo y priorización de ciberseguridad para entornos industriales**, con foco en visibilidad operativa, detección temprana y apoyo a la toma de decisiones.

---

## Recomendaciones antes de la presentación

Antes de mostrar el proyecto, conviene:

1. validar que el stack levante desde cero sin intervención manual;
2. ejecutar un flujo demo reproducible;
3. limpiar credenciales o datos sensibles del repositorio;
4. preparar una narrativa clara: problema, solución, arquitectura, demo, roadmap;
5. mostrar el MVP como base evolutiva, no como producto final cerrado.

---

## Resumen ejecutivo

**SIS** es un MVP de plataforma SIEM/OT que integra captura de tráfico, detección por firmas, procesamiento inteligente, almacenamiento histórico y visualización web en una arquitectura Docker. Su valor principal está en demostrar cómo eventos de ciberseguridad en entornos industriales pueden ser detectados, enriquecidos y priorizados dentro de una sola solución operativa.

---

## Licencia / uso

Se recomienda agregar aquí la licencia del proyecto si se desea formalizar su distribución, reutilización o presentación pública.

---

## Licencia / uso

Se recomienda agregar aquí la licencia del proyecto si se desea formalizar su distribución, reutilización o presentación pública.

## Gestión modular de firmas

La pestaña **✍️ Firmas / Reglas** permite instalar, habilitar y deshabilitar los paquetes IEC-104, Modbus, IEC-61850, Windows, Linux, Web, DNS, SMB y Otros. También ofrece los perfiles **OT eléctrico**, **TI Windows**, **Linux/Web** y **Mixto liviano** como punto de partida editable.

El catálogo y los perfiles viven en `reglas_firmas/catalog.json` y `reglas_firmas/profiles.json`. Al aplicar una selección, el dashboard valida la estructura y los SIDs, genera atómicamente `reglas_firmas/control/effective.rules` y solicita la recarga. El contenedor Snort ejecuta después `snort -T` sobre el candidato; solo si la validación nativa termina correctamente reemplaza `active.rules` y reinicia el proceso del sensor, sin reiniciar Redis, Elasticsearch, el núcleo ni el dashboard. Si la validación falla, conserva el set activo anterior y publica el motivo en la GUI.

### Alcance IPv4 y limpieza de reglas heredadas

SIS descarta eventos IPv6 durante la normalización central, antes de enriquecerlos o almacenarlos en Elasticsearch. El dashboard también excluye resultados IPv6 históricos de todas las vistas operativas. Al iniciar o recargar Snort se elimina automáticamente la antigua firma de prueba SID `1000005` (`[TEST] Ping Detectado en WiFi`) de cualquier `active.rules` persistente, sin alterar los demás paquetes seleccionados.

Al conectar con Elasticsearch, Cerebro elimina selectivamente los documentos históricos que contengan el SID `1000005` o el mensaje `Ping Detectado en WiFi`. La limpieza no afecta a la firma vigente `SIS ICMP detectado` (SID `1100802`).

Los eventos cuyo origen y destino sean simultáneamente `0.0.0.0` se consideran tráfico basura. Cerebro los descarta antes de indexarlos, elimina los históricos existentes al iniciar y el dashboard los excluye de todas las vistas, incluida **Logs Raw**. Un único extremo `0.0.0.0` no activa este filtro.

### Afinación de IA y detección DoS

La detección DoS ya no utiliza el volumen global del sistema para clasificar cada evento. Cerebro calcula tasas sobre una ventana móvil de cinco segundos y exige concentración por flujo o destino, o una firma DoS explícita. El modelo IsolationForest usa tasas logarítmicas estables (EPS aceptados, EPS del flujo dominante, pares únicos y proporción IDS), no aprende ventanas de ataque como tráfico normal y solo aporta evidencia secundaria al riesgo. Una desviación de IA por sí sola no puede convertir ICMP normal en DoS crítico. El fallback directo de logs queda deshabilitado por defecto para evitar duplicar eventos que ya entrega Filebeat.

#### Protección contra replay y pings normales

Cerebro conserva por separado la hora producida por el sensor (campo `ts` de Zeek o encabezado temporal de Snort) y la hora de ingestión entregada por Filebeat. La hora de ingestión mantiene los eventos disponibles en las vistas en vivo; la hora del sensor se utiliza exclusivamente para decidir si un registro puede participar en la tasa de una inundación. Los registros atrasados siguen visibles e indexados, pero no pueden convertirse en un falso pico de tráfico. Además, los duplicados exactos se suprimen durante `SIS_EVENT_DEDUP_TTL_SECONDS`.

ICMP utiliza umbrales independientes y deliberadamente superiores (`SIS_FLOOD_ICMP_MIN_EVENTS` y `SIS_FLOOD_ICMP_MIN_EPS`). Los ping request/reply normales siguen visibles como eventos `SIS ICMP detectado`, pero no se convierten en una inundación confirmada. El dashboard oculta y Cerebro purga los falsos positivos ICMP generados por la versión anterior del detector; las detecciones nuevas llevan `detection_model_version` para distinguirlas de ese historial.

### Bloques SID de los paquetes

Las firmas administradas por SIS usan bloques base de 100 SIDs por categoría dentro del espacio local `1100000-1100899`, con rangos de expansión explícitos cuando una categoría supera esa capacidad. El paquete DNS reserva `1100601-1100699`; sus 55 reglas actuales ocupan consecutivamente `1100601-1100655`. Este bloque cubre consultas inusuales, transferencia de zona, amplificación, tasas elevadas, descubrimiento, DNS dinámico, servicios de túnel, indicadores de exfiltración y patrones de tunneling. Las pruebas del catálogo rechazan duplicados globales y reglas ubicadas fuera de los rangos asignados a su paquete.

El paquete IEC-104 conserva los SIDs iniciales `1100001-1100002` para compatibilidad y reserva `1110001-1110199` para su expansión. Las 106 firmas ampliadas ocupan `1110001-1110106` y cubren APCI/U-frames, Type IDs de telemetría y control, interrogación, sincronización, reset, causas de transmisión, tipos reservados y tasa elevada de APDUs. Los SIDs `1200xxx` de la propuesta original no se usan para evitar mezclar espacios no administrados con los bloques SIS.

El paquete IEC-61850 conserva los SIDs iniciales `1100201-1100202` y asigna sus 40 firmas ampliadas a `1100203-1100242`, dentro del bloque reservado `1100201-1100299`. La cobertura incluye conexiones MMS, TPKT/COTP, PDUs MMS, asociaciones ACSE, operaciones MMS, nodos lógicos y objetos de control IEC-61850, límites de payload y detección de tasas elevadas. Los SIDs `1202xxx` propuestos se remapean al bloque SIS para evitar conflictos entre categorías.

El paquete Linux conserva los SIDs iniciales `1100401-1100402` y asigna sus 84 firmas ampliadas a `1100403-1100486`, dentro del bloque reservado `1100401-1100499`. La cobertura incluye exposición SSH/Telnet/FTP, fuerza bruta SSH, reverse shells, descargas, persistencia, acceso a credenciales, escalamiento, borrado de rastros, herramientas ofensivas, túneles, transferencias, contenedores, Kubernetes y metadatos cloud. Los SIDs `1204xxx` propuestos se remapean al bloque SIS para evitar conflictos entre categorías.

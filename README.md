# SIS – MVP de SIEM para Entornos OT/ICS

## Descripción general

**SIS** es un prototipo funcional (MVP) de una plataforma tipo **SIEM** orientada a la **detección, correlación, priorización y visualización de eventos de ciberseguridad** en entornos de red y, especialmente, en escenarios **OT/ICS** (Operational Technology / Industrial Control Systems).

El proyecto combina **captura de tráfico**, **detección por firmas**, **procesamiento y enriquecimiento de eventos**, **almacenamiento histórico** y **visualización web moderna** en una arquitectura basada en contenedores Docker.

A nivel conceptual, el flujo principal es el siguiente:

1. **Zeek** y **Snort** observan el tráfico de red.
2. **Filebeat** recoge los logs generados y los envía a **Redis**.
3. El **núcleo Python** consume esos eventos, los normaliza, clasifica, enriquece y calcula riesgo mediante Machine Learning.
4. Los eventos procesados se almacenan en **Elasticsearch**.
5. Un **dashboard en Next.js (React + Tailwind CSS)** permite visualizar métricas operativas en tiempo real, operar el motor de IA y configurar alertas.

---

## Objetivo del proyecto

El objetivo de SIS es demostrar la viabilidad de una solución capaz de:

- detectar eventos de seguridad en red mediante reglas y firmas;
- interpretar tráfico de interés para entornos industriales;
- correlacionar y priorizar alertas mediante matrices de riesgo;
- incorporar una capa básica de análisis anómalo y aprendizaje automático;
- entregar visibilidad operativa a través de un dashboard web interactivo y de grado SOC.

Se trata de un **MVP orientado a demostración y validación técnica**, no de una plataforma SIEM empresarial terminada.

---

## Arquitectura de la solución

### Componentes principales

#### 1. Sensores de red

**Zeek**
- Captura y analiza tráfico de red.
- Está preparado para observar tráfico relacionado con **IEC-104** en el puerto **2404**.
- Genera logs de actividad de red crudos (JSON) y eventos OT/ICS para su posterior procesamiento.

**Snort**
- Ejecuta detección basada en firmas.
- Utiliza reglas locales para generar alertas frente a patrones definidos.
- Aporta la capa principal de **detección signature-based** del MVP.

#### 2. Transporte y Comunicación Asíncrona

**Filebeat**
- Lee los logs generados por Zeek y Snort.
- Unifica el envío de eventos hacia la cola de procesamiento.

**Redis**
- Funciona como cola de mensajes/eventos en tiempo real para la ingesta de logs.
- Actúa como **puente de comunicación bidireccional** entre el Dashboard (Next.js) y el motor (Python) para enviar comandos en vivo (Reset IA, Configuración SMTP).

#### 3. Núcleo de análisis

**Python Core (Cerebro)**
- Consume eventos desde Redis.
- Normaliza distintos formatos de logs.
- Identifica origen, IPs, puertos, protocolo y tipo de evento.
- Traduce comandos OT a etiquetas comprensibles.
- Aplica lógica de correlación, clasificación y Machine Learning.
- Calcula puntuaciones de riesgo (Riesgo Total = Impacto x Probabilidad).
- Procesa comandos en vivo desde la UI (ej. reentrenamiento de IA).
- Almacena los resultados procesados en Elasticsearch.

#### 4. Persistencia histórica

**Elasticsearch**
- Guarda los eventos enriquecidos, logs crudos y la telemetría de los sensores.
- Permite consultas históricas y alimenta las APIs del dashboard en tiempo real.

#### 5. Capa de visualización

**Dashboard en Next.js**
- Interfaz moderna construida con React y Tailwind CSS.
- APIs internas que consultan directamente a Elasticsearch y Redis.
- Presenta KPIs en tiempo real (Riesgo Máximo, Incidentes Críticos).
- Matriz de calor dinámica (Impacto vs Probabilidad).
- Permite configurar alertas dinámicas por correo electrónico.

---

## Flujo lógico del sistema

### Flujo funcional detallado

1. El sistema observa tráfico o recibe eventos simulados.
2. Zeek y Snort generan registros y alertas en formato JSON.
3. Filebeat empuja estos logs a la cola de Redis.
4. El núcleo Python consume, transforma y enriquece los eventos.
5. Se calcula una priorización basada en criticidad (Heatmap).
6. Los resultados se indexan en Elasticsearch.
7. El dashboard de Next.js consume las APIs y dibuja las métricas, evaluando en paralelo la salud de la base de datos y la última vez que los sensores emitieron telemetría.
8. El usuario interactúa con la UI (ej. cambia el correo de alertas), enviando una orden asíncrona por Redis que Python procesa al instante.

---

## Funcionalidades del MVP

### 1. Detección por firmas y Monitoreo OT
Integración de Snort para redes IT y análisis de tráfico industrial (IEC-104) mediante Zeek, permitiendo distinguir eventos SCADA de forma diferenciada.

### 2. Matriz de Fusión de Riesgo
Construcción de priorización de alertas basada en severidad, contexto del activo e impacto vs probabilidad. El dashboard lo renderiza visualmente en una cuadrícula (Heatmap) interactiva.

### 3. Dashboard Web Interactivo de grado SOC
Una consola centralizada (Next.js) que ofrece:
- **KPIs Operativos:** Riesgo máximo y conteo de IPs afectadas.
- **Feed Crítico:** Tabla en vivo con los últimos incidentes de severidad alta.
- **Control de IA:** Botones para borrar la memoria del modelo anómalo o forzar un reentrenamiento en vivo.
- **Logs Crudos:** Acceso al payload crudo (JSON) original de Zeek para Threat Hunting profundo.

### 4. Alertas Dinámicas por Correo (SMTP)
El núcleo contempla el envío automático de correos frente a incidentes críticos, mitigando inundaciones (cooldown). El **destinatario de los correos puede ser modificado en tiempo real** desde el dashboard sin necesidad de reiniciar servicios, usando Redis como canal de control.

### 5. Telemetría de Sensores en Vivo
El dashboard no asume el estado de los sensores; consulta activamente Elasticsearch para verificar exactamente hace cuántos segundos inyectaron el último log de tráfico, asegurando visibilidad real del estado de captura.

---

## Estructura general del proyecto

```text
SIS/
├── sensores/              # Sensores (Zeek + Snort)
├── core/                  # Núcleo de análisis (Cerebro IA)
├── dashboard/web/         # Dashboard Next.js (React + APIs)
├── reglas_firmas/         # Reglas IDS / firmas
├── configuracion/         # Configuración de Filebeat/Snort
├── scripts_demo/          # Scripts de simulación y demo
├── logs/                  # Logs generados por sensores
├── docker-compose.yml     # Orquestación principal
└── .env.sis               # Variables de entorno y secretos
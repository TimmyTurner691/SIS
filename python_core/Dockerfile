FROM python:3.9-slim

WORKDIR /app

# Instalar librerías necesarias
RUN pip install redis elasticsearch numpy pandas scikit-learn watchdog

# Copiar el código (se hará vía volumen, pero esto asegura la estructura)
COPY . /app

CMD ["python", "-u", "main.py"]

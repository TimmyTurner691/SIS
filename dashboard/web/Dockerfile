FROM node:20-alpine
WORKDIR /app

# Copiamos archivos e instalamos
COPY package*.json ./
RUN npm install

# Copiamos el resto del código
COPY . .

# 🔥 LA MAGIA OCURRE AQUÍ: Compilamos para producción
RUN npm run build

EXPOSE 3000

# Iniciamos el servidor de producción (sin WebSockets problemáticos)
CMD ["npm", "start"]
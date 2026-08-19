FROM node:20-alpine
WORKDIR /app

# Copiamos solo los archivos de dependencias primero (optimización de caché)
COPY package*.json ./

# Instalamos dependencias
RUN npm install

# Copiamos el resto del código
COPY . .

EXPOSE 3000

# Comando para iniciar Next.js en modo desarrollo
CMD ["npm", "run", "dev"]
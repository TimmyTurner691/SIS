FROM node:20-alpine
WORKDIR /app

# Copiamos solo los archivos de dependencias primero (optimización de caché)
COPY package*.json ./

# Instalamos dependencias
RUN npm install

# Copiamos el resto del código
COPY . .

# Cambiamos el propietario a 'node' (UID 1000 por defecto en esta imagen).
# Esto soluciona los problemas de permisos 403 al montar volúmenes en Linux (Ubuntu),
# asumiendo que el usuario del host también es UID 1000.
RUN chown -R node:node /app

USER node

EXPOSE 3000

# Comando para iniciar Next.js en modo desarrollo
CMD ["npm", "run", "dev"]
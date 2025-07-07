# Dockerfile per API Server Node.js
FROM node:18-alpine

# Installa curl per healthcheck
RUN apk add --no-cache curl

# Crea directory di lavoro
WORKDIR /app

# Copia package files
COPY package*.json ./

# Installa dipendenze di produzione
# Se hai package-lock.json usa npm ci, altrimenti npm install
RUN if [ -f package-lock.json ]; then npm ci --omit=dev; else npm install --omit=dev; fi

# Copia il codice sorgente
COPY . .

# Crea directory per i logs
RUN mkdir -p logs

# Espone la porta dell'API
EXPOSE 3000

# Utente non-root per sicurezza
RUN addgroup -g 1001 -S nodejs
RUN adduser -S nodeuser -u 1001
RUN chown -R nodeuser:nodejs /app
USER nodeuser

# Comando di avvio
CMD ["node", "server.js"]
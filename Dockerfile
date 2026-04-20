FROM node:20-alpine

RUN apk add --no-cache python3 make g++ sqlite

WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev

COPY . .

ENV NODE_ENV=production
ENV PORT=3000
EXPOSE 3000

VOLUME ["/app/data"]
ENV DB_PATH=/app/data/ghost.db

CMD ["node", "server.js"]

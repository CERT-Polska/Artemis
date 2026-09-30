FROM node:22-slim

WORKDIR /app
COPY package.json package-lock.json /app/
RUN npm ci --omit=dev
COPY app.js /app/

CMD ["node", "app.js"]

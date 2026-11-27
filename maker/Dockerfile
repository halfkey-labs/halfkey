# HALFKEY maker daemon. Runs next to monerod + two monero-wallet-rpc processes (see docker-compose.yml).
FROM node:25-slim
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts
COPY sdk ./sdk
COPY maker ./maker
USER node
CMD ["node", "maker/daemon.ts", "/config/config.json"]

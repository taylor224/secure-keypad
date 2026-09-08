# Example server image (build from the repository root):
#   docker build -f examples/server-node/Dockerfile -t secure-keypad-example .
#   docker run -p 3789:3789 -e SKP_MASTER_KEY=<base64> -e SKP_DEMO_ECHO=1 -e SKP_ALLOW_CLIENT_LAYOUT=1 \
#              -e SKP_CORS_ORIGIN=https://<user>.github.io secure-keypad-example
FROM node:22-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends libsodium-dev zlib1g-dev python3 make g++ pkg-config \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY package.json package-lock.json ./
COPY core core
COPY bindings/node bindings/node
COPY clients/web clients/web
COPY clients/react clients/react
COPY examples/server-node examples/server-node
COPY examples/web-vanilla examples/web-vanilla
RUN npm ci --no-audit --no-fund && npm run build

FROM node:22-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends libsodium23 zlib1g && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /app /app
ENV NODE_ENV=production PORT=3789
EXPOSE 3789
USER node
CMD ["node", "examples/server-node/server.mjs"]

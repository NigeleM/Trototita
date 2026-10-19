# Team server image. The desktop app is not containerised: it runs on each user's computer.
#
#   docker build --target test -t vulnmgt-test .    # runs the full test suite on Linux
#   docker build -t vulnmgt-server .                 # the runtime image

FROM node:22-bookworm-slim AS base
# openssl is needed by the test suite (self-signed certificates) and by server/make-cert.sh.
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssl ca-certificates \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app

# Test stage: dev dependencies, no Electron binary (install scripts are skipped).
FROM base AS test
COPY package.json package-lock.json ./
COPY vendor ./vendor
RUN npm ci --ignore-scripts
COPY . .
RUN npm test

# Production dependencies only. Electron is a dev dependency, so it is not installed here.
FROM base AS deps
COPY package.json package-lock.json ./
COPY vendor ./vendor
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force

# Runtime image: the server only, running as the unprivileged "node" user.
FROM base AS runtime
ENV NODE_ENV=production
COPY --from=deps /app/node_modules ./node_modules
COPY package.json ./
COPY src ./src
COPY server ./server
RUN mkdir -p /data /certs && chown node:node /data
USER node
VOLUME ["/data"]
EXPOSE 8443
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "require('https').get({host:'127.0.0.1',port:8443,path:'/api/health',rejectUnauthorized:false},r=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1))"
ENTRYPOINT ["node", "server/server.js"]
CMD ["serve", "--cert", "/certs/cert.pem", "--key", "/certs/key.pem", "--host", "0.0.0.0", "--port", "8443", "--db", "/data/team.db"]

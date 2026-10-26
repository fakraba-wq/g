FROM node:24.22.1-bookworm-slim
WORKDIR /app
COPY --chown=node:node . .
RUN mkdir -p /data/crimson && chown node:node /data/crimson
USER node
RUN node scripts/prepare-hosted.mjs
ENV HOST=0.0.0.0 PORT=3000 SENTINEL_DATA_DIR=/data/crimson
VOLUME ["/data/crimson"]
EXPOSE 3000
CMD ["node", "server.js"]

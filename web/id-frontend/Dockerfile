FROM node:22-alpine AS dev
WORKDIR /app

RUN corepack enable && corepack prepare pnpm@10.3.0 --activate

COPY package.json pnpm-lock.yaml ./

RUN if [ -f package-lock.json ]; then \
      pnpm ci --no-audit --progress=false; \
    else \
      pnpm install --no-audit --progress=false; \
    fi && \
    pnpm install @rollup/rollup-linux-arm64-musl --no-save || true

COPY . .

CMD ["pnpm", "dev", "--host", "0.0.0.0", "--port", "5175"]
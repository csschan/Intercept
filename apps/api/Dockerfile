FROM node:20-slim

WORKDIR /app

# Copy package files and local packages
COPY package.json package-lock.json ./
COPY _solana ./_solana

# Install all dependencies (need tsx for runtime)
RUN npm ci

# Copy source and config
COPY src ./src
COPY drizzle ./drizzle
COPY tsconfig.json ./

ENV NODE_ENV=production
ENV PORT=8080
EXPOSE 8080

CMD ["npx", "tsx", "src/index.ts"]

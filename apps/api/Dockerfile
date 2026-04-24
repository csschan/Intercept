FROM node:20-alpine AS builder

WORKDIR /app
COPY package.json tsconfig.json ./
COPY src ./src

RUN npm install --production=false
RUN npx tsc

FROM node:20-alpine

WORKDIR /app
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY package.json ./

ENV NODE_ENV=production
ENV PORT=8080
EXPOSE 8080

CMD ["node", "dist/index.js"]

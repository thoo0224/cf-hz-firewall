FROM node:18-alpine

RUN npm install -g pnpm
WORKDIR /app

COPY package.json pnpm-lock.yaml ./
RUN pnpm install

COPY . .
CMD ["pnpm", "start"]

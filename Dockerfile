# syntax=docker/dockerfile:1.7

FROM node:22-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN npm test

FROM node:22-alpine AS runtime
WORKDIR /app
COPY --from=build /app ./
USER node
CMD ["node", "-e", "console.log('Release gate test image')"]

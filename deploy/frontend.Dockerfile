# Build multi-estagio. O primeiro estagio so existe pra gerar os arquivos estaticos; o
# Node inteiro (~1 GB de imagem) nao vai pra produção, so o resultado do build.
FROM node:24-alpine AS build
WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY . .

# O Vite grava VITE_API_URL dentro do JavaScript gerado, no momento do build, nao na
# hora em que o container sobe. Por isso o endereco da API entra aqui como ARG e nao
# como variavel de ambiente do container: trocar depois exige buildar de novo, e nao
# tem outro jeito enquanto for arquivo estatico servido por nginx.
ARG VITE_API_URL
ENV VITE_API_URL=${VITE_API_URL}

RUN npm run build

# Segundo estagio: so o nginx e o resultado do build. Sem Node, sem node_modules, sem
# codigo-fonte.
FROM nginx:1.27-alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY --from=nginxconf nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

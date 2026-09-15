# Pacote de deploy

Compose de produção do Veryon: banco, cache, API, motor de detecção Sigma,
enriquecimento de reputação, varredura de vulnerabilidade e o painel. Fica de fora o
que é laboratório de demonstração (honeypot, alvo vulnerável, coletor do honeypot):
um cliente real aponta o Veryon pra infraestrutura dele, não pra um ataque simulado.

Este arquivo cobre só como rodar este pacote. Instalação do zero numa VPS alheia,
backup, e o que fazer quando quebra é assunto do RUNBOOK.md, item separado do Bloco 2.

## Antes de subir

```bash
cp deploy/.env.production.example deploy/.env
```

Edite `deploy/.env`. Os campos que não têm valor de exemplo são obrigatórios:
senha do banco, `JWT_SECRET`, `ADMIN_PASSWORD`, e os dois endereços que decidem se o
painel consegue falar com a API, explicados abaixo.

## Painel e API em origens separadas

O backend publica a porta 8000 direto no host. O painel é servido por um nginx que só
entrega arquivo estático, sem proxy pra API. São duas origens diferentes de propósito,
e isso exige acertar dois campos que parecem repetir a mesma informação mas não são:

- `VITE_API_URL`: o endereço da API, gravado dentro do JavaScript do painel **no
  momento do build**. Servido pelo navegador, então tem que ser o endereço que o
  navegador do analista alcança de fora, não um nome interno do Docker.
- `CORS_ORIGINS`: o endereço de onde o painel é servido, que o backend precisa
  autorizar a chamar ele. Sem isso certo, o navegador bloqueia toda resposta da API
  com erro de CORS, mesmo com a rede toda funcionando.

Exemplo com IP fixo `203.0.113.10` e sem domínio:

```
VITE_API_URL=http://203.0.113.10:8000
CORS_ORIGINS=http://203.0.113.10
```

## Subir

```bash
docker compose -f deploy/docker-compose.prod.yml --env-file deploy/.env up -d --build
```

O `--build` aqui não é o mesmo aviso do compose de desenvolvimento: neste pacote não
existe honeypot pra recriar, então reconstruir não tem custo escondido.

Confirme:

```bash
curl http://SEU_IP_OU_DOMINIO:8000/health
```

`api`, `database` e `redis` têm que vir `ok`. O painel fica em
`http://SEU_IP_OU_DOMINIO/` (porta 80).

## Trocar VITE_API_URL depois de já ter subido

Não basta editar o `.env` e reiniciar o container `web`: o Vite grava o endereço
dentro do arquivo `.js` no momento do build, não lê variável de ambiente em tempo de
execução. É reconstruir a imagem:

```bash
docker compose -f deploy/docker-compose.prod.yml --env-file deploy/.env up -d --build web
```

## TLS

Fora deste pacote de propósito. Ele sobe em HTTP puro, na porta 80 e na 8000. Para um
domínio de verdade, ponha um proxy reverso na frente cuidando do certificado (Caddy,
Traefik ou o proxy da Cloudflare) e aponte ele pras portas 80 e 8000 deste compose.
Isso é decisão de operação, não de código, e cada ambiente escolhe diferente.

## Varredura de vulnerabilidade contra os ativos do cliente

Por padrão o `scanner` varre só os serviços internos deste próprio compose, o que
prova que ele está funcionando mas não acha vulnerabilidade real de ninguém. Preencha
`SCANNER_NMAP_TARGETS` e `SCANNER_NUCLEI_TARGETS` no `.env` com os hosts e URLs reais
que este Veryon deve vigiar, no mesmo formato do compose de desenvolvimento
(`host:porta` para nmap, `alvo@http://host:porta` para nuclei).

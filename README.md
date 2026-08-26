# Veryon

Plataforma de laboratório SOC/SIEM construída do zero, integrando honeypot, coleta de
logs (Windows/Linux), scanner de vulnerabilidades, pipeline de análise com detecção
baseada em regras Sigma mapeadas ao MITRE ATT&CK, enriquecimento com threat intelligence,
API própria, persistência em PostgreSQL/TimescaleDB e um dashboard SOC.

Projeto de portfólio — todo o tráfego de ataque é simulado localmente (sem exposição a
honeypot público na internet).

## O que é o Veryon, e por que ele existe

**SOC** (Security Operations Center) é o nome da "sala de controle" que times de
segurança usam pra vigiar uma rede em tempo real — onde ficam os alertas, os
dashboards, o histórico de eventos. **SIEM** (Security Information and Event
Management) é o tipo de software que torna essa sala possível: ele junta logs de
várias fontes diferentes, entende quando alguma coisa é suspeita e mostra isso de
um jeito que dá pra agir em cima.

O Veryon é a minha versão desse software, construída do zero pra provar — na
prática, não só na teoria — que eu sei montar o pipeline inteiro que uma vaga de
segurança/SOC espera:

1. **Gera tráfego de ataque de verdade** contra um honeypot (um sistema-isca que só
   existe pra ser atacado) e contra uma aplicação web propositalmente vulnerável.
2. **Coleta logs reais** do Windows e do Linux, do mesmo jeito que um agente
   instalado num servidor de produção faria.
3. **Detecta automaticamente** comportamento suspeito usando **Sigma** — o formato
   de regra de detecção mais usado do mercado — mapeado pro **MITRE ATT&CK**, o
   "dicionário" padrão da indústria pra descrever técnicas de ataque (ex: "T1110"
   é sempre força bruta, em qualquer ferramenta de segurança do mundo).
4. **Enriquece IPs suspeitos** consultando serviços públicos de reputação
   (AbuseIPDB, VirusTotal, OTX) — a mesma pergunta que um analista faria: "esse IP
   já foi visto fazendo coisa ruim em outro lugar?".
5. **Mostra tudo isso num dashboard web** com login, feed de eventos, fila de
   alertas com triagem (abrir → reconhecer → fechar) e consulta de reputação de
   IP — pensado pra ser a ferramenta que um analista realmente usaria no dia a dia.
6. **Gera relatório de segurança em PDF/HTML**, porque em qualquer SOC de verdade
   o trabalho não termina no alerta — alguém (cliente, gestão, auditoria) precisa
   de um resumo do que aconteceu.

Cada peça foi escolhida por representar uma responsabilidade real de time de
segurança: ingestão de log, engenharia de detecção, threat intel, backend/API,
frontend de operações e reporting — não é um único script fazendo tudo, é um
pipeline com fronteiras claras entre serviços, do jeito que existiria numa empresa.

## Arquitetura

```
Windows/Linux
│
├── Honeypot (Cowrie, isolado em rede própria)
├── Coleta de logs (coletores Python leves: Windows Event Log + auth.log Linux)
└── Scanner de vulnerabilidades (Nmap / Nuclei)
        ↓
Pipeline de análise (normalização de eventos)
        │
        ├── Detecção/Alertas (regras Sigma + MITRE ATT&CK)
        └── Threat Intel (AbuseIPDB / VirusTotal / OTX)
                ↓
          Backend / API (FastAPI, REST + JWT)
                ↓
             PostgreSQL + TimescaleDB
                ↓
        Frontend SOC Dashboard
                ↓
           Relatório/SOC (PDF/HTML)
```

## Roadmap

- [x] Fase 0 — Fundamentos & Ambiente
- [x] Fase 1 — Honeypot + Ingestão bruta
- [x] Fase 2 — Coleta de logs (Windows + Linux)
- [x] Fase 3 — Scanner de vulnerabilidades
- [x] Fase 4 — Pipeline de análise / Detecção & Alertas
- [x] Fase 5 — Threat Intel
- [x] Fase 6 — Backend/API consolidado
- [x] Fase 7 — Relatórios
- [ ] Fase 8 — Frontend SOC Dashboard *(em andamento — login, dashboard, alertas,
      eventos e threat intel já conectados na API real; relatórios ainda mockado
      no front, pois a Fase 7 não expõe endpoint; faltam as animações finais)*
- [ ] Fase 9 — Polimento & Documentação

## Isolamento das redes de risco

Duas redes rodam código que a gente não confia (honeypot real e app
propositalmente vulnerável): `honeypot_net` (Cowrie) e `target_net` (Juice
Shop, ver Fase 3). Nenhuma das duas tem rota para a rede `core` (onde ficam
backend, banco e redis) — as únicas pontes autorizadas são um volume
compartilhado somente-leitura (honeypot → `collector`) e a porta publicada do
Juice Shop (scanner → host, ver abaixo). Não existe canal de rede direto
entre essas redes de risco e o resto da stack.

Como o objetivo é permitir tráfego simulado vindo do host (ataques no
honeypot, scans no alvo vulnerável), as redes não podem ser `internal: true`
(isso impediria o próprio Docker de publicar as portas). Em vez disso, o
isolamento é feito por firewall no host: qualquer conexão **nova** originada
nas subnets dessas redes (`172.28.0.0/24` e `172.29.0.0/24`) é descartada na
chain `DOCKER-USER` do iptables, então, mesmo que o Cowrie ou o Juice Shop
fossem comprometidos de verdade, não conseguiriam ser usados como pivô para a
internet ou para outros serviços. O tráfego de entrada (sessões simuladas,
scans) não é afetado, pois usa conexões já estabelecidas.

A regra é aplicada por [`infra/firewall/apply-honeypot-egress-block.sh`](infra/firewall/apply-honeypot-egress-block.sh),
via o serviço systemd `soc-siem-egress-block.service` (roda depois do
`docker.service`, idempotente).

**Pegadinha que caímos e vale registrar**: o `scanner` (Fase 3) inicialmente
estava conectado direto na `target_net` pra alcançar o Juice Shop — só que
qualquer container ligado a essa rede recebe um IP dentro de `172.29.0.0/24`,
então o próprio tráfego do scanner acabava batendo na regra de egress-block
(a regra bloqueia pela subnet de origem, não por "quem é o atacante"). A
correção foi tirar o scanner da `target_net` e fazer ele alcançar o Juice
Shop pela porta publicada no host, via `host.docker.internal` — assim o
scanner nunca entra na rede isolada, só bate na porta exposta, como um
scanner de verdade faria vindo de fora.

## Coleta de logs (Fase 2)

Além do honeypot, o pipeline ingere telemetria de sistema operacional real —
o mesmo tipo de sinal que um SOC recebe de endpoints e servidores. Todos os
coletores gravam na mesma tabela `raw_events`, diferenciados pela coluna
`source` (`cowrie`, `linux`, `windows`), o que já deixa tudo pronto para a
Fase 4 (detecção) sem precisar de schemas separados por fonte.

- **Linux** — [`collectors/linux/app.py`](collectors/linux/app.py) roda como
  container (`linux_collector` no compose), lê `/var/log/auth.log` do host
  WSL (montado read-only) e classifica eventos de SSH e `sudo`.
- **Windows** — [`collectors/windows/collector.py`](collectors/windows/collector.py)
  roda **nativamente no Windows** (fora do Docker/WSL), porque a API de Event
  Log só existe lá. Usa `pywin32` para consultar o canal `Security` via XPath
  (login sucesso/falha, uso de privilégio administrativo, criação de processo/conta)
  e grava direto no Postgres publicado em `localhost:5432`.

Configuração única do coletor Windows (não precisa repetir depois):

```powershell
cd collectors\windows
py -3.13 -m venv .venv
.\.venv\Scripts\pip install -r requirements.txt
```

Ele precisa ler o canal `Security`, que por padrão exige privilégio elevado.
Em vez de rodar como Administrador toda vez, adicionamos o usuário ao grupo
local "Event Log Readers" (menor privilégio):

```powershell
# em um PowerShell como Administrador, uma única vez
Add-LocalGroupMember -SID "S-1-5-32-573" -Member $env:USERNAME
# depois: deslogar e logar de novo no Windows para o grupo valer
```

Rodando o coletor (sessão normal, sem admin):

```powershell
cd collectors\windows
.\.venv\Scripts\python collector.py
```

### Estabilidade da WSL2

A VM da WSL2 tem um timeout de inatividade que, mesmo com `docker.service`
habilitado, pode derrubar a distro (e os containers) entre períodos sem uso
ativo. Já desativamos o timeout da VM em `%USERPROFILE%\.wslconfig`
(`vmIdleTimeout=-1`), mas isso sozinho não se mostrou suficiente — a correção
que funcionou de fato foi manter um processo "mantenedor" conectado à distro:

```powershell
Start-Process -FilePath "wsl.exe" -ArgumentList "-d","Ubuntu-24.04","--","sleep","infinity" -WindowStyle Hidden
```

Rode esse comando uma vez no início de cada sessão de trabalho/demo (antes de
usar os coletores ou testar o honeypot) para garantir que a WSL, o Docker e o
encaminhamento de porta `localhost` fiquem estáveis.

## Scanner de vulnerabilidades (Fase 3)

O serviço `scanner` roda **sob demanda** (`profiles: ["tools"]`, não sobe com
`docker compose up`) — um scan é um evento pontual, não um processo contínuo,
mesmo espírito do honeypot. Ele combina:

- **Nmap** — varredura de porta/serviço direcionada (não usa a lista padrão de
  top-1000 portas do Nmap, que é calibrada pra internet pública e não inclui
  portas comuns de infra interna como `6379`/Redis; em vez disso, escaneia as
  portas exatas de cada serviço conhecido — como um scanner interno de
  verdade seria configurado, com inventário de ativos).
- **Nuclei** — templates de vulnerabilidade web (CVEs conhecidas,
  misconfig, exposições), contra o [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/)
  (`juice-shop`, porta `3000`), uma aplicação propositalmente vulnerável usada
  só como alvo de treino, isolada na `target_net` (ver seção de isolamento
  acima).

Os achados vão pro mesmo `raw_events` (`source='scanner'`,
`event_type='scanner.nmap.port_open'` ou `'scanner.nuclei.finding'`).

```bash
docker compose --profile tools run --rm scanner
```

> Nota: a maioria das vulnerabilidades propositais do Juice Shop são falhas de
> lógica de aplicação (SQLi, IDOR, controle de acesso quebrado) — o tipo de
> coisa que o Nuclei, por ser baseado em assinaturas/templates de CVEs e
> misconfigurações conhecidas, não foi feito pra achar. É um resultado
> esperado e um bom ponto pra discutir em entrevista: entender o que cada
> ferramenta cobre (e o que não cobre) é tão importante quanto rodar a
> ferramenta.

## Detecção & Alertas (Fase 4)

O serviço `detection` avalia [regras no formato Sigma](detection/rules/)
(o padrão da indústria para regras de detecção, mapeadas ao
[MITRE ATT&CK](https://attack.mitre.org/)) contra o `raw_events` e grava
correspondências em `alerts`.

- As regras são **validadas** contra o schema oficial do Sigma via
  [`pysigma`](https://github.com/SigmaHQ/pySigma) antes de entrar em uso —
  erro de sintaxe é pego na hora, não silenciosamente ignorado.
- A **avaliação** em si (casar uma regra contra um evento) é um
  interpretador próprio e enxuto ([`detection/sigma_eval.py`](detection/sigma_eval.py)):
  cobre o subconjunto do Sigma realmente necessário aqui — um ou mais blocos
  de seleção combinados com `and`/`or`/`not` e os modificadores
  `contains`/`startswith`/`endswith` — não a especificação completa (ex:
  regras formais de correlação, que o Sigma define separadamente).
- Pra agregação por contagem/janela de tempo (ex: "5 falhas de login do
  mesmo IP em 5 minutos"), as regras usam um bloco `threshold` — uma
  extensão nossa, não sintaxe oficial do Sigma — avaliado via SQL direto
  (`detection/engine.py`), não pelo interpretador de `selection`/`condition`.
- O motor roda em loop (`POLL_SECONDS`), guarda o checkpoint de até onde já
  processou em `raw_events.id` numa tabela própria (`detection_checkpoint`,
  no Postgres — sobrevive a rebuild/restart do container), e faz *cooldown*
  nos alertas de limiar pra não repetir o mesmo alerta a cada ciclo enquanto
  o ataque continua.

7 regras cobrindo as quatro fontes já ingeridas:

| Regra | Fonte | Nível | MITRE |
|---|---|---|---|
| Login bem-sucedido no honeypot | cowrie | high | T1110 |
| Comando executado no honeypot | cowrie | medium | T1059 |
| Força bruta SSH (Linux, limiar) | linux | high | T1110.001 |
| Força bruta de logon (Windows, limiar) | windows | high | T1110 |
| Logon com privilégio administrativo | windows | low | T1078 |
| `sudo` com comando sensível | linux | medium | T1548.003 |
| Achado Nuclei severidade média+ | scanner | medium | T1595 |

```bash
docker compose exec -T db psql -U socadmin -d socsiem -c \
  "SELECT ts, title, level, mitre_technique, source_host, source_ip FROM alerts ORDER BY ts DESC LIMIT 20;"
```

> **Pegadinha que caímos**: na primeira subida do motor, todas as 7 regras
> falharam na validação (`id` precisa ser um UUID de verdade no Sigma
> oficial — eu tinha usado slugs tipo `soc-siem-001`). O motor rodou mesmo
> assim com 0 regras validas e avançou o checkpoint até o fim do histórico
> sem nunca ter avaliado nada. Corrigir as regras depois não bastou -- o
> checkpoint já estava lá na frente, então nada "novo" sobrava pra
> reprocessar. Tive que resetar `detection_checkpoint` manualmente. Boa
> lição sobre como checkpoints "silenciosos" podem mascarar um motor que
> nunca encontrou nada por estar quebrado, não por falta de eventos.

## Threat Intel (Fase 5)

O serviço `threatintel` enriquece IPs vistos em `raw_events` com reputação de
três fontes (todas com plano gratuito): [AbuseIPDB](https://www.abuseipdb.com/)
(score de abuso 0-100, país, ISP), [VirusTotal](https://www.virustotal.com/)
(quantos motores de antivírus marcam o IP como malicioso) e
[OTX/AlienVault](https://otx.alienvault.com/) (quantos "pulses" — relatórios
de inteligência de ameaça da comunidade — referenciam aquele IP). Resultado
gravado em `ip_enrichment` (upsert por IP, com TTL de 24h pra não reconsultar
à toa e estourar os limites do plano gratuito).

**Contexto importante**: como o honeypot e os coletores rodam 100% locais
(sem exposição pública, por design — ver a seção de isolamento), o IP de
origem que a gente realmente observa é quase sempre interno/privado
(`172.28.0.1`, etc), que nenhuma dessas APIs tem o que informar (IP privado
não navega na internet, não tem reputação pública). O motor já filtra esses
automaticamente e nunca gasta chamada de API com eles. Pra demonstrar o
enriquecimento com um IP público de verdade, use o modo sob demanda:

```bash
docker compose run --rm threatintel --ip 8.8.8.8
docker compose exec -T db psql -U socadmin -d socsiem -c \
  "SELECT * FROM ip_enrichment WHERE ip = '8.8.8.8';"
```

Configuração: crie contas gratuitas nos três serviços, gere uma API key em
cada, e coloque em `.env` (`ABUSEIPDB_API_KEY`, `VIRUSTOTAL_API_KEY`,
`OTX_API_KEY`).

## API consolidada (Fase 6)

O FastAPI (`backend`) agora expõe os dados coletados nas fases anteriores
por trás de autenticação **JWT**. Um usuário admin é criado automaticamente
no primeiro startup, a partir de `ADMIN_USERNAME`/`ADMIN_PASSWORD` no `.env`
(senha guardada com hash bcrypt, nunca em texto puro no banco).

| Rota | Auth | Descrição |
|---|---|---|
| `GET /health` | não | healthcheck (API/DB/Redis) |
| `POST /auth/login` | não | login (form `username`/`password`), devolve JWT |
| `GET /events` | sim | lista `raw_events` (filtros: `source`, `event_type`, `src_ip`, `since`, paginação) |
| `GET /events/{id}` | sim | evento específico |
| `GET /alerts` | sim | lista `alerts` (filtros: `level`, `rule_id`, `status`, `since`, paginação) |
| `GET /alerts/{id}` | sim | alerta específico |
| `PATCH /alerts/{id}` | sim | atualiza status (`open`/`acknowledged`/`closed`) |
| `GET /enrichment/{ip}` | sim | dados de threat intel de um IP |
| `GET /stats/summary` | sim | contagens agregadas (eventos por fonte, alertas por nível, top IPs) |

```bash
# login
curl -X POST http://localhost:8000/auth/login \
  -d "username=admin&password=$ADMIN_PASSWORD"

# usar o token
curl -H "Authorization: Bearer <token>" http://localhost:8000/alerts
```

A documentação interativa (Swagger, com botão "Authorize" já integrado ao
fluxo OAuth2/JWT) fica em `http://localhost:8000/docs`.

## Relatórios (Fase 7)

O serviço `reports` roda **sob demanda** (mesmo padrão do `scanner`) e gera
um relatório de segurança em HTML + PDF a partir de `raw_events`/`alerts`/
`ip_enrichment`: resumo executivo, tabela de alertas por severidade,
técnicas MITRE ATT&CK observadas, IPs de origem mais ativos (com contexto de
threat intel quando disponível) e achados do scanner. Renderizado com
Jinja2 (HTML) + [WeasyPrint](https://weasyprint.org/) (PDF).

```bash
docker compose --profile tools run --rm reports --days 7
```

Os arquivos saem em `reports/output/` (fora do controle de versão — é saída
gerada, não código-fonte).

## Frontend / Dashboard (Fase 8)

O dashboard (`frontend/`) é a interface que um analista realmente usaria: login
com JWT, visão geral (dashboard), fila de alertas com triagem, feed de eventos
brutos, consulta de reputação de IP e (em breve) relatórios direto pela tela.

- **Stack**: React 19 + TypeScript + Vite, Tailwind CSS v4, componentes
  [shadcn/ui](https://ui.shadcn.com/), animações com [`motion`](https://motion.dev/)
  (sucessor do Framer Motion), roteamento com `react-router-dom`.
- **Autenticação**: a tela de login chama `POST /auth/login` de verdade — senha
  errada faz uma chamada real, recebe `401` do backend e anima o botão (balança,
  fica vermelho, mostra um X). Senha certa grava o token JWT no navegador
  (`localStorage`) e libera as rotas protegidas; sem token, qualquer tentativa de
  acessar `/dashboard` e as demais telas redireciona pro login.
- **Dados**: dashboard, alertas, eventos e threat intel consomem a API real
  (`/stats/summary`, `/alerts`, `/events`, `/enrichment/{ip}`) — nada de dado
  inventado. Mudar o status de um alerta na tela grava de verdade no banco via
  `PATCH /alerts/{id}`. A tela de Relatórios ainda usa dados de exemplo porque a
  Fase 7 é hoje um script, não uma rota de API — fica pra quando (se) isso virar
  endpoint.
- **Onde mexer**: `frontend/src/pages/` (uma página por tela), `frontend/src/lib/api.ts`
  (cliente HTTP + tipos de cada resposta do backend), `frontend/src/lib/auth-context.tsx`
  (sessão/login), `frontend/src/index.css` (paleta de cores — tokens CSS, não cor
  espalhada pelo código).

> **Pegadinha que caímos**: o backend não tinha CORS configurado — funcionava
> liso no Swagger (`/docs`, mesma origem) mas o navegador bloqueava toda
> chamada vinda do Vite (`localhost:5173`) sem explicação nenhuma na tela,
> só no console. Resolvido com `CORSMiddleware` liberando explicitamente a
> origem do frontend em `backend/app/main.py`.

## Guia rápido — do zero até o dashboard no ar

Passo a passo completo, da primeira vez que você abre o projeto até estar
logado no dashboard vendo dado real. Termos técnicos explicados conforme
aparecem.

### 1. Pré-requisitos: Docker

Você precisa do **Docker** rodando (é ele que sobe banco de dados, backend e
os simuladores de ataque, tudo isolado em containers — como "caixinhas"
independentes que não bagunçam o resto do seu computador). Duas formas
funcionam para este projeto, use a que já estiver disponível na sua máquina:

- **Docker Desktop** (mais simples no Windows) — instale de
  [docker.com/products/docker-desktop](https://www.docker.com/products/docker-desktop/),
  abra o app e espere o ícone da baleia ficar "Running" na bandeja do sistema.
- **Docker nativo dentro do WSL2** (Ubuntu 24.04) — usado quando não se quer
  depender do app gráfico do Docker Desktop; o serviço `docker` roda via
  `systemd` direto na distro Linux.

Confirme que está funcionando:

```bash
docker info
```

Se isso responder com informações do servidor (não um erro de conexão), está
pronto.

### 2. Configurar variáveis de ambiente

O projeto já vem com um `.env.example` — copie pra `.env` (esse arquivo tem
senha e chaves de API, por isso não vai pro controle de versão):

```bash
cp .env.example .env
```

Se quiser reputação de IP de verdade (Fase 5 — Threat Intel), crie contas
gratuitas em [AbuseIPDB](https://www.abuseipdb.com/), [VirusTotal](https://www.virustotal.com/)
e [OTX/AlienVault](https://otx.alienvault.com/), gere uma API key em cada, e
cole nas variáveis `ABUSEIPDB_API_KEY`, `VIRUSTOTAL_API_KEY`, `OTX_API_KEY` do
`.env`. Sem isso, o projeto funciona igual — só não retorna reputação real pra
IPs públicos.

### 3. Subir o backend (API + banco + honeypot + detecção)

```bash
docker compose up -d --build
```

Isso builda e sobe, em segundo plano: banco (PostgreSQL/TimescaleDB), Redis,
a API (`backend`), o honeypot (`cowrie`), o alvo vulnerável (`juice-shop`),
os coletores de log, o motor de detecção e o serviço de threat intel.
Confirme que está tudo certo:

```bash
curl http://localhost:8000/health
```

Resposta esperada:

```json
{"api": "ok", "database": "ok", "redis": "ok"}
```

### 4. Subir o frontend (dashboard)

Em outro terminal:

```bash
cd frontend
npm install
npm run dev
```

Abra `http://localhost:5173` no navegador.

### 5. Fazer login

Usuário e senha são criados automaticamente na primeira subida do backend, a
partir de `ADMIN_USERNAME`/`ADMIN_PASSWORD` no seu `.env` (usuário padrão:
`admin`). Depois de logado:

- **Dashboard** — visão geral: total de eventos ingeridos, alertas por
  severidade, eventos por fonte, IPs de origem mais ativos.
- **Alertas** — fila de triagem: filtra por severidade/status, clica num
  alerta pra ver os detalhes e o payload do evento que disparou a regra, e
  muda o status (Aberto → Reconhecido → Fechado).
- **Eventos** — feed bruto de tudo que foi ingerido (logs de honeypot, Linux,
  Windows, scanner), antes de qualquer regra de detecção rodar em cima.
- **Threat Intel** — consulta a reputação pública de um IP (score de abuso,
  país, ISP, engines de antivírus que marcam como malicioso).
- **Relatórios** — ainda com dado de exemplo (ver seção do Frontend acima).

### 6. Ver o pipeline funcionando de ponta a ponta

Pra ver um ataque de verdade atravessar o sistema inteiro — do honeypot até
virar alerta na tela — simule um login no honeypot SSH:

```bash
sshpass -p 'qualquer-senha' ssh -p 2222 -o StrictHostKeyChecking=no root@localhost 'whoami'
```

Em alguns segundos (o motor de detecção roda em loop curto), um alerta
**high** — "Login bem-sucedido no honeypot" — aparece na tela de Alertas.

### 7. Parar tudo

```bash
docker compose down
```

(o frontend para com `Ctrl+C` no terminal onde rodou `npm run dev`)

## Estrutura do repositório

```
backend/        API FastAPI (Fase 0+)
infra/postgres/ Scripts de inicialização do banco
infra/firewall/ Regra de egress-block da rede do honeypot (Fase 1)
collector/      Coletor do Cowrie (honeypot → raw_events) (Fase 1)
collectors/     Coletores de log de SO: Linux (container) e Windows (nativo) (Fase 2)
scanner/        Nmap + Nuclei contra os serviços internos e o Juice Shop (Fase 3)
detection/      Regras Sigma (validadas via pysigma) + motor de avaliação próprio (Fase 4)
threatintel/    Enriquecimento de IP via AbuseIPDB/VirusTotal/OTX (Fase 5)
reports/        Geração de relatório SOC em HTML/PDF (Fase 7)
frontend/       Dashboard web (React/Vite) — login, alertas, eventos, threat intel (Fase 8)
```

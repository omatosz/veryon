# Veryon

Veryon é um SOC/SIEM completo que eu construí do zero, e este README é o guia pra
você rodar e usar ele na sua máquina, do clone ao primeiro alerta.

Em uma frase: ele recebe ataque de verdade num honeypot, coleta log de Windows e
Linux, varre vulnerabilidade com ciclo de vida, analisa comportamento de API, detecta
com regras Sigma mapeadas pro MITRE ATT&CK, cruza IP com threat intelligence, previne
ameaça com política automática, e põe tudo num painel pra operar.

**[Ver a landing page](https://omatosz.github.io/veryon/)** com a proposta e o
pipeline explicado.

Todo o tráfego de ataque é simulado localmente. Não tem honeypot exposto pra internet
pública, então roda tranquilo na sua máquina pra aprender ou testar.

## Por onde começar

Se você só quer ver funcionando, pule pra
**[Como rodar na sua máquina](#como-rodar-na-sua-máquina)**: são cinco passos e, em
poucos minutos, o painel está no ar. Com ele de pé, o
**[primeiro tour pelo painel](#primeiro-tour-pelo-painel)** mostra o que cada tela
faz, e **[simular ataques](#simular-ataques)** te dá o que digitar pra ver o pipeline
reagir em tempo real.

Se prefere entender o sistema antes de rodar, siga na ordem: as seções abaixo
explicam cada parte e por que ela existe.

---

## O que é o Veryon, e por que ele existe

**SOC** (Security Operations Center) é o nome da "sala de controle" que times de
segurança usam pra vigiar uma rede em tempo real, onde ficam os alertas, os
dashboards, o histórico de eventos. **SIEM** (Security Information and Event
Management) é o tipo de software que torna essa sala possível: junta logs de fontes
diferentes, decide quando alguma coisa é suspeita e mostra isso de um jeito que dá
pra agir em cima.

O Veryon é a minha versão desse software, montada do zero. Em vez de ficar na teoria,
ele roda o pipeline inteiro de um SOC de verdade, do primeiro pacote de um ataque até
a resposta, e deixa você operar cada etapa pelo painel.

A regra que guiou o projeto: **nenhum botão morto**. Se a tela mostra "Bloquear", o
IP é bloqueado de verdade, em dois lugares diferentes da pilha. Se mostra "Desfazer",
o bloqueio sai e a política respeita a decisão. Se mostra um score, dá pra clicar e
ver as requisições que geraram aquele número.

---

## O que ele faz

### Recebe ataque de verdade

Um honeypot Cowrie (sistema-isca que só existe pra ser atacado) roda em rede
isolada, com SSH e Telnet abertos. Do lado, um Juice Shop, aplicação web
propositalmente vulnerável. Tudo que acontece neles vira evento no banco.

### Coleta log como um agente de produção

Coletores leves em Python leem o Event Log do Windows e o `auth.log` do Linux, do
mesmo jeito que um agente instalado num servidor faria, e mandam pro pipeline.

### Detecta com o padrão do mercado

O motor de detecção usa **Sigma**, o formato de regra mais usado da indústria,
validado com `pysigma`. Cada regra é mapeada pro **MITRE ATT&CK**, o dicionário
padrão pra descrever técnica de ataque: T1110 é sempre força bruta, não importa a
ferramenta que o atacante usou.

### Rastreia vulnerabilidade com ciclo de vida

Nmap e Nuclei varrem os serviços internos e o alvo vulnerável. O resultado não é uma
foto solta de cada varredura: cada achado tem assinatura estável, então a mesma
vulnerabilidade numa varredura seguinte **atualiza** em vez de virar linha nova. Se
alguém marcou como corrigida e ela volta, ela reabre sozinha e o contador
`reopened_count` sobe. Número alto ali quer dizer que estão fechando chamado sem
consertar.

Aceitar o risco exige justificativa escrita e data de revisão. A API recusa sem as
duas, porque risco aceito sem prazo é o jeito mais fácil de nunca corrigir nada.

### Analisa comportamento de API

O Veryon observa o próprio tráfego de API e também aceita log de acesso de fora, pelo
endpoint `POST /ingest/api-logs` com chave própria. Isso é o que permite apontar ele
pra API de um cliente.

Sobre esse tráfego roda um motor de oito sinais, cada um com peso:

| Sinal | Peso | O que é |
|---|---|---|
| Tentativa de injeção | 40 | SQLi, XSS, traversal, comando, template, NoSQL |
| Rajada de falha de autenticação | 30 | Muitas tentativas de login falhando da mesma origem |
| Varredura de rotas | 25 | Muitas rotas distintas, a maioria respondendo 404 |
| API fantasma respondendo | 25 | Rota que responde sem estar no inventário declarado |
| Acesso sequencial a objetos | 20 | `/users/1`, `/users/2`, `/users/3`… (BOLA/IDOR) |
| Volume de resposta fora do padrão | 20 | Resposta muito maior que o normal daquela rota |
| Acesso a endpoint sensível | 15 | Rota de credencial, usuário, exportação, administração |
| Método HTTP fora do esperado | 10 | TRACE, CONNECT, ou método que a rota não suporta |

A soma tem teto em 100. Acima de 70 vira alerta automático na tela de Alertas, com
técnica MITRE. Acima de 90 é caso pra prevenção tratar.

Dois detalhes que só aparecem quando se olha o dado real:

- A busca por injeção roda **na forma decodificada** também. Atacante que sabe o
  mínimo manda `%27%20OR`, e o padrão cru nunca casaria com isso.
- O sinal de volume compara contra a **mediana** das outras respostas da mesma rota,
  não contra a média. Média absorve o próprio pico: doze respostas de 1 KB com uma de
  900 KB no meio dão média de 76 KB, e aí o pico deixa de parecer pico.

### Previne com política, sem virar risco

Dez políticas de fábrica decidem o que o sistema pode fazer sozinho. Elas não são
uma linguagem de regra genérica: cada uma aponta pra um avaliador conhecido no
código, com parâmetros ajustáveis. Menos flexível de propósito, porque regra
genérica é o caminho mais curto pra alguém escrever sem querer algo que bloqueia o
parque inteiro.

**Toda política nasce em modo observação.** Nesse modo ela reconhece os casos e
registra o que teria feito, sem tocar em nada. Antes de ligar, a simulação mostra os
alvos de agora e quais seriam segurados.

Sete trilhos de segurança ficam **fora** do controle da política:

1. Política nasce observando; nenhuma age antes de alguém ligar na mão.
2. Allowlist ganha sempre, mesmo que a regra case perfeitamente.
3. Nunca bloqueia endereço privado, de loopback ou reservado.
4. Bloqueio automático sempre expira; política sem prazo não bloqueia.
5. Teto de 10 bloqueios automáticos por hora, somando todas as políticas.
6. Não registra o mesmo desfecho duas vezes no mesmo modo dentro da espera.
7. Toda ação aplicada é desfeita com um clique, e a política respeita o desfazer
   por uma hora em vez de reaplicar no ciclo seguinte.

O trilho 5 é o mais importante dos sete. Os outros impedem erro pontual; ele impede
que um erro sistemático vire incidente enquanto ninguém está olhando.

Tudo que a prevenção fez, simulou ou deixou de fazer vira linha na trilha de
auditoria, com o motivo e, quando foi segurada, qual trilho segurou.

### Bloqueia em dois lugares

Bloquear um IP no Veryon age em dois atuadores ao mesmo tempo:

- `iptables` dentro do namespace de rede do Cowrie, nas portas do honeypot.
- Um middleware ASGI no backend, que recusa a requisição antes dela chegar na rota.

Os dois leem a mesma condição no banco, e o script de enforcement usa exatamente a
mesma cláusula de expiração que a API. Sem isso, o botão "Bloquear" numa tela de
abuso de API não faria nada: o bloqueio antigo só valia pras portas do honeypot.

### Enriquece com reputação pública

IP suspeito é consultado no AbuseIPDB, VirusTotal e OTX, a mesma pergunta que um
analista faria: esse IP já foi visto fazendo coisa ruim em outro lugar?

---

## Arquitetura

```
Windows / Linux
│
├── Honeypot Cowrie ────────┐   (rede isolada, sem rota pro core)
├── Juice Shop ─────────────┤   (alvo vulnerável, rede isolada)
├── Coletores de log ───────┤   (Event Log do Windows, auth.log do Linux)
└── Scanner Nmap/Nuclei ────┘
                            ↓
                    raw_events (TimescaleDB)
                            │
      ┌─────────────────────┼─────────────────────┐
      ↓                     ↓                     ↓
  Detecção            Normalizador           Threat Intel
  (Sigma +            de vulnerabilidade     (AbuseIPDB,
   MITRE)             (ciclo de vida)         VirusTotal, OTX)
      │                     │                     │
      └─────────────────────┼─────────────────────┘
                            ↓
                  Backend / API (FastAPI + JWT)
                     │              │
   Análise de API ───┤              ├─── Prevenção de ameaça
   (8 sinais)        │              │    (10 políticas, 7 trilhos)
                     ↓              ↓
              Bloqueio em dois atuadores
              (iptables + middleware ASGI)
                            ↓
                    Painel React / Vite
```

---

## Como rodar na sua máquina

### 1. Pré-requisitos

Você precisa de **Docker** e **Node.js 20+**.

No Windows ou macOS, instale o
[Docker Desktop](https://www.docker.com/products/docker-desktop/), abra o app e
espere o ícone da baleia ficar "Running". No Linux (ou dentro do WSL2), o serviço
`docker` nativo via `systemd` funciona igual.

Confirme:

```bash
docker info
```

Se responder com informação do servidor em vez de erro de conexão, está pronto.

### 2. Clonar o repositório

```bash
git clone https://github.com/omatosz/veryon.git
```

```bash
cd veryon
```

### 3. Configurar o ambiente

O projeto vem com um `.env.example`. Copie pra `.env`:

```bash
cp .env.example .env
```

Abra o `.env` e preencha, no mínimo:

| Variável | Pra que serve |
|---|---|
| `POSTGRES_PASSWORD` | Senha do banco. Escolha qualquer uma. |
| `JWT_SECRET` | Segredo que assina o token de login. Gere um seu. |
| `ADMIN_PASSWORD` | Sua senha de acesso ao painel. |

Pra gerar o `JWT_SECRET`:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

**Opcionais**, o projeto sobe sem eles:

| Variável | Efeito de deixar vazio |
|---|---|
| `ABUSEIPDB_API_KEY` | Sem reputação real de IP. O resto funciona igual. |
| `VIRUSTOTAL_API_KEY` | Idem. |
| `OTX_API_KEY` | Idem. |
| `INGEST_API_KEY` | O endpoint de ingestão de log externo fica desligado e recusa tudo. |

As três primeiras têm conta gratuita em [AbuseIPDB](https://www.abuseipdb.com/),
[VirusTotal](https://www.virustotal.com/) e [OTX](https://otx.alienvault.com/).

O `.env` nunca vai pro controle de versão. Ele está no `.gitignore`.

### 4. Subir tudo

```bash
docker compose up -d --build
```

Isso sobe, em segundo plano: banco (PostgreSQL/TimescaleDB), Redis, a API, o
honeypot, o alvo vulnerável, os coletores, o motor de detecção, o scanner, o serviço
de threat intel e os dois atuadores de bloqueio. A primeira vez demora alguns
minutos porque builda as imagens.

Confirme que subiu:

```bash
curl http://localhost:8000/health
```

Resposta esperada, com `api`, `database` e `redis` em `ok`:

```json
{
  "api": "ok",
  "database": "ok",
  "redis": "ok",
  "blocklist": { "entries": 0, "loaded_at": "..." },
  "api_traffic": { "queued": 0, "dropped": 0 }
}
```

### 5. Subir o painel

Em outro terminal:

```bash
cd frontend
```

```bash
npm install
```

```bash
npm run dev
```

Abra `http://localhost:5173`.

### 6. Entrar

Usuário e senha são criados na primeira subida do backend, a partir de
`ADMIN_USERNAME` e `ADMIN_PASSWORD` do seu `.env`. O usuário padrão é `admin`.

### 7. Parar tudo

```bash
docker compose down
```

O painel para com `Ctrl+C` no terminal onde rodou `npm run dev`. Pra apagar também
os dados do banco, use `docker compose down -v`.

---

## Primeiro tour pelo painel

| Tela | O que tem |
|---|---|
| **Dashboard** | Visão geral. O gráfico de colunas filtra por tipo de alerta, e o filtro "Origem dos IPs" gira o cartão e revela o mapa-múndi. |
| **Alertas** | Fila de triagem. Filtra por severidade e status, abre o detalhe com o evento que disparou a regra, e muda o status. |
| **Eventos** | Feed bruto de tudo que foi ingerido, antes de qualquer regra rodar em cima. |
| **Vulnerabilidades** | Achados com ciclo de vida, score de risco do parque, e o botão que pede uma varredura na hora. |
| **Análise de API** | Chamadores pontuados pelos oito sinais, com as requisições que geraram cada score, e o inventário de rotas separando conhecida de fantasma. |
| **Prevenção** | Fila crítica das três origens juntas, as dez políticas com simulação, e a trilha de auditoria com desfazer. |
| **Threat Intel** | Consulta de reputação pública de um IP. |

---

## Simular ataques

Tem um guia completo em **[docs/ATAQUES.md](docs/ATAQUES.md)**, com o passo a passo
de cada ataque, qual terminal usar e o que esperar ver aparecer no painel.

O mais rápido pra confirmar que o pipeline inteiro funciona, um login no honeypot
SSH:

```bash
ssh -p 2222 -o StrictHostKeyChecking=no root@localhost
```

Digite qualquer senha (o honeypot aceita), e em poucos segundos um alerta **high**
aparece na tela de Alertas.

---

## Decisões técnicas que valem comentário

**Coleta de tráfego fora do caminho da requisição.** O middleware que observa a API
não escreve no banco: ele empilha num buffer em memória e o flusher grava em lote.
Sem isso, toda chamada pagaria um INSERT antes de responder, e a ferramenta de
observar viraria o gargalo do observado. A fila é limitada; se encher, a amostra
mais nova é descartada em vez de segurar a requisição do usuário.

**Middleware ASGI puro em vez de `BaseHTTPMiddleware`.** O do Starlette monta um par
de streams por requisição, e essas checagens rodam em todas elas. Em ASGI puro o
custo é uma busca em set na memória.

**Ordem de middleware é carregada.** O bloqueio fica por dentro do CORS de propósito:
por fora, o 403 sairia sem cabeçalho CORS e o navegador mostraria erro de CORS no
lugar do motivo real. Já o coletor de tráfego fica por fora do bloqueio e do
limitador de taxa, pra registrar também a requisição que levou 403 e a que levou 429.
Tentativa recusada é justamente o que interessa numa investigação.

**Savepoint por política no motor de prevenção.** Capturar a exceção em Python não
basta: consulta que falha aborta a transação do Postgres, e daí toda política
seguinte quebra em cascata. Sem o savepoint, uma regra com defeito derrubaria o motor
inteiro em silêncio, logando aviso sobre uma só. Pra ferramenta de segurança esse é o
pior tipo de falha: o sistema parece vivo e não faz nada.

**Retrato imutável da blocklist.** Uma tarefa recarrega a lista do banco a cada
poucos segundos e troca o retrato inteiro de uma vez, então quem está lendo no meio
do caminho sempre vê estado coerente. Se o banco piscar, o retrato anterior é
mantido: é melhor bloquear a mais do que abrir a porta porque uma consulta falhou.

**Deduplicação por `(ativo, assinatura)`.** A assinatura de uma porta aberta exclui a
versão do serviço de propósito. Assim, atualizar o Postgres muda o título do achado
existente em vez de criar um novo e deixar o antigo órfão.

**`FOR UPDATE SKIP LOCKED` na fila de varredura.** Garante que dois scanners nunca
peguem o mesmo trabalho, mesmo se alguém subir uma segunda réplica.

---

## Isolamento das redes de risco

Duas redes rodam código que não se confia: `honeypot_net` (Cowrie) e `target_net`
(Juice Shop). Nenhuma das duas tem rota pra rede `core`, onde ficam backend, banco e
Redis. O tráfego de saída do honeypot é bloqueado por regra de firewall, então um
atacante que "escape" pra dentro do container não consegue usar ele pra alcançar
outra coisa.

---

## Estrutura do repositório

```
backend/
  app/api/          Rotas REST (auth, eventos, alertas, vulnerabilidades,
                    análise de API, prevenção, ingestão, blocklist, stats)
  app/core/         Motores: sinais de API, analisador, prevenção, blocklist
  app/middleware/   Bloqueio de IP e coleta de tráfego, ambos ASGI puro
  migrations/       Alembic
collector/          Coletor do Cowrie (honeypot → raw_events)
collectors/         Coletores de log de SO: Linux e Windows
detection/          Regras Sigma + motor de avaliação
enforcement/        Bloqueio via iptables no namespace do honeypot
scanner/            Nmap + Nuclei, e o normalizador de ciclo de vida
threatintel/        Enriquecimento de IP
reports/            Relatório SOC em HTML/PDF
frontend/           Painel React/Vite
landing/            Landing page, publicada via GitHub Pages
infra/              Init do Postgres e regra de firewall
docs/               Guias
```

---

## Segurança do próprio repositório

Nenhuma credencial, chave de API ou dado de acesso vai pro controle de versão. O
`.env` fica no `.gitignore`; só o `.env.example`, com os campos vazios, é versionado.

Uma ressalva que vale registrar: o Cowrie grava em texto claro tudo que é digitado
numa sessão do honeypot, senha inclusive. Por isso os testes do honeypot pedem senha
descartável, nunca uma senha real de outro serviço, que acabaria gravada no log do
container.

---

## Roadmap

- [x] Fundamentos e ambiente
- [x] Honeypot e ingestão bruta
- [x] Coleta de log de Windows e Linux
- [x] Scanner de vulnerabilidades
- [x] Detecção e alertas com Sigma + MITRE
- [x] Threat Intel
- [x] Backend/API consolidado
- [x] Relatórios
- [x] Painel web
- [x] Bloqueio de IP em dois atuadores, com prazo e allowlist
- [x] Vulnerabilidades com ciclo de vida e fila de varredura
- [x] Análise de comportamento de API e ingestão de log externo
- [x] Prevenção de ameaça com política, simulação e trilha de auditoria
- [x] Gráfico interativo e mapa de origem dos IPs
- [ ] Relatórios como rota de API, não script
- [ ] Multi-tenant, pra apontar num cliente por vez

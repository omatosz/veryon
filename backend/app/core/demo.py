"""
Orquestrador da demonstracao de um clique.

Dispara em sequencia os mesmos ataques que docs/ATAQUES.md manda fazer na
mao: login e forca bruta no honeypot, injecao e varredura de rotas contra a
propria API, ingestao externa com fusao de ator, e por ultimo a reacao
administrativa (ligar a politica SSH-BRUTE em vigor) que so faz sentido
depois de existir alerta pra reagir.

So chega a rodar com DEMO_MODE_ENABLED=true (ver app/api/demo.py, que
devolve 404 com a flag desligada). Marcar como corrigida uma vulnerabilidade
fica de fora de proposito: a varredura leva de dezenas de segundos a poucos
minutos pra terminar, e esperar ela pra reagir tornaria o "um clique" em "um
clique e uma espera", contra o proprio pedido de demonstracao rapida. A
varredura e disparada aqui mesmo assim, bem no inicio, pra ter achado fresco
quando o analista chegar nessa tela mais tarde.

Cada fase roda isolada no seu try/except: uma falha no honeypot nao pode
zerar a parte de API, e vice-versa. Ao vivo, na frente de alguem, um tropeco
num passo nao pode derrubar a demonstracao inteira.
"""

import asyncio
import logging
import random
import string

import asyncssh
import httpx
from sqlalchemy import select

from app.core.config import settings
from app.db.models import PreventionPolicy
from app.db.session import async_session

log = logging.getLogger("veryon.demo")

# Mesmo truque do scanner pra alcancar o Juice Shop: o backend fica de fora
# das redes honeypot_net e target_net de proposito (isolamento documentado no
# README), entao alcanca o Cowrie pela porta publicada no host, via gateway,
# em vez de entrar na rede que nao confia.
COWRIE_HOST = "host.docker.internal"
COWRIE_SSH_PORT = 2222

# A mesma senha que o guia de ataques usa pra forca bruta: o Cowrie a recusa
# de proposito pro usuario root, entao garante falha sem depender de sorte.
SENHA_RECUSADA_PELO_COWRIE = "123456"

BASE_URL = "http://127.0.0.1:8000"

# Tempo pro motor de deteccao (ciclo de 10s) e o analisador de API (mesmo
# ciclo) processarem o que a demonstracao acabou de gerar, antes da fase de
# reacao tentar bloquear ou ligar politica em cima de nada.
ESPERA_ANTES_DE_REAGIR_SEGUNDOS = 12

_em_andamento = False


def em_andamento() -> bool:
    return _em_andamento


def _senha_descartavel() -> str:
    return "".join(random.choices(string.ascii_letters + string.digits, k=12))


async def _login_honeypot_sucesso() -> None:
    async with asyncssh.connect(
        COWRIE_HOST,
        port=COWRIE_SSH_PORT,
        username="root",
        password=_senha_descartavel(),
        known_hosts=None,
    ) as conn:
        await conn.run("whoami; id; cat /etc/passwd", check=False)
    log.info("demo: login no honeypot concluido")


async def _forca_bruta_honeypot(tentativas: int = 6) -> None:
    falhas = 0
    for _ in range(tentativas):
        try:
            async with asyncssh.connect(
                COWRIE_HOST,
                port=COWRIE_SSH_PORT,
                username="root",
                password=SENHA_RECUSADA_PELO_COWRIE,
                known_hosts=None,
            ):
                pass
        except asyncssh.PermissionDenied:
            falhas += 1
    log.info("demo: forca bruta no honeypot, %d/%d falhas", falhas, tentativas)


async def _varredura_de_vulnerabilidade(client: httpx.AsyncClient) -> None:
    resp = await client.post("/scans")
    if resp.status_code == 202:
        log.info("demo: varredura de vulnerabilidade enfileirada")
    elif resp.status_code == 409:
        log.info("demo: varredura ja em andamento, seguindo sem enfileirar outra")
    else:
        log.warning("demo: nao deu pra enfileirar varredura (%s): %s", resp.status_code, resp.text)


async def _injecao_e_varredura_de_rotas(client: httpx.AsyncClient) -> None:
    # Injecao: os tres padroes da secao 5 do guia.
    await client.get("/events", params={"source": "' OR 1=1--"})
    await client.get("/alerts", params={"status": "<script>alert(1)</script>"})
    await client.get("/vulnerabilities", params={"asset_type": "../../../../etc/passwd"})

    # Varredura de rotas, secao 6: a maioria vira 404.
    for i in range(1, 26):
        await client.get(f"/admin/painel-secreto-{i}")

    # Rajada de falha de autenticacao, mesma secao. 401 ou 429 do limitador de
    # taxa contam igual pro sinal de auth_burst.
    for i in range(1, 16):
        await client.post(
            "/auth/login",
            data={"username": "admin", "password": f"errada{i}", "website": ""},
        )
    log.info("demo: injecao e varredura de rotas contra a propria API")


async def _ingestao_externa_com_ator(client: httpx.AsyncClient) -> None:
    """IDOR simulado, secao 7 do guia, em dois IPs com a mesma assinatura de
    cabecalho. E o que falta pro rastreamento de ator fundir os dois num
    perfil so: sem headers/user_agent repetidos, cada IP fica sozinho."""
    if not settings.ingest_api_key:
        log.info("demo: ingestao externa pulada, INGEST_API_KEY vazia no .env")
        return

    assinatura = ["Host", "User-Agent", "Accept", "Accept-Encoding", "X-Forwarded-For"]
    agente = "python-requests/2.31 (varredor-generico)"

    for ip in ("203.0.113.77", "198.51.100.42"):
        lote = {
            "requests": [
                {
                    "method": "GET",
                    "path": f"/api/v1/customers/{n}",
                    "status_code": 200,
                    "client_ip": ip,
                    "response_bytes": 1200,
                    "headers": assinatura,
                    "user_agent": agente,
                }
                for n in range(1, 9)
            ]
        }
        resp = await client.post(
            "/ingest/api-logs",
            json=lote,
            headers={"X-Veryon-Key": settings.ingest_api_key},
        )
        if resp.status_code >= 300:
            log.warning("demo: ingestao pro IP %s recusada (%s)", ip, resp.status_code)

    log.info("demo: ingestao externa em dois IPs com a mesma assinatura")


async def _reacoes_administrativas(client: httpx.AsyncClient) -> None:
    """Liga a politica SSH-BRUTE em vigor, pro motor de prevencao reagir por
    conta propria no ciclo seguinte (a cada 15s).

    De proposito NAO chama o bloqueio manual por alerta. O IP de origem, aqui,
    e sempre o gateway da rede Docker (172.28.0.1): e o mesmo caminho que
    QUALQUER conexao usa pra entrar no honeypot publicado, inclusive um SSH
    manual do Leandro. O bloqueio manual (`/alerts/{id}/block`) nao tem a
    trava de IP incerto, que existe so na avaliacao automatica da politica; se
    esta funcao chamasse ele, a demonstracao trancaria o honeypot pra todo
    mundo pelo TTL inteiro, ela mesma incluida na proxima rodada.

    A politica em vigor, por outro lado, e segura: o avaliador automatico
    recusa bloquear IP incerto e a trilha de acoes mostra 'held' em vez de
    'applied'. E o motor funcionando como deveria, nao um defeito."""
    await asyncio.sleep(ESPERA_ANTES_DE_REAGIR_SEGUNDOS)

    async with async_session() as db:
        politica = (
            await db.execute(select(PreventionPolicy).where(PreventionPolicy.code == "SSH-BRUTE"))
        ).scalars().first()

    if politica is None:
        log.warning("demo: politica SSH-BRUTE nao encontrada no banco")
        return

    resp = await client.patch(
        f"/prevention/policies/{politica.id}",
        json={"mode": "enforce", "ttl_minutes": 60},
    )
    if resp.status_code < 300:
        log.info("demo: politica SSH-BRUTE em vigor, avaliacao automatica no proximo ciclo")
    else:
        log.info("demo: nao deu pra ligar a politica SSH-BRUTE (%s)", resp.status_code)


async def run_full_demo(token: str) -> None:
    """Roda a sequencia inteira em segundo plano. Quem chamou ja recebeu a
    resposta HTTP antes desta funcao terminar."""
    global _em_andamento
    _em_andamento = True
    resumo = {"varredura": False, "honeypot": False, "api": False, "ingestao": False, "reacao": False}
    try:
        async with httpx.AsyncClient(
            base_url=BASE_URL,
            headers={"Authorization": f"Bearer {token}"},
            timeout=10.0,
        ) as client:
            try:
                await _varredura_de_vulnerabilidade(client)
                resumo["varredura"] = True
            except Exception as exc:  # noqa: BLE001
                log.warning("demo: fase da varredura falhou: %s", exc)

            try:
                await _login_honeypot_sucesso()
                await _forca_bruta_honeypot()
                resumo["honeypot"] = True
            except Exception as exc:  # noqa: BLE001
                log.warning("demo: fase do honeypot falhou: %s", exc)

            try:
                await _injecao_e_varredura_de_rotas(client)
                resumo["api"] = True
            except Exception as exc:  # noqa: BLE001
                log.warning("demo: fase da API falhou: %s", exc)

            try:
                await _ingestao_externa_com_ator(client)
                resumo["ingestao"] = True
            except Exception as exc:  # noqa: BLE001
                log.warning("demo: fase de ingestao falhou: %s", exc)

            try:
                await _reacoes_administrativas(client)
                resumo["reacao"] = True
            except Exception as exc:  # noqa: BLE001
                log.warning("demo: fase de reacao falhou: %s", exc)

        log.info("demo completa: %s", resumo)
    finally:
        _em_andamento = False

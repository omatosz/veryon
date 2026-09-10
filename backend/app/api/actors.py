"""Perfil do ator: quem esta atacando quando o IP nao serve mais de identidade.

Etapa 2 do rastreamento. A Etapa 1 montou a identidade e ninguem conseguia
ve-la: os atores existiam so no banco, e a unica forma de olhar era abrir psql.

Tres camadas, de fora para dentro, e a ordem e proposital:

  resumo     o que fazer com isto, em uma frase.
  timeline   o que este ator fez, em ordem, juntando honeypot, API e resposta.
  evidencia  por que o Veryon acha que sao a mesma pessoa. Ou melhor: a mesma
             ferramenta, que e o que ele de fato afirma.

## Semaforo no lugar do score cru

A lista nao mostra "score 82". Score cru transfere a decisao para quem esta
lendo, e as tres da manha ninguem sabe se 82 e muito. Cada ator sai com uma
acao recomendada e o motivo dela em portugues.

A confianca tem poder de veto sobre a acao. Um ator de confianca baixa nunca
recomenda bloqueio, por pior que seja a pontuacao: confianca baixa quer dizer
que a juncao dos IPs e fraca, e bloquear com base nela e bloquear inocente.

## O que este modulo nunca diz

Nao existe "mesma pessoa" em lugar nenhum do texto. O rastreamento afirma mesma
ferramenta com o mesmo padrao de uso, e a diferenca entre as duas frases e a
unica coisa que mantem esta funcionalidade honesta.
"""

from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.blocklist import guard_target
from app.api.deps import current_username, get_current_user, require_admin
from app.core import blocklist as blocklist_cache
from app.db.session import get_db

router = APIRouter(
    prefix="/actors",
    tags=["actors"],
    dependencies=[Depends(get_current_user)],
)

# A partir daqui a pontuacao do achado e considerada grave. E o mesmo corte que
# o motor de prevencao usa para fila critica, e ter dois numeros diferentes para
# a mesma ideia seria a forma mais facil de os dois discordarem em producao.
SCORE_GRAVE = 70

CONFIANCA_EM_PORTUGUES = {"high": "alta", "medium": "media", "low": "baixa"}


class Decisao(BaseModel):
    # 'bloquear' | 'investigar' | 'observar'. A tela pinta a partir daqui, e
    # nao a partir do score, para que a regra viva num lugar so.
    acao: str
    # Frase pronta, em portugues, dizendo por que essa acao e nao outra.
    porque: str


class AtorResumo(BaseModel):
    ref: str
    confidence: str
    distinctiveness: float
    ip_count: int
    request_count: int
    max_score: int
    status: str
    first_seen: datetime
    last_seen: datetime
    note: str | None = None
    agente: str | None = None
    decisao: Decisao


class AtorIP(BaseModel):
    client_ip: str
    first_seen: datetime
    last_seen: datetime
    request_count: int
    # Com quanta semelhanca este IP entrou no ator, e a quebra por traco. Existe
    # para o analista discordar com dado na mao.
    similarity: float
    match_detail: dict[str, Any] | None = None
    manual: bool
    bloqueado: bool


class AtorDetalhe(AtorResumo):
    traits: dict[str, Any]
    ips: list[AtorIP]


class EventoDaLinha(BaseModel):
    ts: datetime
    # 'honeypot' | 'alerta' | 'api' | 'resposta'
    fonte: str
    titulo: str
    detalhe: str | None = None
    nivel: str | None = None
    ip: str | None = None


class AtorUpdate(BaseModel):
    note: str | None = Field(default=None, max_length=2000)
    status: Literal["active", "dormant", "archived"] | None = None


def decidir(ator: dict[str, Any]) -> Decisao:
    """Traduz confianca mais gravidade em uma acao e o motivo dela.

    A confianca vem primeiro na ordem das perguntas, e nao a gravidade, porque
    ela e quem pode vetar. Um ator gravissimo com juncao fraca nao vira
    bloqueio, vira investigacao: o erro de bloquear a juncao errada cai em cima
    de quem nao fez nada.
    """
    conf = ator.get("confidence") or "low"
    score = int(ator.get("max_score") or 0)
    ips = int(ator.get("ip_count") or 1)
    grave = score >= SCORE_GRAVE

    if conf == "high" and grave:
        alcance = f"os {ips} IPs" if ips > 1 else "o IP"
        return Decisao(
            acao="bloquear",
            porque=(
                f"Mesmo padrao confirmado com confianca alta e pontuacao {score}. "
                f"Bloquear {alcance} de uma vez fecha a porta que trocar de endereco abriria."
            ),
        )

    if grave:
        return Decisao(
            acao="investigar",
            porque=(
                f"Comportamento grave, pontuacao {score}, mas a juncao dos enderecos tem "
                f"confianca {CONFIANCA_EM_PORTUGUES.get(conf, conf)}. Olhe a evidencia antes "
                "de bloquear: bloquear juncao fraca acerta quem nao fez nada."
            ),
        )

    if conf == "high" and ips > 1:
        return Decisao(
            acao="investigar",
            porque=(
                f"A mesma ferramenta apareceu de {ips} enderecos diferentes. Ainda nao fez "
                "nada grave, e trocar de IP sem motivo ja e o motivo."
            ),
        )

    return Decisao(
        acao="observar",
        porque=(
            f"Pontuacao {score} e confianca {CONFIANCA_EM_PORTUGUES.get(conf, conf)}. "
            "Nada aqui pede acao agora."
        ),
    )


SELECT_BASE = """
    SELECT id, ref, traits, confidence, distinctiveness, ip_count, request_count,
           max_score, status, first_seen, last_seen, note
      FROM actors
"""


def _resumo(linha: dict[str, Any]) -> dict[str, Any]:
    traits = linha.get("traits") or {}
    return {
        **{k: v for k, v in linha.items() if k not in ("id", "traits")},
        "agente": traits.get("agente"),
        "decisao": decidir(linha),
    }


@router.get("", response_model=list[AtorResumo])
async def listar(
    status_filtro: str | None = Query(None, alias="status"),
    acao: str | None = Query(None, description="bloquear, investigar ou observar"),
    limit: int = Query(100, le=500),
    db: AsyncSession = Depends(get_db),
):
    """Os atores conhecidos, do que mais pede acao para o que menos pede.

    A ordem e por pontuacao e nao por data: quem fez a pior coisa aparece em
    cima, mesmo que tenha aparecido ontem. Lista de trabalho, nao diario.
    """
    sql = SELECT_BASE
    params: dict[str, Any] = {"limit": limit}
    if status_filtro:
        sql += " WHERE status = :status"
        params["status"] = status_filtro
    sql += " ORDER BY max_score DESC, last_seen DESC LIMIT :limit"

    linhas = [_resumo(dict(l)) for l in (await db.execute(text(sql), params)).mappings()]

    # O filtro por acao acontece aqui e nao no SQL porque a acao nasce de uma
    # regra em Python. Repeti-la em SQL criaria duas versoes da mesma decisao,
    # e elas divergiriam na primeira vez que alguem mexesse em uma so.
    if acao:
        linhas = [l for l in linhas if l["decisao"].acao == acao]
    return linhas


async def _buscar(db: AsyncSession, ref: str) -> dict[str, Any]:
    linha = (
        await db.execute(text(SELECT_BASE + " WHERE ref = :ref"), {"ref": ref})
    ).mappings().first()
    if linha is None:
        raise HTTPException(status_code=404, detail="Ator nao encontrado")
    return dict(linha)


SELECT_IPS = text(
    """
    SELECT ai.client_ip, ai.first_seen, ai.last_seen, ai.request_count,
           ai.similarity, ai.match_detail, ai.manual,
           EXISTS (
               SELECT 1 FROM blocked_ips b
                WHERE b.ip = ai.client_ip AND b.unblocked_at IS NULL
           ) AS bloqueado
      FROM actor_ips ai
     WHERE ai.actor_id = :ator
     ORDER BY ai.last_seen DESC
    """
)


@router.get("/{ref}", response_model=AtorDetalhe)
async def detalhe(ref: str, db: AsyncSession = Depends(get_db)):
    ator = await _buscar(db, ref)
    ips = [dict(l) for l in (await db.execute(SELECT_IPS, {"ator": ator["id"]})).mappings()]
    return {**_resumo(ator), "traits": ator.get("traits") or {}, "ips": ips}


# Quatro consultas em vez de uma UNION gigante: cada fonte tem coluna e
# significado proprios, e uma UNION obrigaria a achatar tudo em texto no SQL.
# Ordenar quatro listas pequenas em Python custa nada e deixa cada consulta
# legivel sozinha.
TIMELINE_HONEYPOT = text(
    """
    SELECT ts, event_type, src_ip, payload
      FROM raw_events
     WHERE src_ip = ANY(:ips) AND ts >= now() - make_interval(days => :dias)
     ORDER BY ts DESC LIMIT :cap
    """
)

TIMELINE_ALERTAS = text(
    """
    SELECT ts, title, level, rule_id, source_ip, status
      FROM alerts
     WHERE source_ip = ANY(:ips) AND ts >= now() - make_interval(days => :dias)
     ORDER BY ts DESC LIMIT :cap
    """
)

TIMELINE_API = text(
    """
    SELECT last_seen AS ts, client_ip, score, severity, signals, status
      FROM api_findings
     WHERE client_ip = ANY(:ips) AND last_seen >= now() - make_interval(days => :dias)
     ORDER BY last_seen DESC LIMIT :cap
    """
)

TIMELINE_RESPOSTA = text(
    """
    -- Cada ramo entre parenteses: ORDER BY solto no primeiro SELECT de uma
    -- UNION e erro de sintaxe, o Postgres le como ordem do conjunto inteiro.
    (
      SELECT ts, action_type, target, reason, mode, status
        FROM prevention_actions
       WHERE target = ANY(:ips) AND ts >= now() - make_interval(days => :dias)
       ORDER BY ts DESC LIMIT :cap
    )
    UNION ALL
    (
      SELECT blocked_at AS ts, 'block' AS action_type, ip AS target,
             COALESCE(reason, 'sem motivo registrado') AS reason,
             source AS mode, 'applied' AS status
        FROM blocked_ips
       WHERE ip = ANY(:ips) AND blocked_at >= now() - make_interval(days => :dias)
       ORDER BY blocked_at DESC LIMIT :cap
    )
    """
)


@router.get("/{ref}/timeline", response_model=list[EventoDaLinha])
async def timeline(
    ref: str,
    dias: int = Query(30, ge=1, le=365),
    limit: int = Query(200, le=500),
    db: AsyncSession = Depends(get_db),
):
    """O que este ator fez, em ordem, juntando as quatro fontes.

    O valor esta na juncao. Cada tela do Veryon ja mostra a sua parte, e e
    exatamente por isso que ninguem enxerga a historia: o honeypot conta um
    pedaco, a analise de API conta outro, e a resposta conta o final. Aqui os
    tres viram uma linha so, e a ordem revela o que nenhuma das telas mostra
    sozinha, que e a sequencia.
    """
    ator = await _buscar(db, ref)
    ips = [
        l["client_ip"]
        for l in (await db.execute(SELECT_IPS, {"ator": ator["id"]})).mappings()
    ]
    if not ips:
        return []

    p = {"ips": ips, "dias": dias, "cap": limit}
    eventos: list[dict[str, Any]] = []

    for linha in (await db.execute((TIMELINE_HONEYPOT), p)).mappings():
        carga = linha["payload"] or {}
        detalhe = carga.get("input") or carga.get("message") or carga.get("username")
        eventos.append(
            {
                "ts": linha["ts"],
                "fonte": "honeypot",
                "titulo": linha["event_type"],
                "detalhe": str(detalhe)[:300] if detalhe else None,
                "nivel": None,
                "ip": linha["src_ip"],
            }
        )

    for linha in (await db.execute((TIMELINE_ALERTAS), p)).mappings():
        eventos.append(
            {
                "ts": linha["ts"],
                "fonte": "alerta",
                "titulo": linha["title"],
                "detalhe": f"{linha['rule_id']} · {linha['status']}",
                "nivel": linha["level"],
                "ip": linha["source_ip"],
            }
        )

    for linha in (await db.execute((TIMELINE_API), p)).mappings():
        sinais = linha["signals"] or []
        nomes = ", ".join(s.get("label", s.get("id", "?")) for s in sinais[:4])
        eventos.append(
            {
                "ts": linha["ts"],
                "fonte": "api",
                "titulo": f"Achado de API, pontuacao {linha['score']}",
                "detalhe": nomes or None,
                "nivel": linha["severity"],
                "ip": linha["client_ip"],
            }
        )

    for linha in (await db.execute((TIMELINE_RESPOSTA), p)).mappings():
        eventos.append(
            {
                "ts": linha["ts"],
                "fonte": "resposta",
                "titulo": f"{linha['action_type']} ({linha['mode']})",
                "detalhe": linha["reason"],
                "nivel": None,
                "ip": linha["target"],
            }
        )

    eventos.sort(key=lambda e: e["ts"], reverse=True)
    return eventos[:limit]


@router.patch("/{ref}", response_model=AtorResumo)
async def atualizar(
    ref: str,
    body: AtorUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: str = Depends(current_username),
):
    """Nota e situacao do ator. E triagem, entao analista faz."""
    ator = await _buscar(db, ref)
    campos = body.model_dump(exclude_unset=True)
    if not campos:
        return _resumo(ator)

    sets = ", ".join(f"{c} = :{c}" for c in campos)
    await db.execute(
        text(f"UPDATE actors SET {sets}, updated_by = :quem WHERE id = :id"),
        {**campos, "quem": current_user, "id": ator["id"]},
    )
    await db.commit()
    return _resumo(await _buscar(db, ref))


@router.post("/{ref}/ips/{ip}/detach", status_code=204)
async def separar_ip(
    ref: str,
    ip: str,
    db: AsyncSession = Depends(get_db),
):
    """Tira um IP do ator porque o analista discordou da juncao.

    O vinculo e apagado e nao remarcado, mas a ideia e a mesma do desfazer da
    prevencao: automacao nao pode desfazer decisao humana no ciclo seguinte. Por
    isso o IP volta para actor_ips na proxima passada apenas se voltar a bater,
    e quando volta ele entra com manual ligado, o que congela o laco naquele
    vinculo.

    Analista pode fazer: e discordar de uma inferencia, nao mudar o
    comportamento do sistema. Separar errado nao machuca ninguem, e nao poder
    corrigir a maquina, sim.
    """
    ator = await _buscar(db, ref)
    resultado = await db.execute(
        text(
            "UPDATE actor_ips SET manual = true, actor_id = NULL "
            "WHERE actor_id = :ator AND client_ip = :ip"
        ),
        {"ator": ator["id"], "ip": ip},
    )
    if not resultado.rowcount:
        await db.rollback()
        raise HTTPException(status_code=404, detail="Esse IP nao esta neste ator")
    await db.commit()


@router.post("/{ref}/block", dependencies=[Depends(require_admin)])
async def bloquear_ator(
    ref: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: str = Depends(current_username),
) -> dict[str, Any]:
    """Bloqueia de uma vez todos os IPs deste ator.

    E a razao de o rastreamento existir. Bloquear um IP por vez perde a corrida
    contra quem troca de endereco de graca; bloquear o ator fecha as portas que
    ele ja mostrou que tem.

    Restrito a admin, como todo bloqueio. E confere a decisao antes: se o
    proprio Veryon nao recomenda bloquear, recusa e diz por que. Um botao que
    bloqueia oito enderecos com base numa juncao de confianca baixa e a forma
    mais rapida de derrubar cliente inocente.
    """
    ator = await _buscar(db, ref)
    decisao = decidir(ator)
    if decisao.acao != "bloquear":
        raise HTTPException(
            status_code=422,
            detail=f"O Veryon nao recomenda bloquear este ator. {decisao.porque}",
        )

    ips = [
        l["client_ip"]
        for l in (await db.execute(SELECT_IPS, {"ator": ator["id"]})).mappings()
        if not l["bloqueado"]
    ]
    if not ips:
        return {"bloqueados": [], "detalhe": "Todos os IPs deste ator ja estao bloqueados"}

    bloqueados: list[str] = []
    recusados: list[dict[str, str]] = []
    for ip in ips:
        # Passa pelo mesmo guarda do bloqueio manual: allowlist e IP proprio
        # continuam valendo. Bloqueio em lote nao pode ser um atalho por fora
        # das protecoes que existem justamente para o bloqueio.
        try:
            alvo = await guard_target(request, db, ip)
        except HTTPException as exc:
            # Recusa individual nao derruba o lote. Um IP na allowlist no meio
            # de oito nao pode impedir os outros sete de serem bloqueados, e
            # quem chamou precisa saber quais ficaram de fora e por que.
            recusados.append({"ip": ip, "motivo": str(exc.detail)})
            continue

        await db.execute(
            text(
                "INSERT INTO blocked_ips (ip, reason, blocked_by, source) "
                "VALUES (:ip, :motivo, :quem, 'actor')"
            ),
            {
                "ip": alvo,
                "motivo": f"Ator {ref}: {decisao.porque}",
                "quem": current_user,
            },
        )
        bloqueados.append(alvo)

    await db.commit()
    if bloqueados:
        await blocklist_cache.refresh()

    return {"bloqueados": bloqueados, "recusados": recusados}

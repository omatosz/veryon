"""
Cadastro de canais de notificacao e visao da fila.

Sem isto, configurar para onde um alerta vai exige INSERT na mao no banco, o
que serve para o dono do projeto e para mais ninguem.

O endpoint que mais importa aqui e o POST /notifications/channels/{id}/test.
Ele manda uma mensagem na hora, fora da fila e fora do teto por hora. E a
diferenca entre descobrir que a URL do webhook esta errada agora, com a tela
aberta, ou as tres da manha, quando o alerta de verdade nao chegou.

NOTA DE ESTRUTURA: os schemas ficam neste arquivo e as consultas usam text()
em vez do ORM, contrariando o padrao dos outros routers, que declaram modelo
em db/models.py e schema em schemas.py. Motivo: os dois arquivos tem alteracao
nao commitada do rastreamento de ator, e misturar as duas frentes num mesmo
diff impediria separa-las depois. Quando aquela frente for resolvida, mover os
modelos e schemas daqui para os arquivos de sempre e trabalho mecanico.
"""

import re
from datetime import datetime
from typing import Any, Literal

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, ValidationError, field_validator
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, require_admin
from app.core import notifier, notify_adapters
from app.core.config import settings
from app.db.session import get_db

router = APIRouter(
    prefix="/notifications",
    tags=["notifications"],
    dependencies=[Depends(get_current_user)],
)

TIPOS = ("discord", "slack", "teams", "generic", "email")
NIVEIS = tuple(notify_adapters.NIVEIS)

# Frouxo de proposito: valida o formato, nao a existencia. Endereco que existe
# mas esta errado so aparece no teste de envio, e e para isso que o teste
# existe.
RE_EMAIL = re.compile(r"^[^@\s,]+@[^@\s,]+\.[^@\s,]+$")


class CanalIn(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    kind: Literal["discord", "slack", "teams", "generic", "email"]
    target: str = Field(min_length=1)
    # Abaixo disto o alerta nem aparece neste canal.
    min_level: Literal["informational", "low", "medium", "high", "critical"] = "high"
    # A partir daqui o alerta interrompe: sai sozinho, na proxima entrega. O que
    # fica entre min_level e este espera o resumo. Igualar os dois significa
    # "me interrompa com tudo que eu aceito receber".
    immediate_level: Literal["informational", "low", "medium", "high", "critical"] = "critical"
    # Quando o IP de origem pertence a um ator conhecido, a mensagem agrupa
    # por ator em vez de por IP. Ligado por padrao: sem ator conhecido a chave
    # continua sendo regra mais IP, entao nao ha caso em que ligar isto piore.
    group_by_actor: bool = True
    # Nasce desligado, igual toda politica de prevencao nasce em observacao.
    # Quem cadastra um canal ainda nao testou o endereco.
    enabled: bool = False

    @field_validator("target")
    @classmethod
    def valida_target(cls, v: str, info) -> str:
        kind = info.data.get("kind")
        v = v.strip()

        if kind == "email":
            destinos = [d.strip() for d in v.split(",") if d.strip()]
            if not destinos:
                raise ValueError("informe ao menos um destinatario")
            ruins = [d for d in destinos if not RE_EMAIL.match(d)]
            if ruins:
                raise ValueError(f"endereco de e-mail invalido: {', '.join(ruins)}")
            return ", ".join(destinos)

        if not v.startswith(("http://", "https://")):
            raise ValueError("webhook precisa comecar com http:// ou https://")
        return v


class CanalUpdate(BaseModel):
    """Tudo opcional: manda so o que muda."""

    name: str | None = Field(default=None, min_length=1, max_length=80)
    target: str | None = None
    min_level: Literal["informational", "low", "medium", "high", "critical"] | None = None
    immediate_level: Literal["informational", "low", "medium", "high", "critical"] | None = None
    group_by_actor: bool | None = None
    enabled: bool | None = None


class CanalOut(BaseModel):
    id: int
    name: str
    kind: str
    target: str
    min_level: str
    immediate_level: str
    group_by_actor: bool
    enabled: bool
    last_digest_at: datetime | None = None


class ResultadoTeste(BaseModel):
    ok: bool
    detalhe: str


SELECT_CANAIS = text(
    "SELECT id, name, kind, target, min_level, immediate_level, group_by_actor, enabled, last_digest_at "
    "FROM notification_channels ORDER BY name"
)

SELECT_CANAL = text(
    "SELECT id, name, kind, target, min_level, immediate_level, group_by_actor, enabled, last_digest_at "
    "FROM notification_channels WHERE id = :id"
)

INSERT_CANAL = text(
    """
    INSERT INTO notification_channels
        (name, kind, target, min_level, immediate_level, group_by_actor, enabled)
    VALUES (:name, :kind, :target, :min_level, :immediate_level, :group_by_actor, :enabled)
    RETURNING id, name, kind, target, min_level, immediate_level, group_by_actor,
              enabled, last_digest_at
    """
)


async def _busca_canal(db: AsyncSession, canal_id: int) -> dict[str, Any]:
    linha = (await db.execute(SELECT_CANAL, {"id": canal_id})).mappings().first()
    if linha is None:
        raise HTTPException(status_code=404, detail="Canal nao encontrado")
    return dict(linha)


@router.get("/channels", response_model=list[CanalOut])
async def listar_canais(db: AsyncSession = Depends(get_db)):
    return [dict(l) for l in (await db.execute(SELECT_CANAIS)).mappings()]


@router.post("/channels", response_model=CanalOut, status_code=201, dependencies=[Depends(require_admin)])
async def criar_canal(dados: CanalIn, db: AsyncSession = Depends(get_db)):
    try:
        linha = (await db.execute(INSERT_CANAL, dados.model_dump())).mappings().first()
    except Exception as exc:  # noqa: BLE001
        await db.rollback()
        # O unico UNIQUE da tabela e o nome. Devolver 409 em vez de 500 diz a
        # quem chamou que o problema e o dado, nao o servidor.
        if "unique" in str(exc).lower():
            raise HTTPException(status_code=409, detail="Ja existe canal com esse nome")
        raise
    await db.commit()
    return dict(linha)


@router.patch("/channels/{canal_id}", response_model=CanalOut, dependencies=[Depends(require_admin)])
async def atualizar_canal(
    canal_id: int, dados: CanalUpdate, db: AsyncSession = Depends(get_db)
):
    atual = await _busca_canal(db, canal_id)

    campos = dados.model_dump(exclude_unset=True)
    if not campos:
        return atual

    # O tipo do canal nao muda depois de criado: trocar de webhook para e-mail
    # com o mesmo target guardado deixaria uma linha invalida. Para trocar,
    # apague e crie de novo. Validamos o target novo contra o tipo que ja existe.
    #
    # O try existe porque o ValidationError nasce aqui dentro do handler, e nao
    # na entrada da requisicao. Sem ele o FastAPI devolveria 500, ou seja,
    # "erro do servidor" para um dado errado de quem chamou.
    if "target" in campos:
        try:
            campos["target"] = CanalIn(
                name=atual["name"], kind=atual["kind"], target=campos["target"]
            ).target
        except ValidationError as exc:
            # So a mensagem, e nao exc.errors() inteiro: o dicionario do
            # Pydantic carrega o ValueError original dentro de ctx, que nao e
            # serializavel em JSON e transformaria este 422 num 500.
            raise HTTPException(
                status_code=422,
                detail="; ".join(e["msg"] for e in exc.errors()),
            ) from exc

    sets = ", ".join(f"{c} = :{c}" for c in campos)
    linha = (
        await db.execute(
            text(
                f"UPDATE notification_channels SET {sets} WHERE id = :id "
                "RETURNING id, name, kind, target, min_level, immediate_level, "
                "group_by_actor, enabled, last_digest_at"
            ),
            {**campos, "id": canal_id},
        )
    ).mappings().first()
    await db.commit()
    return dict(linha)


@router.delete("/channels/{canal_id}", status_code=204, dependencies=[Depends(require_admin)])
async def remover_canal(canal_id: int, db: AsyncSession = Depends(get_db)):
    await _busca_canal(db, canal_id)
    # A fila tem ON DELETE CASCADE, entao as mensagens daquele canal saem
    # junto. Mensagem pendente de canal apagado nao teria para onde ir.
    await db.execute(
        text("DELETE FROM notification_channels WHERE id = :id"), {"id": canal_id}
    )
    await db.commit()


@router.post("/channels/{canal_id}/test", response_model=ResultadoTeste, dependencies=[Depends(require_admin)])
async def testar_canal(canal_id: int, db: AsyncSession = Depends(get_db)):
    """Manda uma mensagem agora, fora da fila e fora do teto por hora.

    Nao grava nada em alert_notifications de proposito: teste manual nao e
    alerta, e sujar a fila com teste atrapalharia o agrupamento de verdade.
    Tambem ignora o enabled, porque o teste e justamente o que a pessoa faz
    antes de ligar o canal.
    """
    canal = await _busca_canal(db, canal_id)

    linha = {
        **canal,
        "level": "high",
        "title": "Mensagem de teste do Veryon",
        "rule_id": "TESTE-CANAL",
        "source_ip": None,
        "alert_count": 1,
        "payload": {},
    }

    try:
        async with httpx.AsyncClient(
            timeout=settings.notification_timeout_seconds
        ) as cliente:
            await notifier.entregar(cliente, linha)
    except Exception as exc:  # noqa: BLE001
        # 200 com ok=false, e nao 5xx: a requisicao funcionou, quem falhou foi
        # o destino. Quem chamou precisa da mensagem de erro para consertar a
        # configuracao, e um 500 generico esconderia isso.
        return ResultadoTeste(ok=False, detalhe=str(exc)[:400])

    return ResultadoTeste(ok=True, detalhe=f"Mensagem enviada para {canal['target']}")


@router.post("/digest/run", dependencies=[Depends(require_admin)])
async def rodar_digest_agora():
    """Forca o envio dos resumos pendentes, ignorando o periodo.

    Serve para duas coisas: demonstrar o resumo sem esperar uma hora, e
    esvaziar o acumulado antes de uma manutencao. Nao burla trilho nenhum, so
    antecipa o relogio.
    """
    from sqlalchemy import text as _text

    from app.db.session import async_session

    async with async_session() as s:
        await s.execute(_text("UPDATE notification_channels SET last_digest_at = NULL"))
        await s.commit()

    return {"resumos_enviados": await notifier.enviar_digests()}


@router.get("/queue")
async def ver_fila(
    status_filtro: str | None = Query(None, alias="status"),
    limit: int = Query(50, le=200),
    db: AsyncSession = Depends(get_db),
):
    """Ultimas mensagens da fila, com o motivo de quem nao saiu.

    E a resposta para "por que o alerta nao chegou". Sem isso, a unica saida e
    abrir o banco na mao.
    """
    sql = """
        SELECT n.id, c.name AS canal, c.kind, n.group_key, n.status, n.level,
               n.title, n.alert_count, n.attempts, n.last_error,
               n.created_at, n.sent_at, n.next_attempt_at
          FROM alert_notifications n
          JOIN notification_channels c ON c.id = n.channel_id
    """
    params: dict[str, Any] = {"limit": limit}
    if status_filtro:
        sql += " WHERE n.status = :status"
        params["status"] = status_filtro
    sql += " ORDER BY n.id DESC LIMIT :limit"

    return [dict(l) for l in (await db.execute(text(sql), params)).mappings()]
